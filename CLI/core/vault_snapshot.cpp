// Vault snapshot / verify / restore implementation
// Copy order matters: data (.ptd) first, index (.feindex.d) last, so an
// interrupted snapshot behaves like a crashed vault write (recoverable by
// --vault-reindex) rather than an index pointing at missing data.
#define _CRT_SECURE_NO_WARNINGS
#include "vault_snapshot.hpp"

#include "FileEncryptor.hpp"
#include "fileio_util.hpp"
#include "config.hpp"
#include "util/hex.hpp"

#include <sodium.h>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#endif

namespace fs = std::filesystem;

namespace {

const char* kManifestName = "MANIFEST.sha256";
const char* kManifestMagic = "# FileEncryptor vault snapshot";

struct SnapFile {
    std::string rel;   // '/'-separated, relative to vault root
    std::string abs;   // native absolute path
};

// Resume/temp residue never belongs in a snapshot
bool snap_skip_name(const std::string& name) {
    std::string lower = name;
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char c) { return (char)std::tolower(c); });
    if (lower.size() >= 4 && lower.compare(lower.size() - 4, 4, ".prs") == 0) return true;
    if (lower.size() >= 4 && lower.compare(lower.size() - 4, 4, ".prt") == 0) return true;
    if (lower.rfind("fe_tmp", 0) == 0) return true;
    return false;
}

// Index dir sorts last (commit point)
int snap_order(const std::string& rel) {
    return rel.rfind(".feindex.d", 0) == 0 ? 1 : 0;
}

bool collect_snap_files(const std::string& root, std::vector<SnapFile>& out,
                        std::string& err) {
    std::error_code ec;
    fs::path rdir = fs::u8path(root);
    if (!fs::exists(rdir, ec)) { err = "vault dir not found: " + root; return false; }
    fs::recursive_directory_iterator it(rdir, fs::directory_options::skip_permission_denied, ec);
    fs::recursive_directory_iterator end;
    while (!ec && it != end) {
        std::error_code ec2;
        if (it->is_regular_file(ec2)) {
            fs::path p = it->path();
            std::string name = p.filename().u8string();
            if (!snap_skip_name(name)) {
                SnapFile sf;
                sf.abs = p.u8string();
                sf.rel = fs::relative(p, rdir, ec2).u8string();
                std::replace(sf.rel.begin(), sf.rel.end(), '\\', '/');
                out.push_back(std::move(sf));
            }
        }
        it.increment(ec);
    }
    if (ec) { err = "cannot enumerate vault dir: " + root; return false; }
    std::stable_sort(out.begin(), out.end(), [](const SnapFile& a, const SnapFile& b) {
        return snap_order(a.rel) < snap_order(b.rel);
    });
    return true;
}

bool sha256_file_hex(const std::string& path, std::string& hex, std::string& err) {
    std::ifstream f;
    if (!open_stream(f, path, std::ios::binary)) { err = "cannot open " + path; return false; }
    crypto_hash_sha256_state st;
    crypto_hash_sha256_init(&st);
    char buf[65536];
    while (true) {
        f.read(buf, sizeof(buf));
        std::streamsize n = f.gcount();
        if (n > 0)
            crypto_hash_sha256_update(&st, reinterpret_cast<const unsigned char*>(buf),
                                      (unsigned long long)n);
        if (n < (std::streamsize)sizeof(buf)) break;
    }
    if (f.bad()) { err = "read error: " + path; return false; }
    unsigned char out[32];
    crypto_hash_sha256_final(&st, out);
    hex = fe::util::to_hex(out, 32);
    return true;
}

bool read_manifest(const std::string& snap_dir,
                   std::vector<std::pair<std::string, std::string>>& entries,
                   std::string& source_dir, std::string& err) {
    std::string mf = snap_dir + "/" + kManifestName;
    std::ifstream f;
    if (!open_stream(f, mf, std::ios::in)) { err = "manifest not found: " + mf; return false; }
    std::string line;
    while (std::getline(f, line)) {
        while (!line.empty() && (line.back() == '\r' || line.back() == '\n')) line.pop_back();
        if (line.empty()) continue;
        if (line.rfind("# source: ", 0) == 0) { source_dir = line.substr(10); continue; }
        if (line[0] == '#') continue;
        // <64 hex>  <rel>
        if (line.size() < 66 || line[64] != ' ') continue;
        std::string hex = line.substr(0, 64);
        std::string rel = line.substr(66);
        entries.emplace_back(std::move(hex), std::move(rel));
    }
    if (entries.empty()) { err = "manifest has no entries: " + mf; return false; }
    return true;
}

}  // namespace

bool vault_snapshot(const std::string& vault_dir_in, const std::string& dest_dir_in,
                    std::string& err) {
    std::string vault_dir = vault_dir_in;
    while (!vault_dir.empty() && (vault_dir.back() == '/' || vault_dir.back() == '\\'))
        vault_dir.pop_back();
    std::string dest_dir = dest_dir_in;
    while (!dest_dir.empty() && (dest_dir.back() == '/' || dest_dir.back() == '\\'))
        dest_dir.pop_back();
    if (vault_dir.empty() || dest_dir.empty()) { err = "empty path"; return false; }
    // Refuse nesting: snapshot inside the vault would recurse on next run
    std::string nv = vault_dir, nd = dest_dir;
    std::transform(nv.begin(), nv.end(), nv.begin(),
                   [](unsigned char c) { return (char)std::tolower(c); });
    std::transform(nd.begin(), nd.end(), nd.begin(),
                   [](unsigned char c) { return (char)std::tolower(c); });
    if (nd.rfind(nv, 0) == 0 &&
        (nd.size() == nv.size() || nd[nv.size()] == '/' || nd[nv.size()] == '\\')) {
        err = "destination is inside the vault; pick a directory outside it";
        return false;
    }
    if (!create_directory_recursive(dest_dir)) { err = "cannot create " + dest_dir; return false; }

    std::vector<SnapFile> files;
    if (!collect_snap_files(vault_dir, files, err)) return false;
    if (files.empty()) { err = "vault has no snapshot-able files"; return false; }

    std::string manifest;
    manifest += std::string(kManifestMagic) + "\n";
    manifest += "# source: " + vault_dir + "\n";

    uint64_t total = 0;
    size_t copied = 0;
    for (const auto& sf : files) {
        std::string dst = dest_dir + "/" + sf.rel;
        size_t pos = dst.find_last_of("/\\");
        if (pos != std::string::npos) {
            if (!create_directory_recursive(dst.substr(0, pos))) {
                err = "cannot create dir for " + sf.rel;
                return false;
            }
        }
        std::error_code ec;
        fs::copy_file(fs::u8path(sf.abs), fs::u8path(dst), fs::copy_options::overwrite_existing, ec);
        if (ec) { err = "copy failed: " + sf.rel + " (" + ec.message() + ")"; return false; }
        std::string hex;
        if (!sha256_file_hex(dst, hex, err)) return false;
        manifest += hex + "  " + sf.rel + "\n";
        total += (uint64_t)fs::file_size(fs::u8path(dst), ec);
        ++copied;
    }
    std::ofstream mf;
    if (!open_stream(mf, dest_dir + "/" + kManifestName, std::ios::out | std::ios::trunc)) {
        err = "cannot write manifest";
        return false;
    }
    mf << manifest;
    mf.close();
    if (!mf.good()) { err = "write manifest failed"; return false; }
    std::cout << "Snapshot OK: " << copied << " file(s), " << format_size(total)
              << " -> " << dest_dir << "/" << kManifestName << "\n";
    return true;
}

bool vault_snapshot_verify(const std::string& snap_dir_in, std::string& err) {
    std::string snap_dir = snap_dir_in;
    while (!snap_dir.empty() && (snap_dir.back() == '/' || snap_dir.back() == '\\'))
        snap_dir.pop_back();
    std::vector<std::pair<std::string, std::string>> entries;
    std::string source_dir;
    if (!read_manifest(snap_dir, entries, source_dir, err)) return false;
    size_t ok = 0, missing = 0, corrupt = 0;
    for (const auto& e : entries) {
        std::string hex;
        if (!sha256_file_hex(snap_dir + "/" + e.second, hex, err)) {
            if (err.find("cannot open") != std::string::npos) { ++missing; continue; }
            return false;
        }
        if (hex == e.first) ++ok;
        else {
            ++corrupt;
            std::cerr << "Corrupt: " << e.second << "\n";
        }
    }
    std::cout << "Snapshot check: " << ok << " ok, " << missing << " missing, "
              << corrupt << " corrupt (" << entries.size() << " total)\n";
    if (missing || corrupt) {
        err = "snapshot verification failed";
        return false;
    }
    return true;
}

bool vault_snapshot_restore(const std::string& snap_dir_in,
                            const std::string& vault_dir_override, std::string& err) {
    std::string snap_dir = snap_dir_in;
    while (!snap_dir.empty() && (snap_dir.back() == '/' || snap_dir.back() == '\\'))
        snap_dir.pop_back();
    std::vector<std::pair<std::string, std::string>> entries;
    std::string source_dir;
    if (!read_manifest(snap_dir, entries, source_dir, err)) return false;
    // Manifest is ordered index-last already; keep that order on restore
    std::string vault_dir = vault_dir_override.empty() ? source_dir : vault_dir_override;
    if (vault_dir.empty()) {
        err = "snapshot has no recorded source and no --vault-restore-to given";
        return false;
    }
    std::error_code ec;
    if (!fs::exists(fs::u8path(vault_dir), ec)) {
        err = "restore target does not exist: " + vault_dir +
              " (create the vault first or pass --vault-restore-to)";
        return false;
    }
    size_t done = 0, failed = 0;
    for (const auto& e : entries) {
        if (e.second == kManifestName) continue;
        std::string src = snap_dir + "/" + e.second;
        std::string dst = vault_dir + "/" + e.second;
        size_t pos = dst.find_last_of("/\\");
        if (pos != std::string::npos) {
            if (!create_directory_recursive(dst.substr(0, pos))) { ++failed; continue; }
        }
        std::error_code ec2;
        fs::copy_file(fs::u8path(src), fs::u8path(dst),
                      fs::copy_options::overwrite_existing, ec2);
        if (ec2) {
            ++failed;
            std::cerr << "Restore failed: " << e.second << " (" << ec2.message() << ")\n";
        } else {
            ++done;
        }
    }
    std::cout << "Restore: " << done << " file(s) copied, " << failed << " failed -> "
              << vault_dir << "\n";
    if (failed) { err = "restore finished with errors"; return false; }
    std::cout << "Note: run --vault-reindex afterwards to fold any orphan .ptd "
                 "created after the snapshot back into the index.\n";
    return true;
}
