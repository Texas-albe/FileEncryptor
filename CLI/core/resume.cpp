#include "resume.hpp"

#include <cstdio>
#include <fstream>
#include <vector>
#include <sys/stat.h>

#include <sodium.h>

#include "FileEncryptor.hpp"    // open_stream / ProgressInfo / CryptoMode / 常量 / 路径工具
#include "fileio_util.hpp"      // fe_file_size / fe_normalize_path_lexical
#include "ptd_format.hpp"       // HEADER_SIZE_V6 / MAGIC / header_size_for_version

// 内容摘要：头部 64KiB + 尾部 64KiB 的 blake2b，拼上文件大小的十六进制。
// 只取首尾是折中——全文件哈希对大文件太慢，而首尾已足以区分「同一个文件」与「被换掉的文件」。
static std::string file_content_token(const std::string& path) {
    int64_t sz = fe_file_size(path);
    if (sz < 0) return std::string();
    const size_t kHead = 1u << 16, kTail = 1u << 16;
    std::ifstream f;
    if (!open_stream(f, path, std::ios::binary)) return std::string();
    crypto_generichash_state st;
    crypto_generichash_init(&st, nullptr, 0, 16);
    std::vector<unsigned char> buf(kHead);
    size_t to_read = (size_t)std::min<int64_t>(kHead, sz);
    if (to_read > 0) {
        f.read(reinterpret_cast<char*>(buf.data()), (std::streamsize)to_read);
        crypto_generichash_update(&st, buf.data(), (size_t)f.gcount());
    }
    if (sz > (int64_t)(kHead + kTail)) {
        f.seekg(-(std::streamoff)kTail, std::ios::end);
        if (f.read(reinterpret_cast<char*>(buf.data()), (std::streamsize)kTail))
            crypto_generichash_update(&st, buf.data(), (size_t)f.gcount());
    }
    f.close();
    unsigned char out[16];
    crypto_generichash_final(&st, out, 16);
    char hex[33];
    sodium_bin2hex(hex, sizeof(hex), out, 16);
    char sizeb[24];
    snprintf(sizeb, sizeof(sizeb), "%llx", (unsigned long long)sz);
    return std::string(hex) + std::string(sizeb);
}

std::string fe_compute_progress_binding(const std::string& in_path) {
    // 规范化走 fe_normalize_path_lexical：宽字符往返，避免 fs::path 按 ACP 解释
    // 使含中文/Emoji 的 UTF-8 路径抛异常（历史缺陷：中文路径加密必崩溃）。
    const std::string norm = fe_normalize_path_lexical(in_path);
    int64_t sz = fe_file_size(in_path);
    int64_t mt = 0;
#ifdef _WIN32
    struct _stat64 st;
    if (_wstat64(utf8_to_wstring(in_path).c_str(), &st) == 0) mt = (int64_t)st.st_mtime;
#else
    struct stat st;
    if (stat(in_path.c_str(), &st) == 0) mt = (int64_t)st.st_mtime;
#endif
    std::string token = file_content_token(in_path);
    // 用 std::string 拼接，避免 snprintf 返回超长时按返回值构造 std::string 的越界读。
    return "|" + norm + "|" + std::to_string(sz) + "|" + std::to_string(mt) + "|" + token;
}

bool fe_is_file_valid(const std::string& path) {
    std::ifstream f;
    if (!open_stream(f, path, std::ios::binary)) return false;
    unsigned char hbuf[HEADER_SIZE_V6];
    f.read(reinterpret_cast<char*>(hbuf), HEADER_SIZE_V6);
    if (f.gcount() < 5) return false;
    unsigned char ver = hbuf[4];
    uint64_t need = header_size_for_version(ver);
    if ((uint64_t)f.gcount() < need) return false;
    return (memcmp(hbuf, MAGIC, 4) == 0 && (ver == 1 || ver == 2 || ver == 3 || ver == 5 || ver == 6 || ver == VERSION));
}

bool fe_is_complete_output(const std::string& out_path, bool encrypt, const std::string& in_path,
                           int64_t in_size_hint, bool* header_ok) {
    if (header_ok) *header_ok = false;
    int64_t cur = fe_file_size(out_path);
    if (cur < 0) return false;
    if (encrypt) {
        int64_t in_sz = in_size_hint;
        if (in_sz < 0) in_sz = fe_file_size(in_path);
        if (in_sz < 0) return false;
        // 读取输出头部的 version / mode 以确定头部大小与 tag 长度
        std::ifstream hf;
        unsigned char ver = 0; CryptoMode m = CryptoMode::XCHACHA20;
        uint32_t cs_stored = CHUNK_SIZE;   // 文件头里的实际块大小，读不到则按当前默认
        if (open_stream(hf, out_path, std::ios::binary)) {
            // 一次读到最大头长：既取 version/mode，也据实际读到的字节数判头是否完整
            unsigned char hb[HEADER_SIZE_V6];
            hf.read(reinterpret_cast<char*>(hb), HEADER_SIZE_V6);
            std::streamsize got = hf.gcount();
            if (got >= 6 && memcmp(hb, MAGIC, 4) == 0) {
                ver = hb[4]; m = static_cast<CryptoMode>(hb[5]);
                if (header_ok && (uint64_t)got >= header_size_for_version(ver)
                    && (ver == 1 || ver == 2 || ver == 3 || ver == 5 || ver == 6 || ver == VERSION)) *header_ok = true;
            }
            // 块大小取自文件头：默认块大小上调后，旧密文仍能被正确判定为「已完成」
            hf.clear();   // 首读可能撞 EOF 置位，不清则后续 seekg 直接失败
            uint64_t recip_meta = 0;
            if (ver == 6 && (uint64_t)got >= HEADER_SIZE_V6) {
                FileHeaderV6 hv = load_header<FileHeaderV6>(hb);
                recip_meta = get_recip_len(hv.reserved);
            }
            if (hf.seekg((std::streamoff)(header_size_for_version(ver) + recip_meta), std::ios::beg)) {
                uint32_t cs_raw = 0;
                if (hf.read(reinterpret_cast<char*>(&cs_raw), 4)
                    && cs_raw >= MIN_CHUNK_SIZE && cs_raw <= MAX_CHUNK_SIZE) cs_stored = cs_raw;
            }
            hf.close();
        }
        uint64_t hdr = header_size_for_version(ver);
        size_t tag = tag_size_for_mode(m);
        uint64_t cs = cs_stored;
        uint64_t expected;
        if (in_sz == 0) {
            expected = hdr + 4 + 4 + 8;
        } else {
            uint64_t tc = ((uint64_t)in_sz + cs - 1) / cs;
            uint64_t last = (uint64_t)in_sz - (tc - 1) * cs;
            expected = hdr + 4 + 4 + 8 + (tc - 1) * (cs + tag) + (last + tag);
        }
        uint64_t fl = 0;
        fe_peek_name_footer_len(out_path, fl);   // 新格式总带加密名尾部
        expected += fl;
        return (uint64_t)cur == expected;
    } else {
        // 解密产物：从源 .ptd 头读取 orig_size 与当前输出尺寸比较
        std::ifstream f;
        if (!open_stream(f, in_path, std::ios::binary)) return false;
        unsigned char verbuf[5];
        if (!f.read(reinterpret_cast<char*>(verbuf), 5)) return false;
        unsigned char ver = verbuf[4];
        uint64_t hdr_size = header_size_for_version(ver);
        uint64_t orig = 0;
        // v6 非对称容器：块元数据之前还有收件人 blob，需先读出其长度再定位 orig_size
        uint64_t recip_len_meta = 0;
        if (ver == 6) {
            unsigned char h6[HEADER_SIZE_V6];
            f.seekg(0, std::ios::beg);
            if (f.read(reinterpret_cast<char*>(h6), HEADER_SIZE_V6) &&
                (size_t)f.gcount() == HEADER_SIZE_V6) {
                FileHeaderV6 hv = load_header<FileHeaderV6>(h6);
                recip_len_meta = get_recip_len(hv.reserved);
            }
        }
        f.seekg((std::streamoff)(hdr_size + recip_len_meta + 4 + 4), std::ios::beg);
        if (!f.read(reinterpret_cast<char*>(&orig), 8)) return false;
        return (uint64_t)cur == orig;
    }
}

bool fe_load_progress(const std::string& out_path, ProgressInfo& info) {
    std::string prog_path = out_path + ".prs";
    std::ifstream f;
    if (!open_stream(f, prog_path, std::ios::binary)) return false;
    f.read(reinterpret_cast<char*>(&info), sizeof(info));
    if (f.gcount() != sizeof(info)) return false;
    if (info.magic != PROGRESS_MAGIC || info.version != PROGRESS_VERSION) {
        return false;
    }
    return true;
}

bool fe_verify_progress_hmac(const ProgressInfo& info, const unsigned char* auth_key,
                             const std::string& binding) {
    std::vector<unsigned char> msg;
    msg.reserve(24 + binding.size());
    msg.insert(msg.end(), reinterpret_cast<const unsigned char*>(&info),
        reinterpret_cast<const unsigned char*>(&info) + 24);
    msg.insert(msg.end(), binding.begin(), binding.end());
    return crypto_auth_verify(info.hmac, msg.data(), msg.size(), auth_key) == 0;
}

bool fe_save_progress(const std::string& out_path, uint64_t processed_chunks,
                      uint64_t processed_bytes, const unsigned char* auth_key,
                      const std::string& binding) {
    ProgressInfo info;
    info.magic = PROGRESS_MAGIC;
    info.version = PROGRESS_VERSION;
    info.processed_chunks = processed_chunks;
    info.processed_bytes = processed_bytes;
    std::vector<unsigned char> msg;
    msg.reserve(24 + binding.size());
    msg.insert(msg.end(), reinterpret_cast<const unsigned char*>(&info),
        reinterpret_cast<const unsigned char*>(&info) + 24);
    msg.insert(msg.end(), binding.begin(), binding.end());
    crypto_auth(info.hmac, msg.data(), msg.size(), auth_key);

    std::string prog_path = out_path + ".prs";
    std::string temp_prog = prog_path + ".tmp";
    // temp 用 trunc 打开即可覆盖残留（上次 rename 失败遗留的 tmp 会作为本次源被重写），
    // 无需逐次 unlink 预清理——每省一次元数据操作，对每 0.5s 一次的节流保存更友好。
    std::ofstream f;
    if (!open_stream(f, temp_prog, std::ios::binary | std::ios::trunc)) return false;
    f.write(reinterpret_cast<const char*>(&info), sizeof(info));
    if (!f.good()) {
        f.close();
        remove_file_utf8(temp_prog);
        return false;
    }
    f.close();
    // 关键：Windows std::rename 在目标已存在时失败(EEXIST)，改用 replace_file_utf8()
    //（MoveFileExW 替换写）保证每块后都能覆盖更新进度文件。
    if (!replace_file_utf8(temp_prog, prog_path)) {
        remove_file_utf8(temp_prog);
        return false;
    }
    return true;
}

void fe_remove_progress(const std::string& out_path) {
    std::string prog_path = out_path + ".prs";
    remove_file_utf8(prog_path);
}
