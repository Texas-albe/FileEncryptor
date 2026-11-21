// WebDAV cloud backend (libcurl based)
#pragma once

#include "saf.hpp"

#include <string>

// Build with FE_WITH_CURL; otherwise saf_open_webdav returns nullptr
struct SafWebDavOptions {
    std::string base_url;      // http(s)://host[:port]/path, no userinfo
    std::string user;          // basic/digest auth, may be empty
    std::string pass;
    long        timeout_sec = 60;
    bool        verify_tls = true;  // false allows self-signed certs
    uint64_t    chunk = 1u << 20;   // stream read block
};

std::shared_ptr<StorageBackend> saf_open_webdav(const SafWebDavOptions& opt);

// Parse webdav(s)://[user:pass@]host[:port]/path; FE_WEBDAV_USER/PASS env as fallback.
// Does not touch opt.user/pass if the URI carries no userinfo and env is unset.
bool saf_webdav_parse_uri(const std::string& uri, SafWebDavOptions& opt, std::string& err);

// Append a small text line to a WebDAV file (GET + PUT); used for audit anchors.
bool saf_webdav_append_text(const SafWebDavOptions& opt, const std::string& rel,
                            const std::string& text, std::string& err);

// Diagnostics for the most recent failure on this thread
std::string saf_webdav_last_error();
