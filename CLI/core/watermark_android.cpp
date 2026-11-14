// Android 水印降级实现
// Android 侧未交叉编译 OpenSSL，水
// 接口签名
#include "watermark.hpp"

#include <ctime>
#include <cstring>

bool wm_sign_and_serialize(uint64_t /*timestamp*/,
                           const unsigned char /*machine_id*/[16],
                           uint8_t /*flags*/,
                           const std::string& /*priv_pem_path*/,
                           bool /*pqc*/,
                           std::vector<unsigned char>& /*blob*/,
                           std::string& error)
{
    error = "Android 端不支持水印签名";
    return false;
}

bool wm_parse_blob(const unsigned char* /*data*/, size_t /*len*/,
                   bool /*pqc*/,
                   const std::string* /*pub_pem_path*/,
                   WatermarkInfo& out)
{
    out.error = "Android 端不支持水印验签";
    return false;
}

bool wm_generate_keypair(const std::string& /*priv_pem_path*/, bool /*pqc*/,
                         std::string& /*pub_pem*/, std::string& error)
{
    error = "Android 端不支持生成水印密钥";
    return false;
}

std::string wm_timestamp_text(uint64_t ts)
{
    time_t t = static_cast<time_t>(ts);
    struct tm tm_buf{};
#if defined(_WIN32)
    localtime_s(&tm_buf, &t);
#else
    localtime_r(&t, &tm_buf);
#endif
    char buf[32];
    std::memset(buf, 0, sizeof(buf));
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm_buf);
    return std::string(buf);
}
