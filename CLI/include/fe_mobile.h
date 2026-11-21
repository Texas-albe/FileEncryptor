// 移动端单文件加
// 包装 core/FileEncryptor
// 输入输出均走 fd
// 可 seek
// 不可 seek
#pragma once
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// 导出控制
// 无 default 属性
#ifndef FE_M_API
#  ifdef VDISK_BUILD
#    ifdef _WIN32
#      define FE_M_API __declspec(dllexport)
#    else
#      define FE_M_API __attribute__((visibility("default")))
#    endif
#  else
#    define FE_M_API
#  endif
#endif

#define FE_M_ABI_VERSION 0x00010000u

// 错误码
enum FeMError {
    FE_M_OK      = 0,
    FE_M_E_ARG   = -1,   // 参数非法
    FE_M_E_IO    = -2,   // 读写失败
    FE_M_E_AUTH  = -3,   // 密码错误 / 认证失
    FE_M_E_UNSUP = -4,   // 模式
    FE_M_E_MEM   = -5,   // 内存不足
    FE_M_E_HASH  = -6,   // 明文完整性校验
    FE_M_E_INT   = -7    // 内部错误
};

// 载荷算法
// XChaCha20/AEGIS/AES-GCM 恒可用，SM4 需 OpenSSL）
#define FE_M_MODE_XCHACHA20 1
#define FE_M_MODE_AEGIS256  2
#define FE_M_MODE_AES_GCM   3
#define FE_M_MODE_SM4       4

// 自动试压
#define FE_M_COMPRESS_AUTO  100

// 进度回调
typedef void (*fe_m_progress_fn)(uint64_t done, uint64_t total, void* user);

// ABI 版本
FE_M_API uint32_t fe_m_abi_version(void);

// 错误码 → 可读串
FE_M_API const char* fe_m_strerror(int code);

// 模式可用性
FE_M_API int fe_m_mode_supported(int mode);

// 加密
// in_size
// out_fd 内容
FE_M_API int fe_m_encrypt_fd(int in_fd, uint64_t in_size, int out_fd,
                    const char* password, size_t pass_len,
                    int mode, int compress_level,
                    fe_m_progress_fn progress, void* user);

// 解密
// force_overwrite
// preview_bytes
FE_M_API int fe_m_decrypt_fd(int in_fd, int out_fd,
                    const char* password, size_t pass_len,
                    int force_overwrite, uint64_t preview_bytes,
                    fe_m_progress_fn progress, void* user);

// 解密
// ext_kek 为 Argon2id
// 同批导入
FE_M_API int fe_m_decrypt_fd_kek(int in_fd, int out_fd,
                    const char* password, size_t pass_len,
                    const unsigned char* ext_kek, size_t ext_kek_len,
                    int force_overwrite, uint64_t preview_bytes,
                    fe_m_progress_fn progress, void* user);

// 校验
FE_M_API int fe_m_verify_fd(int in_fd, const char* password, size_t pass_len);

// 计算 fd 前 size 字节
FE_M_API int fe_m_hash_fd(int fd, uint64_t size, unsigned char* out32);

// R58
// path 必须是可读
// out_* 为调用方分配
// info
FE_M_API int fe_m_info(const char* ptd_path, char* out_json, size_t cap);
// 恢复原始文件名
FE_M_API int fe_m_original_name(const char* ptd_path, const char* password, size_t pass_len,
                                char* out_name, size_t cap);
// v6 改密
// 需旧密码正确
FE_M_API int fe_m_rewrap(const char* ptd_path, const char* old_password, size_t old_len,
                         const char* new_password, size_t new_len);


// 非对称收件人 / FEKW / 库 PQC
// 能力探测
FE_M_API int fe_m_asym_supported(void);

// 生成密钥对。algo
// out_pub/out_priv 为 UTF-8 缓冲，建议各 8192 字
FE_M_API int fe_m_generate_keypair(int algo, char* out_pub, size_t cap_pub,
                                   char* out_priv, size_t cap_priv);

// 收件人公钥加密
// 与 fe_m_encrypt_fd 同语义，但
FE_M_API int fe_m_encrypt_fd_asym(int in_fd, uint64_t in_size, int out_fd,
                    const char* recips, size_t recips_len,
                    int mode, int compress_level,
                    fe_m_progress_fn progress, void* user);

// 身份私钥解密
FE_M_API int fe_m_decrypt_fd_asym(int in_fd, int out_fd,
                    const char* identity, size_t identity_len,
                    int force_overwrite, uint64_t preview_bytes,
                    fe_m_progress_fn progress, void* user);

// FEKW 密钥包装
// secret 语义随 alg
// key 为待包装密钥
FE_M_API int fe_m_keywrap_pack(const unsigned char* key, size_t key_len,
                    const char* secret, size_t secret_len, int alg,
                    unsigned char* out_blob, size_t cap, size_t* out_len);
FE_M_API int fe_m_keywrap_unpack(const unsigned char* blob, size_t blob_len,
                    const char* secret, size_t secret_len,
                    unsigned char* out_key, size_t cap, size_t* out_len);

// 库主密码 PQC 封装
// seal 生成混合密钥
FE_M_API int fe_m_pqc_seal(const char* pass, size_t pass_len,
                    const unsigned char* vault_salt, size_t salt_len,
                    unsigned char* out_blob, size_t cap, size_t* out_len,
                    char* out_priv, size_t cap_priv);
FE_M_API int fe_m_pqc_open(const unsigned char* blob, size_t blob_len,
                    const char* priv, size_t priv_len,
                    const unsigned char* vault_salt, size_t salt_len,
                    unsigned char* out_pass, size_t cap, size_t* out_pass_len);

// 水印签名（与桌面 --watermark / --wm-sign / --wm-verify 对齐）
// 加密时附带水印；wm_priv_pem 为签名私钥 PEM 文本
// wm_pqc=1 用 ML-DSA-65，=0 用 RSA-3072
// 内部先落临时 fstream 再拷到 out_fd，保证「容器+水印+名尾」顺序
FE_M_API int fe_m_encrypt_fd_wm(int in_fd, uint64_t in_size, int out_fd,
                    const char* password, size_t pass_len,
                    int mode, int compress_level,
                    const char* wm_priv_pem, int wm_pqc,
                    fe_m_progress_fn progress, void* user);

// 校验水印。pub_pem 可空（只展示不验签）
// 返回 JSON：timestamp/machine_id_hex/nonce_hex/has_signature/verify_ok 等
FE_M_API int fe_m_wm_verify(const char* ptd_path, const char* pub_pem, int pqc,
                    char* out_json, size_t cap);

// 生成水印签名密钥
// out_pub/out_priv 为 PEM 文本缓冲（建议各 16384 字）
FE_M_API int fe_m_wm_generate_keypair(int pqc,
                    char* out_pub, size_t cap_pub,
                    char* out_priv, size_t cap_priv);

#ifdef __cplusplus
}
#endif
