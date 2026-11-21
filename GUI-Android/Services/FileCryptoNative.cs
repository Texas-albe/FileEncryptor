// fe_mobile C ABI
// 对应 CLI/include
using System.Runtime.InteropServices;

namespace FileEncryptorMobile.Services;

// 错误码必须
public enum FeMError
{
    Ok = 0,
    Arg = -1,
    Io = -2,
    Auth = -3,
    Unsup = -4,
    Mem = -5,
    Hash = -6,
    Internal = -7,
}

public enum FeMMode
{
    XChaCha20 = 1,
    Aegis256 = 2,
    AesGcm = 3,
    Sm4 = 4,
}

// 进度回调
[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
public delegate void FeMProgressNative(ulong done, ulong total, IntPtr user);

internal static partial class FileCryptoNative
{
    // 与 vdisk 同一库
    private const string Lib = "vdisk";

    internal const uint ExpectedAbiVersion = 0x00010000u;

    // 与 fe_mobile.h
    internal const int CompressAuto = 100;

    [LibraryImport(Lib)]
    internal static partial uint fe_m_abi_version();

    [LibraryImport(Lib)]
    [return: MarshalAs(UnmanagedType.LPStr)]
    internal static partial string fe_m_strerror(int code);

    [LibraryImport(Lib)]
    internal static partial int fe_m_mode_supported(int mode);

    // 加密
    [LibraryImport(Lib)]
    internal static unsafe partial int fe_m_encrypt_fd(
        int in_fd, ulong in_size, int out_fd,
        byte* password, UIntPtr pass_len,
        int mode, int compress_level,
        delegate* unmanaged<ulong, ulong, IntPtr, void> progress, IntPtr user);

    // 解密
    [LibraryImport(Lib)]
    internal static unsafe partial int fe_m_decrypt_fd(
        int in_fd, int out_fd,
        byte* password, UIntPtr pass_len,
        int force_overwrite, ulong preview_bytes,
        delegate* unmanaged<ulong, ulong, IntPtr, void> progress, IntPtr user);

    // 校验
    [LibraryImport(Lib)]
    internal static unsafe partial int fe_m_verify_fd(
        int in_fd, byte* password, UIntPtr pass_len);

    // fd 前 size 字节
    [LibraryImport(Lib)]
    internal static unsafe partial int fe_m_hash_fd(
        int fd, ulong size, byte* out32);

    // R58
    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    internal static unsafe partial int fe_m_info(string ptdPath, byte* outJson, UIntPtr cap);

    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    internal static unsafe partial int fe_m_original_name(
        string ptdPath, byte* password, UIntPtr passLen, byte* outName, UIntPtr cap);

    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    internal static unsafe partial int fe_m_rewrap(
        string ptdPath, byte* oldPassword, UIntPtr oldLen, byte* newPassword, UIntPtr newLen);

    // 非对称 / FEKW / 库 PQC：均走裸
    [LibraryImport(Lib)]
    internal static partial int fe_m_asym_supported();

    [LibraryImport(Lib)]
    internal static unsafe partial int fe_m_generate_keypair(
        int algo, byte* outPub, UIntPtr capPub, byte* outPriv, UIntPtr capPriv);

    [LibraryImport(Lib)]
    internal static unsafe partial int fe_m_encrypt_fd_asym(
        int in_fd, ulong in_size, int out_fd,
        byte* recips, UIntPtr recips_len,
        int mode, int compress_level,
        delegate* unmanaged<ulong, ulong, IntPtr, void> progress, IntPtr user);

    [LibraryImport(Lib)]
    internal static unsafe partial int fe_m_decrypt_fd_asym(
        int in_fd, int out_fd,
        byte* identity, UIntPtr identity_len,
        int force_overwrite, ulong preview_bytes,
        delegate* unmanaged<ulong, ulong, IntPtr, void> progress, IntPtr user);

    [LibraryImport(Lib)]
    internal static unsafe partial int fe_m_keywrap_pack(
        byte* key, UIntPtr key_len, byte* secret, UIntPtr secret_len, int alg,
        byte* out_blob, UIntPtr cap, out UIntPtr out_len);

    [LibraryImport(Lib)]
    internal static unsafe partial int fe_m_keywrap_unpack(
        byte* blob, UIntPtr blob_len, byte* secret, UIntPtr secret_len,
        byte* out_key, UIntPtr cap, out UIntPtr out_len);

    [LibraryImport(Lib)]
    internal static unsafe partial int fe_m_pqc_seal(
        byte* pass, UIntPtr pass_len, byte* vault_salt, UIntPtr salt_len,
        byte* out_blob, UIntPtr cap, out UIntPtr out_len,
        byte* out_priv, UIntPtr cap_priv);

    [LibraryImport(Lib)]
    internal static unsafe partial int fe_m_pqc_open(
        byte* blob, UIntPtr blob_len, byte* priv, UIntPtr priv_len,
        byte* vault_salt, UIntPtr salt_len,
        byte* out_pass, UIntPtr cap, out UIntPtr out_pass_len);

    // 水印签名加密
    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    internal static unsafe partial int fe_m_encrypt_fd_wm(
        int in_fd, ulong in_size, int out_fd,
        byte* password, UIntPtr pass_len,
        int mode, int compress_level,
        string wm_priv_pem, int wm_pqc,
        delegate* unmanaged<ulong, ulong, IntPtr, void> progress, IntPtr user);

    // 水印校验
    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    internal static unsafe partial int fe_m_wm_verify(
        string ptdPath, string? pubPem, int pqc,
        byte* outJson, UIntPtr cap);

    // 生成水印签名密钥
    [LibraryImport(Lib)]
    internal static unsafe partial int fe_m_wm_generate_keypair(
        int pqc,
        byte* out_pub, UIntPtr cap_pub,
        byte* out_priv, UIntPtr cap_priv);
}
