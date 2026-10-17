#include "ptd_meta.hpp"
#include <fstream>
#include <vector>
#include <iostream>
#include <iterator>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <algorithm>
#include <sodium.h>
#include "FileEncryptor.hpp"   // decrypt_file / derive_key / open_stream / SecureBuffer / fe_file_size
#include "ptd_format.hpp"      // MAGIC VERSION HEADER_* load_header get_recip_len FileHeaderV* HASH_SIZE ARGON2_* get_be32 put_be32 parse_recipients
#include "kdf.hpp"             // derive_header_auth_key HEADER_HMAC_SIZE ARGON2_OPS_LEGACY ARGON2_MEM_LEGACY_KB ARGON2_OUTPUT_LEN
#include "asym_crypto.hpp"     // wrap_dek fe_recover_dek_from_stanzas
#include "keywrap.hpp"         // unwrap_dek
#include "output_lock.hpp"     // fe_acquire_output_lock LockResult OutputLockGuard
#include "watermark.hpp"       // WatermarkInfo WatermarkSpec wm_parse_blob wm_sign_and_serialize collect_machine_id
#include "name_obfuscate.hpp"  // fe_peek_name_footer_len fe_decrypt_name_footer
#include "util/hex.hpp"
#include "machine_id.hpp"      // MachineId

bool read_watermark(const std::string& ptd_path, WatermarkInfo& out, const std::string& pub_pem,
                    bool pqc) {
    out = WatermarkInfo();
    uint64_t footer=0;
    uint32_t wm=0;
    if(!fe_peek_name_footer_len(ptd_path, footer, &wm) || wm==0) return false;
    const int64_t sz=fe_file_size(ptd_path);
    if(sz<0 || (uint64_t)sz < footer) return false;
    // footer 已把 [wm_len(4)][记录] 计入，故 blob 直接从尾部回退 footer 字节处定位
    const uint64_t blob_start=(uint64_t)sz-footer;
    std::ifstream f;
    if(!open_stream(f,ptd_path,std::ios::binary)) return false;
    std::vector<unsigned char> blob((size_t)wm);
    f.seekg((std::streamoff)blob_start, std::ios::beg);
    if(!f.read(reinterpret_cast<char*>(blob.data()),(std::streamsize)wm)) return false;
    return wm_parse_blob(blob.data(), blob.size(), pqc, pub_pem.empty()?nullptr:&pub_pem, out);
}

// 追加水印区到文件尾（须在名字尾部之前写，尾部总长由 peek_name_footer_len 统一计算）。
bool fe_append_watermark_tail(std::fstream& fout, const WatermarkSpec& spec) {
    const MachineId mid = collect_machine_id();
    std::vector<unsigned char> blob;
    std::string err;
    if(!wm_sign_and_serialize((uint64_t)std::time(nullptr), mid.id, mid.flags,
            spec.sign_key, spec.pqc, blob, err)) {
        fprintf(stderr,"%s\n", err.c_str());
        return false;
    }
    // 尾部顺序：blob → wm_len(4) → 名字信封；长度字段放 blob 之后，
    // 解密侧仅凭末尾 8 字节就能定位它（无需重算密文长度）
    fout.seekp(0,std::ios::end);
    fout.write(reinterpret_cast<const char*>(blob.data()),(std::streamsize)blob.size());
    unsigned char len4[4];
    for(int i=0;i<4;++i) len4[i]=(unsigned char)((blob.size()>>(24-8*i))&0xff);
    fout.write(reinterpret_cast<const char*>(len4),4);
    fout.flush();
    return fout.good();
}


// 公开接口：从密文末尾的加密信封恢复原始文件名。需密码以派生主密钥并解密尾部。
// 解密失败（密钥错/无尾部）返回 false，调用方回退到基于 .ptd 文件名的命名。
// v6 非对称容器：从头部后的收件人 blob 取出 stanza，用身份私钥直接解出 DEK
// （非对称下 dek_box 为空，密码解裹通道不可用，故必须走收件人 stanza）。
static bool recover_dek_v6_asym(const std::string& ptd_path,
    const std::string& asym_identity, unsigned char* dek_out) {
    std::ifstream f;
    if(!open_stream(f,ptd_path,std::ios::binary)) return false;
    unsigned char hdrbuf[320];
    if(!f.read(reinterpret_cast<char*>(hdrbuf),5)) return false;
    if(memcmp(hdrbuf,MAGIC,4)!=0) return false;
    unsigned char ver=hdrbuf[4];
    // VERSION 是 v4 基础布局常量（非最新格式版本），v6 容器必须显式放行，否则非对称 -R 会被误拒。
    if(ver!=VERSION&&ver!=6) return false;
    size_t hdr_size=header_size_for_version(ver);
    if(!f.read(reinterpret_cast<char*>(hdrbuf+5),(std::streamoff)(hdr_size-5))) return false;
    FileHeaderV6 h6=load_header<FileHeaderV6>(hdrbuf);
    const uint32_t recip_len=get_recip_len(h6.reserved);
    if(recip_len==0) return false;
    std::vector<unsigned char> blob(recip_len);
    if(!f.read(reinterpret_cast<char*>(blob.data()),recip_len)) return false;
    std::vector<RecipientStanza> stanzas;
    if(!parse_recipients(blob.data(),recip_len,stanzas)) return false;
    return fe_recover_dek_from_stanzas(stanzas, asym_identity, dek_out).ok;
}

bool read_original_name(const std::string& ptd_path, std::string& out_name,
    const SecureBuffer& password,
    const unsigned char* pre_kek, size_t pre_kek_len,
    std::vector<unsigned char>* out_kek,
    const std::string& asym_identity) {
    out_name.clear();
    std::ifstream f;
    if(!open_stream(f,ptd_path,std::ios::binary)) return false;
    unsigned char hdrbuf[320];
    if(!f.read(reinterpret_cast<char*>(hdrbuf),5)) return false;
    if(memcmp(hdrbuf,MAGIC,4)!=0) return false;
    unsigned char ver=hdrbuf[4];
    if(ver!=1&&ver!=2&&ver!=3&&ver!=VERSION&&ver!=5&&ver!=6) return false;
    size_t hdr_size=header_size_for_version(ver);
    if(!f.read(reinterpret_cast<char*>(hdrbuf+5),(std::streamoff)(hdr_size-5))) return false;
    unsigned char salt_buf[ARGON2_SALT_LEN];
    const unsigned char* salt_ptr=nullptr;
    unsigned int kdf_ops=ARGON2_OPS_LEGACY;
    size_t kdf_mem=(size_t)ARGON2_MEM_LEGACY_KB*1024;
    if(ver==1)      { FileHeaderV1 h=load_header<FileHeaderV1>(hdrbuf); memcpy(salt_buf,h.salt,ARGON2_SALT_LEN); salt_ptr=salt_buf; }
    else if(ver==2) { FileHeaderV2 h=load_header<FileHeaderV2>(hdrbuf);  memcpy(salt_buf,h.salt,ARGON2_SALT_LEN); salt_ptr=salt_buf; kdf_ops=h.opslimit; kdf_mem=(size_t)h.memlimit_kb*1024; }
    else if(ver==3) { FileHeaderV3 h=load_header<FileHeaderV3>(hdrbuf); memcpy(salt_buf,h.salt,ARGON2_SALT_LEN); salt_ptr=salt_buf; kdf_ops=h.opslimit; kdf_mem=(size_t)h.memlimit_kb*1024; }
    else if(ver==5) { FileHeaderV5 h=load_header<FileHeaderV5>(hdrbuf); memcpy(salt_buf,h.salt,ARGON2_SALT_LEN); salt_ptr=salt_buf; kdf_ops=h.opslimit; kdf_mem=(size_t)h.memlimit_kb*1024; }
    else if(ver==6) { FileHeaderV6 h=load_header<FileHeaderV6>(hdrbuf); memcpy(salt_buf,h.salt,ARGON2_SALT_LEN); salt_ptr=salt_buf; kdf_ops=h.opslimit; kdf_mem=(size_t)h.memlimit_kb*1024; }
    else            { FileHeaderV4 h=load_header<FileHeaderV4>(hdrbuf); memcpy(salt_buf,h.salt,ARGON2_SALT_LEN); salt_ptr=salt_buf; kdf_ops=h.opslimit; kdf_mem=(size_t)h.memlimit_kb*1024; }
    SecureBuffer kek(ARGON2_OUTPUT_LEN);
    if(asym_identity.empty()) {
        // 非对称容器密码通道不参与：跳过 Argon2，DEK 从收件人 stanza 直接恢复
        if(pre_kek && pre_kek_len >= ARGON2_OUTPUT_LEN) {
            std::memcpy(kek.data(), pre_kek, ARGON2_OUTPUT_LEN);
        } else if(!derive_key(password.data(),password.size(),salt_ptr,kek.data(),kdf_ops,kdf_mem)) {
            return false;
        }
        if(out_kek) out_kek->assign(kek.data(), kek.data()+ARGON2_OUTPUT_LEN);
    }

    // v6 容器：文件名信封由 DEK 加密（与载荷一致），KEK 仅用于解裹 DEK。
    // 故 v6 须先解裹出 DEK，再以 DEK 还原文件名；v1-v5 直接以 KEK（载荷密钥）解密。
    if(ver==6) {
        FileHeaderV6 h6=load_header<FileHeaderV6>(hdrbuf);
        unsigned char dek[32];
        if(!asym_identity.empty() && !recover_dek_v6_asym(ptd_path, asym_identity, dek))
            return false;
        else if(asym_identity.empty() &&
                !unwrap_dek(h6.dek_box, kek.data(), h6.dek_nonce, dek)) return false;
        bool ok=fe_decrypt_name_footer(ptd_path, out_name, dek, salt_ptr);
        sodium_memzero(dek, sizeof(dek));
        return ok;
    }
    return fe_decrypt_name_footer(ptd_path, out_name, kek.data(), salt_ptr);
}

// 只读元数据预览（功能2：文件头信息查看器）
// 不派生密钥、不解密任何内容，仅解析公开头部与尾部信封标志。
bool read_ptd_metadata(const std::string& ptd_path, PtdMeta& meta) {
    meta=PtdMeta{};
    std::ifstream f;
    if(!open_stream(f,ptd_path,std::ios::binary)) return false;
    unsigned char hdr[HEADER_SIZE_V6];
    if(!f.read(reinterpret_cast<char*>(hdr),5)) return false;
    if(memcmp(hdr,MAGIC,4)!=0) return false;
    unsigned char ver=hdr[4];
    if(ver!=1&&ver!=2&&ver!=3&&ver!=VERSION&&ver!=5&&ver!=6) return false;
    meta.version=ver;
    meta.valid=true;
    size_t need=header_size_for_version(ver);
    if(!f.read(reinterpret_cast<char*>(hdr+5),(std::streamoff)(need-5))) return false;
    unsigned char salt_buf[ARGON2_SALT_LEN];
    const unsigned char* salt_ptr=nullptr;
    size_t iv_len=0;
    size_t recip_len_meta=0;   // v6 非对称容器：收件人 blob 字节数（位于固定头与块元数据之间）
    if(ver==1)      { FileHeaderV1 h=load_header<FileHeaderV1>(hdr); memcpy(salt_buf,h.salt,ARGON2_SALT_LEN); salt_ptr=salt_buf; meta.mode=static_cast<CryptoMode>(h.mode); iv_len=h.iv_len;
                     char hex[65]; sodium_bin2hex(hex,sizeof(hex),h.iv,std::min<size_t>(h.iv_len,24)); meta.iv_hex=hex; }
    else if(ver==2) { FileHeaderV2 h=load_header<FileHeaderV2>(hdr);  memcpy(salt_buf,h.salt,ARGON2_SALT_LEN); salt_ptr=salt_buf; meta.mode=static_cast<CryptoMode>(h.mode); meta.opslimit=h.opslimit; meta.memlimit_kb=h.memlimit_kb; iv_len=h.iv_len;
                     char hex[65]; sodium_bin2hex(hex,sizeof(hex),h.iv,std::min<size_t>(h.iv_len,24)); meta.iv_hex=hex; }
    else if(ver==3) { FileHeaderV3 h=load_header<FileHeaderV3>(hdr); memcpy(salt_buf,h.salt,ARGON2_SALT_LEN); salt_ptr=salt_buf; meta.mode=static_cast<CryptoMode>(h.mode); meta.opslimit=h.opslimit; meta.memlimit_kb=h.memlimit_kb; iv_len=h.iv_len;
                     char hex[65]; sodium_bin2hex(hex,sizeof(hex),h.iv,std::min<size_t>(h.iv_len,32)); meta.iv_hex=hex;
                     char hx2[65]; sodium_bin2hex(hx2,sizeof(hx2),h.plaintext_hash,HASH_SIZE); meta.plaintext_hash_hex=hx2;
                     int64_t sz=fe_file_size(ptd_path); (void)sz; }
    else if(ver==5) { FileHeaderV5 h=load_header<FileHeaderV5>(hdr); memcpy(salt_buf,h.salt,ARGON2_SALT_LEN); salt_ptr=salt_buf; meta.mode=static_cast<CryptoMode>(h.mode); meta.opslimit=h.opslimit; meta.memlimit_kb=h.memlimit_kb; iv_len=h.iv_len;
                     meta.compression=h.compression; meta.comp_level=h.comp_level;
                     char hex[65]; sodium_bin2hex(hex,sizeof(hex),h.iv,32); meta.iv_hex=hex;
                     char hx2[65]; sodium_bin2hex(hx2,sizeof(hx2),h.plaintext_hash,HASH_SIZE); meta.plaintext_hash_hex=hx2; }
    else if(ver==6) { FileHeaderV6 h=load_header<FileHeaderV6>(hdr); memcpy(salt_buf,h.salt,ARGON2_SALT_LEN); salt_ptr=salt_buf; meta.mode=static_cast<CryptoMode>(h.mode); meta.opslimit=h.opslimit; meta.memlimit_kb=h.memlimit_kb; iv_len=h.iv_len;
                     meta.compression=h.compression; meta.comp_level=h.comp_level;
                     meta.dek_wrapped=true; meta.key_version=get_be32(reinterpret_cast<const unsigned char*>(&h.key_version));
                     recip_len_meta=get_recip_len(h.reserved);
                     char hex[65]; sodium_bin2hex(hex,sizeof(hex),h.iv,32); meta.iv_hex=hex;
                     char hx2[65]; sodium_bin2hex(hx2,sizeof(hx2),h.plaintext_hash,HASH_SIZE); meta.plaintext_hash_hex=hx2; }
    else            { FileHeaderV4 h=load_header<FileHeaderV4>(hdr); memcpy(salt_buf,h.salt,ARGON2_SALT_LEN); salt_ptr=salt_buf; meta.mode=static_cast<CryptoMode>(h.mode); meta.opslimit=h.opslimit; meta.memlimit_kb=h.memlimit_kb; iv_len=h.iv_len;
                     char hex[65]; sodium_bin2hex(hex,sizeof(hex),h.iv,32); meta.iv_hex=hex;
                     char hx2[65]; sodium_bin2hex(hx2,sizeof(hx2),h.plaintext_hash,HASH_SIZE); meta.plaintext_hash_hex=hx2; }
    // 头部之后紧随 16 字节块元数据：chunk_size(4) + total_chunks(4) + orig_size(8)
    // （不在任何版本的头部结构内，故需单独读取）
    uint32_t meta_chunk=0, meta_chunks=0;
    uint64_t meta_orig=0;
    // 非对称容器：先跳过收件人 blob，再读块元数据
    if(recip_len_meta>0) f.seekg((std::streamoff)recip_len_meta,std::ios::cur);
    if(f.read(reinterpret_cast<char*>(&meta_chunk),4)&&
       f.read(reinterpret_cast<char*>(&meta_chunks),4)&&
       f.read(reinterpret_cast<char*>(&meta_orig),8)) {
        meta.chunk_size=meta_chunk;
        meta.total_chunks=meta_chunks;
        meta.orig_size=meta_orig;
    }
    if(salt_ptr) {
        char hex[65]; sodium_bin2hex(hex,sizeof(hex),salt_ptr,ARGON2_SALT_LEN); meta.salt_hex=hex;
    }
    // 尾部文件名信封：仅 v1.7.1+ 写入（FENX 加密 / FENM 明文）；旧格式无。
    uint64_t fl=0;
    meta.has_name_footer = fe_peek_name_footer_len(ptd_path, fl);
    return true;
}
bool verify_ptd(const std::string& ptd_path, const SecureBuffer& password,
                const std::string& asym_identity) {
    // 自校验：直接流式解密并计算明文哈希，不再落盘 .verify.tmp（消除 4 倍 I/O）。
    // decrypt_file 在 verify_only 模式下当且仅当明文长度与存储哈希均匹配时返回 true；
    // asym_identity 非空时按非对称容器用身份私钥解裹 DEK，故 -V 不再只支持对称密码文件。
    return decrypt_file(ptd_path, ptd_path, password,
        nullptr, false, false, nullptr, nullptr, 0, true, 0, asym_identity);
}

// 密钥轮换 / rewrap（v6 容器）
// old_password 解出 wrapped DEK，new_password 派生新 KEK 重裹（key_version 自增），重写头部容器区与 hmac，载荷不动；仅 v6+。
bool rewrap_file_with(const std::string& ptd_path,
    const SecureBuffer& old_password,
    const SecureBuffer& new_pw,
    bool quiet) {
    if(new_pw.empty()) { fprintf(stderr,"rewrap requires a new password.\n"); return false; }

    // 只读方式打开，先校验 magic / 版本
    std::fstream f;
    if(!open_stream(f,ptd_path,std::ios::in|std::ios::out|std::ios::binary)) {
        fprintf(stderr,"Cannot open container for rewrap: %s\n",ptd_path.c_str());
        return false;
    }
    unsigned char hdr[HEADER_SIZE_V6];
    if(!f.read(reinterpret_cast<char*>(hdr),HEADER_SIZE_V6) || f.gcount()!=HEADER_SIZE_V6) {
        fprintf(stderr,"Container too small or unreadable: %s\n",ptd_path.c_str());
        f.close(); return false;
    }
    if(memcmp(hdr,MAGIC,4)!=0) { fprintf(stderr,"Invalid magic (not a FileEncryptor file).\n"); f.close(); return false; }
    FileHeaderV6 h=load_header<FileHeaderV6>(hdr);
    if(h.version!=6) {
        fprintf(stderr,"rewrap requires a v6 container; file version=%u (re-encrypt instead).\n",(unsigned)h.version);
        f.close(); return false;
    }

    // 跨进程锁：避免与其他进程（如加密中）并发写同一文件
    std::string lock_path;
    LockResult lr=fe_acquire_output_lock(ptd_path,lock_path);
    if(lr!=LockResult::OK) {
        fprintf(stderr,"Cannot acquire lock for rewrap: %s\n",ptd_path.c_str());
        f.close(); return false;
    }
    OutputLockGuard lock_guard{lock_path,true};

    // 用旧密码派生 KEK，解开 DEK（同时校验旧密码正确性）
    SecureBuffer old_kek(ARGON2_OUTPUT_LEN);
    if(!derive_key(old_password.data(),old_password.size(),h.salt,old_kek.data(),
            h.opslimit,(size_t)h.memlimit_kb*1024)) {
        fprintf(stderr,"Key derivation failed (old password).\n");
        f.close(); return false;
    }
    // DEK 以 SecureBuffer 持有（析构自动清零 + 解锁），保留至 header_hmac 重算完成
    SecureBuffer dek(32);
    if(!unwrap_dek(h.dek_box, old_kek.data(), h.dek_nonce, dek.data())) {
        fprintf(stderr, "Failed to unwrap DEK (wrong old password or corrupted container).\n");
        f.close(); return false;
    }
    sodium_memzero(old_kek.data(),old_kek.size());

    // 用新密码派生新 KEK，重裹 DEK（重新随机 nonce + box）。DEK 保持不变。
    SecureBuffer new_kek(ARGON2_OUTPUT_LEN);
    if(!derive_key(new_pw.data(),new_pw.size(),h.salt,new_kek.data(),
            h.opslimit,(size_t)h.memlimit_kb*1024)) {
        fprintf(stderr,"Key derivation failed (new password).\n");
        f.close(); return false;
    }
    if(!wrap_dek(dek.data(), new_kek.data(), h.dek_nonce, h.dek_box)) {
        fprintf(stderr,"DEK rewrap failed.\n");
        f.close(); return false;
    }
    sodium_memzero(new_kek.data(),new_kek.size());

    // 写回容器区：key_version 自增（大端）。DEK 不变，故 header_hmac 仍由 DEK 派生密钥计算，
    // 重算整头 HMAC（覆盖至 reserved 区，含新容器）后仍自洽。
    uint32_t kv=get_be32(reinterpret_cast<const unsigned char*>(&h.key_version))+1;
    put_be32(reinterpret_cast<unsigned char*>(&h.key_version), kv);
    // 局部 h 的容器区改动（dek_box / nonce / key_version）须先写回原始字节缓冲，
    // header_hmac 的覆盖与整头落盘都以该缓冲为基准（h 是 memcpy 出的副本）。
    memcpy(hdr, &h, HEADER_SIZE_V6);
    {
        unsigned char hdr_auth[HEADER_HMAC_SIZE];
        derive_header_auth_key(dek.data(), hdr_auth);
        crypto_auth(hdr + (HEADER_SIZE_V6 - HEADER_HMAC_SIZE), hdr, HEADER_HMAC_COVER_V6, hdr_auth);
        sodium_memzero(hdr_auth,sizeof(hdr_auth));
    }

    // 落盘：从头写回完整 256 字节头部（plaintext_hash 保持原值不变）
    f.seekp(0,std::ios::beg);
    if(!f.write(reinterpret_cast<const char*>(hdr),HEADER_SIZE_V6)) {
        fprintf(stderr,"Failed to write rewrapped header: %s\n",ptd_path.c_str());
        f.close(); return false;
    }
    f.flush();
    f.close();
    if(!quiet) printf("rewrap: container '%s' rotated to key_version=%u (payload ciphertext untouched).\n",
        ptd_path.c_str(), kv);
    return true;
}

// CLI 侧包装：新密码来自密钥文件 / stdin（原始字节）
bool rewrap_file(const std::string& ptd_path,
    const SecureBuffer& old_password,
    const std::string& new_key_path,
    bool new_key_from_stdin) {
    SecureBuffer new_pw;
    if(!new_key_path.empty()) {
        std::ifstream kf;
        if(!open_stream(kf,new_key_path,std::ios::binary)) {
            fprintf(stderr,"Cannot open new key file: %s\n",new_key_path.c_str());
            return false;
        }
        std::vector<char> kbuf((std::istreambuf_iterator<char>(kf)),
                               std::istreambuf_iterator<char>());
        kf.close();
        if(kbuf.empty()) { fprintf(stderr,"New key file is empty: %s\n",new_key_path.c_str()); return false; }
        new_pw=SecureBuffer(kbuf.data(),kbuf.size());
        sodium_memzero(kbuf.data(),kbuf.size()); kbuf.clear();
    } else if(new_key_from_stdin) {
        std::vector<char> sbuf((std::istreambuf_iterator<char>(std::cin)),
                               std::istreambuf_iterator<char>());
        if(sbuf.empty()) { fprintf(stderr,"No new key material received from stdin.\n"); return false; }
        new_pw=SecureBuffer(sbuf.data(),sbuf.size());
        sodium_memzero(sbuf.data(),sbuf.size()); sbuf.clear();
    } else {
        fprintf(stderr,"rewrap requires a new key source (--new-key-file <file> or --new-key-stdin).\n");
        return false;
    }
    return rewrap_file_with(ptd_path, old_password, new_pw, false);
}
