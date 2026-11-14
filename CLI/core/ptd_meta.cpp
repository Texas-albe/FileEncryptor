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
#include "FileEncryptor.hpp"   
#include "ptd_format.hpp"      
#include "kdf.hpp"             
#include "asym_crypto.hpp"     // wrap_dek fe_recover_dek_from_stanzas
#include "keywrap.hpp"         // unwrap_dek
#include "output_lock.hpp"     
#include "watermark.hpp"       
#include "name_obfuscate.hpp"  
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
    // footer 已把 [wm_len][记录] 计入，故
    const uint64_t blob_start=(uint64_t)sz-footer;
    std::ifstream f;
    if(!open_stream(f,ptd_path,std::ios::binary)) return false;
    std::vector<unsigned char> blob((size_t)wm);
    f.seekg((std::streamoff)blob_start, std::ios::beg);
    if(!f.read(reinterpret_cast<char*>(blob.data()),(std::streamsize)wm)) return false;
    return wm_parse_blob(blob.data(), blob.size(), pqc, pub_pem.empty()?nullptr:&pub_pem, out);
}

// 追加水印区到文
bool fe_append_watermark_tail(std::fstream& fout, const WatermarkSpec& spec) {
    const MachineId mid = collect_machine_id();
    std::vector<unsigned char> blob;
    std::string err;
    if(!wm_sign_and_serialize((uint64_t)std::time(nullptr), mid.id, mid.flags,
            spec.sign_key, spec.pqc, blob, err)) {
        fprintf(stderr,"%s\n", err.c_str());
        return false;
    }
    // 尾部顺序
    // 解密侧
    fout.seekp(0,std::ios::end);
    fout.write(reinterpret_cast<const char*>(blob.data()),(std::streamsize)blob.size());
    unsigned char len4[4];
    for(int i=0;i<4;++i) len4[i]=(unsigned char)((blob.size()>>(24-8*i))&0xff);
    fout.write(reinterpret_cast<const char*>(len4),4);
    fout.flush();
    return fout.good();
}


// 公开接口
// 解密失败
// v6 非对称容器
static bool recover_dek_v6_asym(const std::string& ptd_path,
    const std::string& asym_identity, unsigned char* dek_out) {
    std::ifstream f;
    if(!open_stream(f,ptd_path,std::ios::binary)) return false;
    unsigned char hdrbuf[320];
    if(!f.read(reinterpret_cast<char*>(hdrbuf),5)) return false;
    if(memcmp(hdrbuf,MAGIC,4)!=0) return false;
    unsigned char ver=hdrbuf[4];
    // 本函数
    if(ver!=6) return false;
    size_t hdr_size=header_size_for_version(ver);
    if(!f.read(reinterpret_cast<char*>(hdrbuf+5),(std::streamoff)(hdr_size-5))) return false;
    FileHeaderV6 h6=load_header<FileHeaderV6>(hdrbuf);
    const uint32_t recip_len=get_recip_len(h6.reserved);
    if(recip_len==0) return false;
    // recip_len 来自未认证头部
    f.seekg(0,std::ios::end);
    const std::streamoff total=f.tellg();
    if(total<0) return false;
    if((uint64_t)recip_len>(uint64_t)total-(uint64_t)hdr_size) return false;
    f.seekg((std::streamoff)hdr_size,std::ios::beg);
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
        // 非对称容器密码
        if(pre_kek && pre_kek_len >= ARGON2_OUTPUT_LEN) {
            std::memcpy(kek.data(), pre_kek, ARGON2_OUTPUT_LEN);
        } else if(!derive_key(password.data(),password.size(),salt_ptr,kek.data(),kdf_ops,kdf_mem)) {
            return false;
        }
        if(out_kek) out_kek->assign(kek.data(), kek.data()+ARGON2_OUTPUT_LEN);
    }

    // v6 容器
    // 故 v6 须先解裹出 DEK
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

// 只读元数据预览
// 不派生密钥、不解
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
    size_t recip_len_meta=0;   // v6 非对称容器
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
    // 头部
    uint32_t meta_chunk=0, meta_chunks=0;
    uint64_t meta_orig=0;
    // 非对称容器
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
    // 尾部文件名信封
    uint64_t fl=0;
    meta.has_name_footer = fe_peek_name_footer_len(ptd_path, fl);
    return true;
}
bool verify_ptd(const std::string& ptd_path, const SecureBuffer& password,
                const std::string& asym_identity) {
    // 自校验
    // decrypt_file 在 verify_only 模式下当且
    // asym_identity 非空
    return decrypt_file(ptd_path, ptd_path, password,
        nullptr, false, false, nullptr, nullptr, 0, true, 0, asym_identity);
}

// 密钥轮换 / rewrap
// old_password 解出 wrapped
bool rewrap_file_with(const std::string& ptd_path,
    const SecureBuffer& old_password,
    const SecureBuffer& new_pw,
    bool quiet) {
    if(new_pw.empty()) { fprintf(stderr,"rewrap requires a new password.\n"); return false; }

    // 只读方式打开
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

    // 跨进程锁
    std::string lock_path;
    LockResult lr=fe_acquire_output_lock(ptd_path,lock_path);
    if(lr!=LockResult::OK) {
        fprintf(stderr,"Cannot acquire lock for rewrap: %s\n",ptd_path.c_str());
        f.close(); return false;
    }
    OutputLockGuard lock_guard{lock_path,true};

    // 用旧密码派生 KEK
    SecureBuffer old_kek(ARGON2_OUTPUT_LEN);
    if(!derive_key(old_password.data(),old_password.size(),h.salt,old_kek.data(),
            h.opslimit,(size_t)h.memlimit_kb*1024)) {
        fprintf(stderr,"Key derivation failed (old password).\n");
        f.close(); return false;
    }
    // DEK 以 SecureBuffer 持有，保留至
    SecureBuffer dek(32);
    if(!unwrap_dek(h.dek_box, old_kek.data(), h.dek_nonce, dek.data())) {
        fprintf(stderr, "Failed to unwrap DEK (wrong old password or corrupted container).\n");
        f.close(); return false;
    }
    sodium_memzero(old_kek.data(),old_kek.size());

    // 重写头部
    {
        unsigned char hdr_auth[HEADER_HMAC_SIZE];
        derive_header_auth_key(dek.data(), hdr_auth);
        int hv=crypto_auth_verify(hdr+(HEADER_SIZE_V6-HEADER_HMAC_SIZE),
                                  hdr, HEADER_HMAC_COVER_V6, hdr_auth);
        sodium_memzero(hdr_auth,sizeof(hdr_auth));
        if(hv!=0) {
            fprintf(stderr,"Header authentication failed (container tampered); rewrap aborted.\n");
            f.close(); return false;
        }
    }

    // 用新密码派生新 KEK
    // 注意
    // FileEncryptor.cpp 解密端复刻），改盐
    // 「新口令继承旧参
    // 协商）
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

    // 写回容器区
    // 重算整头 HMAC
    uint32_t kv=get_be32(reinterpret_cast<const unsigned char*>(&h.key_version))+1;
    put_be32(reinterpret_cast<unsigned char*>(&h.key_version), kv);
    // 局部 h
    // header_hmac 的覆盖
    memcpy(hdr, &h, HEADER_SIZE_V6);
    {
        unsigned char hdr_auth[HEADER_HMAC_SIZE];
        derive_header_auth_key(dek.data(), hdr_auth);
        crypto_auth(hdr + (HEADER_SIZE_V6 - HEADER_HMAC_SIZE), hdr, HEADER_HMAC_COVER_V6, hdr_auth);
        sodium_memzero(hdr_auth,sizeof(hdr_auth));
    }

    // 落盘
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

// CLI 侧包装
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
