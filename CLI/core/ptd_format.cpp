#include "ptd_format.hpp"

const unsigned char MAGIC[4]={'F','E','N','C'};

// v6 DEK 包裹明文的固定标记：解裹时以恒定时间比较，兼作密码正确性校验
static const unsigned char DEK_MARKER[16] = {
    'F','E','D','E','K','W','R','A','P','0','0','0','0','0','1','\0' };

bool verify_magic(const unsigned char* buf) {
    return std::memcmp(buf, MAGIC, 4) == 0;
}

size_t header_size_for_version(unsigned char ver) {
    if(ver==1) return HEADER_SIZE_V1;
    if(ver==2) return HEADER_SIZE_V2;
    if(ver==3) return HEADER_SIZE_V3;
    if(ver==5) return HEADER_SIZE_V5;
    if(ver==6) return HEADER_SIZE_V6;
    if(ver==4) return HEADER_SIZE_V4;
    // 未知版本返回哨兵而非静默回退 V4，避免把损坏/伪造文件误判为合法 v4 解析
    return size_t(-1);
}

size_t header_hmac_cover(unsigned char ver) {
    if(ver==6) return HEADER_HMAC_COVER_V6;
    if(ver==5) return HEADER_HMAC_COVER_V5;
    if(ver==4) return HEADER_HMAC_COVER;
    return size_t(-1);
}

bool wrap_dek(const unsigned char* dek, const unsigned char* kek,
              unsigned char nonce[24], unsigned char box[64]) {
    unsigned char pt[48];
    for(int i=0;i<16;++i) pt[i]=DEK_MARKER[i];
    for(int i=0;i<32;++i) pt[16+i]=dek[i];
    unsigned long long clen=0;
    randombytes_buf(nonce, 24);
    int rc=crypto_aead_xchacha20poly1305_ietf_encrypt(box,&clen,pt,48,
        nullptr,0,nullptr,nonce,kek);
    sodium_memzero(pt,sizeof(pt));
    return (rc==0 && clen==64);
}

bool unwrap_dek(const unsigned char* box, const unsigned char* kek,
                const unsigned char* nonce, unsigned char dek[32]) {
    unsigned char pt[48]; unsigned long long mlen=0;
    int rc=crypto_aead_xchacha20poly1305_ietf_decrypt(pt,&mlen,nullptr,box,64,
        nullptr,0,nonce,kek);
    if(rc!=0 || mlen!=48) return false;
    bool ok=(sodium_memcmp(pt,DEK_MARKER,16)==0);
    if(ok) {
        for(int i=0;i<32;++i) dek[i]=pt[16+i];
    }
    sodium_memzero(pt,sizeof(pt));
    return ok;
}

// ---------------------------------------------------------------------------
// 收件人 blob 序列化 / 反序列化（变长，每条含算法 + 长度前缀）
// 长度前缀沿用旧的 1 字节写法（古典键 32/56 字节），并在 >=254 时改用
// 0xFF + 2 字节大端扩展，使 1184 字节的 ML-KEM 公钥也能进同一布局。
// 旧格式只会取 1 字节分支，故向后读取完全兼容。
// ---------------------------------------------------------------------------
namespace {
constexpr uint8_t LEN_EXT = 0xFF;   // 扩展前缀：后随 2 字节大端长度

bool put_len_prefixed(std::vector<unsigned char>& b, const std::vector<unsigned char>& v) {
    if(v.size() < LEN_EXT) {
        b.push_back((uint8_t)v.size());
    } else if(v.size() <= 0xFFFEu) {
        b.push_back(LEN_EXT);
        b.push_back((unsigned char)(v.size() >> 8));
        b.push_back((unsigned char)(v.size() & 0xff));
    } else {
        return false;
    }
    b.insert(b.end(), v.begin(), v.end());
    return true;
}

// 读一个长度前缀；成功推进 off 并返回长度
bool get_len_prefixed(const unsigned char* data, size_t len, size_t& off, size_t& n) {
    if(off >= len) return false;
    const uint8_t h = data[off++];
    if(h != LEN_EXT) { n = h; return true; }
    if(len - off < 2) return false;
    n = ((size_t)data[off] << 8) | (size_t)data[off+1];
    off += 2;
    return n <= len - off;
}
} // namespace

size_t recip_static_len(uint8_t algo) {
    if(algo==RECIP_ALGO_X448)  return RECIP_KEY_X448;
    if(algo==RECIP_ALGO_MLKEM) return RECIP_KEY_MLKEM_PUB;
    return RECIP_KEY_X25519;
}

size_t recip_eph_len(uint8_t algo) {
    if(algo==RECIP_ALGO_X448)  return RECIP_KEY_X448;
    if(algo==RECIP_ALGO_MLKEM) return RECIP_EPH_MLKEM_CT;
    return RECIP_KEY_X25519;
}

bool serialize_recipients(const std::vector<RecipientStanza>& stanzas,
                         std::vector<unsigned char>& blob) {
    blob.clear();
    for(const auto& s : stanzas) {
        if(s.recip_pub.size()!=recip_static_len(s.algo)) return false;
        if(s.eph_pub.size()!=recip_eph_len(s.algo)) return false;
        if(s.wrapped_dek.size()!=RECIP_WRAP_LEN) return false;
        blob.push_back(s.algo);
        if(!put_len_prefixed(blob, s.recip_pub)) return false;
        if(!put_len_prefixed(blob, s.eph_pub)) return false;
        // wrapped_dek 固定 48 字节，直接追加（不另加长度前缀）
        blob.insert(blob.end(), s.wrapped_dek.begin(), s.wrapped_dek.end());
    }
    return true;
}

bool parse_recipients(const unsigned char* data, size_t len,
                     std::vector<RecipientStanza>& stanzas) {
    stanzas.clear();
    size_t off = 0;
    while(off < len) {
        RecipientStanza s;
        s.algo = data[off++];
        size_t rl=0, el=0;
        // 先读长度、后取数据：两次取片都要用当时的 off，先读两个前缀会让第一片取错起点。
        if(!get_len_prefixed(data, len, off, rl)) return false;
        if(rl != recip_static_len(s.algo)) return false;
        s.recip_pub.assign(data+off, data+off+rl); off += rl;
        if(!get_len_prefixed(data, len, off, el)) return false;
        if(el != recip_eph_len(s.algo)) return false;
        if(off + el + RECIP_WRAP_LEN > len) return false;
        s.eph_pub.assign(data+off, data+off+el); off += el;
        s.wrapped_dek.assign(data+off, data+off+RECIP_WRAP_LEN); off += RECIP_WRAP_LEN;
        stanzas.push_back(std::move(s));
    }
    return off == len;
}

