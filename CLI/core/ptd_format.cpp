#include "ptd_format.hpp"

const unsigned char MAGIC[4]={'F','E','N','C'};

// v6 DEK 包裹明文的固定标记：解裹时以恒定时间比较，兼作口令正确性校验
static const unsigned char DEK_MARKER[16] = {
    'F','E','D','E','K','W','R','A','P','0','0','0','0','0','1','\0' };

size_t header_size_for_version(unsigned char ver) {
    if(ver==1) return HEADER_SIZE_V1;
    if(ver==2) return HEADER_SIZE_V2;
    if(ver==3) return HEADER_SIZE_V3;
    if(ver==5) return HEADER_SIZE_V5;
    if(ver==6) return HEADER_SIZE_V6;
    return HEADER_SIZE_V4;
}

size_t header_hmac_cover(unsigned char ver) {
    if(ver==6) return HEADER_HMAC_COVER_V6;
    return (ver==5) ? HEADER_HMAC_COVER_V5 : HEADER_HMAC_COVER;
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
