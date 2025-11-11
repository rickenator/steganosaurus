// turtle_fft_stego_aead.cpp
// Stego via 2D FFT phase quantization with a keystream "turtle" across RGB planes,
// hardened with ChaCha20-Poly1305 AEAD and KDF (PBKDF2 + HKDF).
// Adds small ECC (Repetition-3 for header; Hamming(7,4) for ciphertext||tag) + optional interleaving.
// Makes turtle path key = SHA256(pass) for BOTH embed & extract so header can be decoded deterministically.
// Build: g++ -std=c++17 -O3 -march=native turtle_fft_stego_aead.cpp -o turtlefft

// Debug output: set to 1 to enable detailed logging
#ifndef DEBUG
#define DEBUG 0
#endif

#include <bits/stdc++.h>
using namespace std;

// ============================ stb_image / stb_image_write ====================
#define STB_IMAGE_IMPLEMENTATION
#define STB_IMAGE_WRITE_IMPLEMENTATION
#include "stb_image.h"
#include "stb_image_write.h"

 // ============================ Endian helpers (portable) ======================
 static inline uint32_t load32_le(const void* p){
     uint8_t b[4]; memcpy(b, p, 4);
     return (uint32_t)b[0] | ((uint32_t)b[1]<<8) | ((uint32_t)b[2]<<16) | ((uint32_t)b[3]<<24);
 }
 static inline void store32_le(uint32_t v, void* p){
     uint8_t* b=(uint8_t*)p;
     b[0]= (uint8_t)(v      &0xFF);
     b[1]= (uint8_t)((v>>8 )&0xFF);
     b[2]= (uint8_t)((v>>16)&0xFF);
     b[3]= (uint8_t)((v>>24)&0xFF);
 }

// ============================ SHA-256 / HMAC / PBKDF2 / HKDF =================
namespace sha256 {
static inline uint32_t rotr(uint32_t x, int n){ return (x>>n)|(x<<(32-n)); }
static inline uint32_t ch(uint32_t x,uint32_t y,uint32_t z){ return (x&y)^(~x&z); }
static inline uint32_t maj(uint32_t x,uint32_t y,uint32_t z){ return (x&y)^(x&z)^(y&z); }
static inline uint32_t bs0(uint32_t x){ return rotr(x,2)^rotr(x,13)^rotr(x,22); }
static inline uint32_t bs1(uint32_t x){ return rotr(x,6)^rotr(x,11)^rotr(x,25); }
static inline uint32_t ss0(uint32_t x){ return rotr(x,7)^rotr(x,18)^(x>>3); }
static inline uint32_t ss1(uint32_t x){ return rotr(x,17)^rotr(x,19)^(x>>10); }
static const uint32_t K[64]={
0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};

static array<uint8_t,32> hash(const uint8_t* data, size_t len){
    vector<uint8_t> m(data, data+len);
    uint64_t bitlen = (uint64_t)len*8;
    m.push_back(0x80);
    while((m.size()+8)%64) m.push_back(0);
    for(int i=7;i>=0;--i) m.push_back((uint8_t)(bitlen>>(8*i)));
    uint32_t H[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    for(size_t off=0; off<m.size(); off+=64){
        uint32_t w[64];
        for(int i=0;i<16;++i){
            w[i]=(m[off+4*i]<<24)|(m[off+4*i+1]<<16)|(m[off+4*i+2]<<8)|(m[off+4*i+3]);
        }
        for(int i=16;i<64;++i) w[i]=ss1(w[i-2])+w[i-7]+ss0(w[i-15])+w[i-16];
        uint32_t a=H[0],b=H[1],c=H[2],d=H[3],e=H[4],f=H[5],g=H[6],h=H[7];
        for(int i=0;i<64;++i){
            uint32_t t1=h+bs1(e)+ch(e,f,g)+K[i]+w[i];
            uint32_t t2=bs0(a)+maj(a,b,c);
            h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
        }
        H[0]+=a; H[1]+=b; H[2]+=c; H[3]+=d; H[4]+=e; H[5]+=f; H[6]+=g; H[7]+=h;
    }
    array<uint8_t,32> out{};
    for(int i=0;i<8;++i){
        out[4*i+0]=(H[i]>>24)&0xFF;
        out[4*i+1]=(H[i]>>16)&0xFF;
        out[4*i+2]=(H[i]>>8)&0xFF;
        out[4*i+3]= H[i]     &0xFF;
    }
    return out;
}
static array<uint8_t,32> hash(const string& s){ return hash((const uint8_t*)s.data(), s.size()); }

static void hmac_sha256(const uint8_t* key,size_t klen,const uint8_t* msg,size_t mlen,uint8_t out[32]){
    uint8_t k0[64]={0};
    if(klen>64){
        auto h=hash(key,klen); memcpy(k0,h.data(),32);
    } else memcpy(k0,key,klen);
    uint8_t ipad[64], opad[64];
    for(int i=0;i<64;i++){ ipad[i]=k0[i]^0x36; opad[i]=k0[i]^0x5c; }
    vector<uint8_t> inner(64+mlen);
    memcpy(inner.data(), ipad, 64); memcpy(inner.data()+64, msg, mlen);
    auto hi = hash(inner.data(), inner.size());
    uint8_t tmp[64+32];
    memcpy(tmp, opad, 64); memcpy(tmp+64, hi.data(), 32);
    auto ho = hash(tmp, 96);
    memcpy(out, ho.data(), 32);
}

static void pbkdf2_hmac_sha256(const string& pass,const vector<uint8_t>& salt,uint32_t iters,uint8_t* out,size_t dkLen){
    // RFC 8018
    uint32_t blocks = (uint32_t)((dkLen + 31)/32);
    vector<uint8_t> U(32), T(32);
    for(uint32_t i=1;i<=blocks;i++){
        // U1 = HMAC( pass, salt || INT(i) )
        vector<uint8_t> msg(salt.begin(), salt.end());
        uint8_t be[4]={(uint8_t)(i>>24),(uint8_t)(i>>16),(uint8_t)(i>>8),(uint8_t)i};
        msg.insert(msg.end(), be, be+4);
        hmac_sha256((const uint8_t*)pass.data(), pass.size(), msg.data(), msg.size(), U.data());
        memcpy(T.data(), U.data(), 32);
        for(uint32_t j=2;j<=iters;j++){
            hmac_sha256((const uint8_t*)pass.data(), pass.size(), U.data(), 32, U.data());
            for(int k=0;k<32;k++) T[k]^=U[k];
        }
        size_t off=(size_t)(i-1)*32, need=min((size_t)32, dkLen-off);
        memcpy(out+off, T.data(), need);
    }
}

static void hkdf_sha256_extract(const uint8_t* salt,size_t slen,const uint8_t* ikm,size_t ikmlen,uint8_t prk[32]){
    hmac_sha256(salt,slen,ikm,ikmlen,prk);
}
static void hkdf_sha256_expand(const uint8_t prk[32], const uint8_t* info,size_t infolen, uint8_t* out, size_t L){
    // RFC 5869
    uint8_t T[32]; size_t Tlen=0; uint8_t ctr=1; size_t pos=0;
    while(pos < L){
        vector<uint8_t> msg(T, T+Tlen);
        msg.insert(msg.end(), info, info+infolen);
        msg.push_back(ctr);
        hmac_sha256(prk,32,msg.data(),msg.size(),T);
        Tlen=32;
        size_t need=min((size_t)32, L-pos);
        memcpy(out+pos, T, need); pos+=need; ctr++;
    }
}
} // ns sha256

// ============================ ChaCha20 / Poly1305 (RFC 8439) ================
namespace chacha_poly {
static inline uint32_t rotl(uint32_t v,int n){return (v<<n)|(v>>(32-n));}
static inline void qr(uint32_t& a,uint32_t& b,uint32_t& c,uint32_t& d){
    a+=b; d^=a; d=rotl(d,16);
    c+=d; b^=c; b=rotl(b,12);
    a+=b; d^=a; d=rotl(d,8);
    c+=d; b^=c; b=rotl(b,7);
}
struct ChaCha20 {
    uint32_t s[16];
    void init(const uint8_t key[32], const uint8_t nonce[12], uint32_t counter=1){
        const uint8_t sigma[16] = {'e','x','p','a','n','d',' ','3','2','-','b','y','t','e',' ','k'};
        s[0]=load32_le(&sigma[0]);  s[1]=load32_le(&sigma[4]);
        s[2]=load32_le(&sigma[8]);  s[3]=load32_le(&sigma[12]);
        for(int i=0;i<8;i++) s[4+i]=load32_le(key + 4*i);
        s[12]=counter;
        s[13]=load32_le(nonce+0); s[14]=load32_le(nonce+4); s[15]=load32_le(nonce+8);
    }
    void block(uint8_t out[64]){
        uint32_t x[16]; memcpy(x,s,64);
        for(int i=0;i<10;i++){
            qr(x[0],x[4],x[8],x[12]); qr(x[1],x[5],x[9],x[13]); qr(x[2],x[6],x[10],x[14]); qr(x[3],x[7],x[11],x[15]);
            qr(x[0],x[5],x[10],x[15]); qr(x[1],x[6],x[11],x[12]); qr(x[2],x[7],x[8],x[13]); qr(x[3],x[4],x[9],x[14]);
        }
        for(int i=0;i<16;i++) x[i]+=s[i];
        // Keystream words are little-endian per spec
        for(int i=0;i<16;i++) store32_le(x[i], out + 4*i);
        s[12]++; // counter++
    }
    void xor_stream(uint8_t* data,size_t len){
        uint8_t keystream[64]; size_t off=0;
        while(off<len){
            block(keystream);
            size_t n=min((size_t)64, len-off);
            for(size_t i=0;i<n;i++) data[off+i]^=keystream[i];
            off+=n;
        }
    }
};

// Poly1305 (little-endian math)
static void poly1305_mac(uint8_t tag[16], const uint8_t* msg, size_t mlen, const uint8_t key[32]){
    // r (clamped) and s:
    uint64_t r0 = load32_le(&key[0])  & 0x3ffffff;
    uint64_t r1 = (load32_le(&key[3]) >> 2) & 0x3ffff03;
    uint64_t r2 = (load32_le(&key[6]) >> 4) & 0x3ffc0ff;
    uint64_t r3 = (load32_le(&key[9]) >> 6) & 0x3f03fff;
    uint64_t r4 = (load32_le(&key[12])>> 8) & 0x00fffff;

    // multipliers for r values (rename to avoid later redeclaration with 'sN' used for the key part)
    uint64_t sr1 = r1*5, sr2 = r2*5, sr3 = r3*5, sr4 = r4*5;
    uint64_t h0=0,h1=0,h2=0,h3=0,h4=0;

    const uint8_t* p=msg; size_t left=mlen;
    while(left){
        uint64_t t0=0,t1=0,t2=0,t3=0,t4=0;
        size_t n=min(left,(size_t)16);
        uint8_t block[16]={0}; memcpy(block,p,n); p+=n; left-=n;
    t0 =  load32_le(&block[0])  & 0x3ffffff;
    t1 = (load32_le(&block[3]) >> 2) & 0x3ffffff;
    t2 = (load32_le(&block[6]) >> 4) & 0x3ffffff;
    t3 = (load32_le(&block[9]) >> 6) & 0x3ffffff;
    // fallback: always add the 1 bit to the top of t4 (Poly1305 pad)
    t4 = (load32_le(&block[12]) >> 8);
        t4 |= (1ull<<24);

        h0+=t0; h1+=t1; h2+=t2; h3+=t3; h4+=t4;

        uint64_t d0 = h0*r0 + h1*sr4 + h2*sr3 + h3*sr2 + h4*sr1;
        uint64_t d1 = h0*r1 + h1*r0 + h2*sr4 + h3*sr3 + h4*sr2;
        uint64_t d2 = h0*r2 + h1*r1 + h2*r0 + h3*sr4 + h4*sr3;
        uint64_t d3 = h0*r3 + h1*r2 + h2*r1 + h3*r0 + h4*sr4;
        uint64_t d4 = h0*r4 + h1*r3 + h2*r2 + h3*r1 + h4*r0;

        uint64_t c;
        c = (d0 >> 26); h0 = d0 & 0x3ffffff;
        d1 += c; c = (d1 >> 26); h1 = d1 & 0x3ffffff;
        d2 += c; c = (d2 >> 26); h2 = d2 & 0x3ffffff;
        d3 += c; c = (d3 >> 26); h3 = d3 & 0x3ffffff;
        d4 += c; c = (d4 >> 26); h4 = d4 & 0x3ffffff;
        h0 += c*5; c = h0 >> 26; h0 &= 0x3ffffff; h1 += c;
    }

    // final reduction
    uint64_t c = h1 >> 26; h1 &= 0x3ffffff; h2 += c;
    c = h2 >> 26; h2 &= 0x3ffffff; h3 += c;
    c = h3 >> 26; h3 &= 0x3ffffff; h4 += c;
    c = h4 >> 26; h4 &= 0x3ffffff; h0 += c*5;
    c = h0 >> 26; h0 &= 0x3ffffff; h1 += c;

    // compute h + -p
    uint64_t g0 = h0 + 5; c = g0 >> 26; g0 &= 0x3ffffff;
    uint64_t g1 = h1 + c; c = g1 >> 26; g1 &= 0x3ffffff;
    uint64_t g2 = h2 + c; c = g2 >> 26; g2 &= 0x3ffffff;
    uint64_t g3 = h3 + c; c = g3 >> 26; g3 &= 0x3ffffff;
    uint64_t g4 = h4 + c - (1ull<<26);

    uint64_t mask = (g4 >> 63) - 1;
    h0 = (h0 & ~mask) | (g0 & mask);
    h1 = (h1 & ~mask) | (g1 & mask);
    h2 = (h2 & ~mask) | (g2 & mask);
    h3 = (h3 & ~mask) | (g3 & mask);
    h4 = (h4 & ~mask) | (g4 & mask) + (1ull<<26);

    // s part
    uint64_t s0 = load32_le(&key[16]);
    uint64_t s1 = load32_le(&key[20]);
    uint64_t s2 = load32_le(&key[24]);
    uint64_t s3 = load32_le(&key[28]);

    uint64_t f0 = ((h0      ) | (h1<<26)) + s0;
    uint64_t f1 = ((h1>>6  ) | (h2<<20)) + s1 + (f0>>32); f0&=0xffffffff;
    uint64_t f2 = ((h2>>12 ) | (h3<<14)) + s2 + (f1>>32); f1&=0xffffffff;
    uint64_t f3 = ((h3>>18 ) | (h4<<8 )) + s3 + (f2>>32); f2&=0xffffffff; f3&=0xffffffff;

    store32_le((uint32_t)f0, &tag[0]);
    store32_le((uint32_t)f1, &tag[4]);
    store32_le((uint32_t)f2, &tag[8]);
    store32_le((uint32_t)f3, &tag[12]);
}

// AEAD: encrypt in place; aad may be null/0.
static bool chacha20_poly1305_seal(const uint8_t key[32], const uint8_t nonce[12],
                                   const uint8_t* aad,size_t aadlen,
                                   uint8_t* data,size_t len,
                                   uint8_t tag[16]){
    // one-time Poly key = ChaCha20(key, nonce, counter=0) block
    uint8_t otk[64]; ChaCha20 c0; c0.init(key, nonce, 0); c0.block(otk);
    // encrypt with ChaCha20 counter=1
    ChaCha20 c; c.init(key, nonce, 1); c.xor_stream(data, len);
    // compute tag over aad || pad16 || ciphertext || pad16 || len(aad)||len(ct)
    auto le64=[&](uint64_t x){ array<uint8_t,8> b{}; for(int i=0;i<8;i++) b[i]=(x>>(8*i))&0xff; return b; };
    vector<uint8_t> mac; mac.reserve(((aadlen+15)/16)*16 + ((len+15)/16)*16 + 16);
    if(aad && aadlen){ mac.insert(mac.end(), aad, aad+aadlen); while(mac.size()%16) mac.push_back(0); }
    if(len){ mac.insert(mac.end(), data, data+len); while(mac.size()%16) mac.push_back(0); }
    auto la=le64(aadlen), lc=le64(len);
    mac.insert(mac.end(), la.begin(), la.end());
    mac.insert(mac.end(), lc.begin(), lc.end());
    poly1305_mac(tag, mac.data(), mac.size(), otk);
    return true;
}
static bool chacha20_poly1305_open(const uint8_t key[32], const uint8_t nonce[12],
                                   const uint8_t* aad,size_t aadlen,
                                   uint8_t* data,size_t len,
                                   const uint8_t tag[16]){
    // recompute tag then decrypt
    uint8_t mytag[16];
    uint8_t otk[64]; ChaCha20 c0; c0.init(key, nonce, 0); c0.block(otk);
    auto le64=[&](uint64_t x){ array<uint8_t,8> b{}; for(int i=0;i<8;i++) b[i]=(x>>(8*i))&0xff; return b; };
    vector<uint8_t> mac; mac.reserve(((aadlen+15)/16)*16 + ((len+15)/16)*16 + 16);
    if(aad && aadlen){ mac.insert(mac.end(), aad, aad+aadlen); while(mac.size()%16) mac.push_back(0); }
    if(len){ mac.insert(mac.end(), data, data+len); while(mac.size()%16) mac.push_back(0); }
    auto la=le64(aadlen), lc=le64(len);
    mac.insert(mac.end(), la.begin(), la.end());
    mac.insert(mac.end(), lc.begin(), lc.end());
    poly1305_mac(mytag, mac.data(), mac.size(), otk);
    if(!std::equal(mytag,mytag+16,tag)) return false;
    ChaCha20 c; c.init(key, nonce, 1); c.xor_stream(data, len);
    return true;
}
} // ns chacha_poly

// ============================ CRC32 (unused by AEAD, kept for debug) ========
static uint32_t CRC_TABLE[256];
static void crc32_init(){ for(uint32_t i=0;i<256;i++){ uint32_t c=i; for(int j=0;j<8;j++) c=(c&1)?(0xEDB88320u^(c>>1)):(c>>1); CRC_TABLE[i]=c; } }
static uint32_t crc32_bytes(const vector<uint8_t>& v){ uint32_t c=0xFFFFFFFFu; for(uint8_t b:v) c=CRC_TABLE[(c^b)&0xFF]^(c>>8); return c^0xFFFFFFFFu; }

// ============================ FFT (radix-2) ==================================
static void fft1d(vector<complex<double>>& a, bool inverse){
    const size_t n=a.size();
    for(size_t i=1,j=0;i<n;i++){
        size_t bit=n>>1; for(; j&bit; bit>>=1) j^=bit; j^=bit; if(i<j) swap(a[i],a[j]);
    }
    for(size_t len=2; len<=n; len<<=1){
        double ang = 2*M_PI/len * (inverse?-1:1);
        complex<double> wlen(cos(ang), sin(ang));
        for(size_t i=0;i<n;i+=len){
            complex<double> w(1,0);
            for(size_t j=0;j<len/2;j++){
                auto u=a[i+j], v=a[i+j+len/2]*w;
                a[i+j]=u+v; a[i+j+len/2]=u-v; w*=wlen;
            }
        }
    }
    if(inverse){ for(auto& z:a) z/=double(n); }
}
static void fft2d(vector<vector<complex<double>>>& A, bool inverse){
    const size_t H=A.size(), W=A[0].size();
    for(size_t y=0;y<H;y++) fft1d(A[y], inverse);
    for(size_t x=0;x<W;x++){
        vector<complex<double>> col(H); for(size_t y=0;y<H;y++) col[y]=A[y][x];
        fft1d(col, inverse); for(size_t y=0;y<H;y++) A[y][x]=col[y];
    }
}

// ============================ Utilities =====================================
static size_t next_pow2(size_t v){ size_t p=1; while(p<v) p<<=1; return p; }
static inline pair<int,int> conj_idx(int y,int x,int H,int W){
    int yy = (y==0)?0:(H - y); int xx = (x==0)?0:(W - x); return {yy%H, xx%W};
}
static inline double hypot_idx(int y,int x){ return hypot((double)y,(double)x); }

struct Params {
    double alpha = 0.22, rmin = 0.05, rmax = 0.45, magmin = 0.01, density=0.7, jitter=0.05;
    bool center=false;
    uint32_t pbkdf2_iter = 200000;
};

static void to_planes_u8(const uint8_t* img,int W,int H,int comp, vector<double>& R,vector<double>& G,vector<double>& B){
    R.resize((size_t)W*H); G.resize((size_t)W*H); B.resize((size_t)W*H);
    for(int i=0;i<W*H;i++){ R[i]=img[3*i+0]; G[i]=img[3*i+1]; B[i]=img[3*i+2]; }
}
static void from_planes_u8(const vector<double>& R,const vector<double>& G,const vector<double>& B,int W,int H, vector<uint8_t>& out){
    out.assign((size_t)W*H*3,255);
    auto clamp8=[&](double v){ return (uint8_t)max(0.0, min(255.0, round(v))); };
    for(int i=0;i<W*H;i++){ out[3*i+0]=clamp8(R[i]); out[3*i+1]=clamp8(G[i]); out[3*i+2]=clamp8(B[i]); }
}
static void apply_center(vector<double>& P,int W,int H,bool on){ if(!on) return; for(int y=0;y<H;y++) for(int x=0;x<W;x++) if(((x+y)&1)) P[y*W+x]*=-1.0; }
static vector<vector<complex<double>>> pad_to_fft(const vector<double>& P,int W,int H,int& PW,int& PH){
    PW=(int)next_pow2(W); PH=(int)next_pow2(H);
    vector<vector<complex<double>>> F(PH, vector<complex<double>>(PW,{0.0,0.0}));
    for(int y=0;y<H;y++) for(int x=0;x<W;x++) F[y][x]=complex<double>(P[y*W+x],0.0);
    return F;
}
static vector<double> ifft_crop(const vector<vector<complex<double>>>& F,int W,int H){
    vector<double> P((size_t)W*H);
    for(int y=0;y<H;y++) for(int x=0;x<W;x++) P[y*W+x]=F[y][x].real();
    return P;
}
static double median_abs(const vector<vector<complex<double>>>& F){
    vector<double> mags; mags.reserve(F.size()*F[0].size());
    for(auto& r:F) for(auto& z:r) mags.push_back(abs(z));
    nth_element(mags.begin(), mags.begin()+mags.size()/2, mags.end());
    return mags[mags.size()/2];
}

// ============================ Bit I/O =======================================
static vector<uint8_t> bytes_from_bits(const vector<uint8_t>& bits){
    vector<uint8_t> out; out.reserve(bits.size()/8+1);
    for(size_t i=0;i<bits.size(); i+=8){
        uint8_t v=0; for(int j=0;j<8;j++) v=(v<<1)| ( (i+j<bits.size())?bits[i+j]:0 );
        out.push_back(v);
    }
    return out;
}
static vector<uint8_t> bits_from_bytes(const vector<uint8_t>& bytes){
    vector<uint8_t> bits; bits.reserve(bytes.size()*8);
    for(uint8_t b: bytes) for(int i=7;i>=0;--i) bits.push_back((b>>i)&1);
    return bits;
}

// ============================ ECC helpers =================================
// Repetition-3 for header (simple majority decode)
static vector<uint8_t> rep3_encode_bits(const vector<uint8_t>& bits){
    vector<uint8_t> out; out.reserve(bits.size()*3);
    for(uint8_t b: bits){ out.push_back(b); out.push_back(b); out.push_back(b); }
    return out;
}
static vector<uint8_t> rep3_decode_bits(const vector<uint8_t>& bits, bool &ok){
    ok = true; vector<uint8_t> out; if(bits.size()%3!=0) ok = false;
    for(size_t i=0;i+2<bits.size(); i+=3){
        int s = bits[i] + bits[i+1] + bits[i+2]; out.push_back((s>=2)?1:0);
    }
    return out;
}

// Hamming(7,4) encode/decode for payload (ciphertext||tag)
// Data nibble: d3,d2,d1,d0 -> codeword bits positions 1..7 = p1,p2,d3,p3,d2,d1,d0
static vector<uint8_t> ham74_encode_bits(const vector<uint8_t>& bits){
    vector<uint8_t> out; size_t n = bits.size(); size_t pad = (4 - (n%4))%4; size_t total = n + pad;
    for(size_t i=0;i<total;i+=4){
        uint8_t d3 = (i < n) ? bits[i] : 0;
        uint8_t d2 = (i+1 < n) ? bits[i+1] : 0;
        uint8_t d1 = (i+2 < n) ? bits[i+2] : 0;
        uint8_t d0 = (i+3 < n) ? bits[i+3] : 0;
        uint8_t p1 = d3 ^ d2 ^ d0;
        uint8_t p2 = d3 ^ d1 ^ d0;
        uint8_t p3 = d2 ^ d1 ^ d0;
        out.push_back(p1); out.push_back(p2); out.push_back(d3); out.push_back(p3);
        out.push_back(d2); out.push_back(d1); out.push_back(d0);
    }
    return out;
}
static vector<uint8_t> ham74_decode_bits(const vector<uint8_t>& bits, size_t orig_bits_len){
    vector<uint8_t> out; out.reserve((bits.size()/7)*4);
    for(size_t i=0;i+6<bits.size(); i+=7){
        uint8_t c1=bits[i], c2=bits[i+1], c3=bits[i+2], c4=bits[i+3], c5=bits[i+4], c6=bits[i+5], c7=bits[i+6];
        uint8_t p1 = c1 ^ c3 ^ c5 ^ c7;
        uint8_t p2 = c2 ^ c3 ^ c6 ^ c7;
        uint8_t p3 = c4 ^ c5 ^ c6 ^ c7;
        uint8_t syndrome = p1 + (p2<<1) + (p3<<2);
        if(syndrome){
            size_t pos = (size_t)syndrome - 1; // 0-based
            switch(pos){
                case 0: c1 ^= 1; break; case 1: c2 ^= 1; break; case 2: c3 ^= 1; break;
                case 3: c4 ^= 1; break; case 4: c5 ^= 1; break; case 5: c6 ^= 1; break;
                case 6: c7 ^= 1; break;
            }
        }
        out.push_back(c3); out.push_back(c5); out.push_back(c6); out.push_back(c7);
    }
    if(out.size() > orig_bits_len) out.resize(orig_bits_len);
    return out;
}

// ============================ KDF / Key split ================================
struct KeyMaterial {
    array<uint8_t,32> path_key;
    array<uint8_t,32> aead_key;
    array<uint8_t,12> nonce;
    array<uint8_t,16> salt;
};
static KeyMaterial derive_keys(const string& pass, const array<uint8_t,16>& salt, uint32_t iters){
    KeyMaterial km{};
    vector<uint8_t> dk(32);
    sha256::pbkdf2_hmac_sha256(pass, vector<uint8_t>(salt.begin(), salt.end()), iters, dk.data(), dk.size());
    uint8_t prk[32];
    sha256::hkdf_sha256_extract(nullptr,0, dk.data(), dk.size(), prk);
    uint8_t out[32+32+12];
    const uint8_t info1[] = "fft_turtle:keys";
    sha256::hkdf_sha256_expand(prk, info1, sizeof(info1)-1, out, sizeof(out));
    memcpy(km.path_key.data(), out, 32);
    memcpy(km.aead_key.data(), out+32, 32);
    memcpy(km.nonce.data(), out+64, 12);
    km.salt = salt;
    return km;
}

// ============================ Keystreams for turtle/opcodes ==================
struct KS {
    array<uint8_t,32> state{};
    size_t pos=32;
    uint32_t ctr=0;
    explicit KS(const array<uint8_t,32>& key){ state.fill(0); }
    array<uint8_t,32> key;
    KS(const array<uint8_t,32>& k, bool init): key(k) { (void)init; }
    uint8_t next_byte(){
        if(pos>=32){
            // SHA-256(key || ctr)
            string block; block.append((const char*)key.data(), key.size());
            block.push_back(char(0xAA));
            uint8_t ctr_le[4]; store32_le(ctr, ctr_le);
            block.append((const char*)ctr_le, 4);
            auto h=sha256::hash((const uint8_t*)block.data(), block.size());
            state = h; pos=0; ctr++;
        }
        return state[pos++];
    }
    int next_opcode3(){ static int bitpool=0,bits=0; while(bits<3){ bitpool=(bitpool<<8)|next_byte(); bits+=8; } int op=(bitpool>>(bits-3))&7; bits-=3; return op; }
    bool hit_density(double density){ // return true if we embed on this candidate
        // uniform 0..255 < density*256
        return next_byte() < (uint8_t)floor(density*256.0);
    }
    double jitter(double maxj){ // uniform in [-maxj, +maxj]
        int16_t r = (int16_t)((next_byte()<<8)|next_byte());
        double u = r / 32768.0; // [-1,1)
        return u * maxj;
    }
};

// ============================ Phase write/read ===============================
static inline bool on_axis(int y,int x,int H,int W){
    return (y==0 || x==0 || (H%2==0 && y==H/2) || (W%2==0 && x==W/2));
}
static inline void write_bit_on_bin(vector<vector<complex<double>>>& F, int y,int x, int bit, double alpha, double jitter, KS& ks){
    auto v = F[y][x];
    double mag = max(1e-12, abs(v));
    double target = bit ? +alpha : -alpha;
    double j = ks.jitter(jitter);
    double theta = target + j;
    complex<double> nv = polar(mag, theta);
    F[y][x] = nv;
    auto [cy,cx]=conj_idx(y,x,(int)F.size(),(int)F[0].size());
    if(!(cy==y && cx==x)) {
        F[cy][cx]=conj(nv);
    } else {
        F[y][x]=complex<double>(mag,0.0);
        #if DEBUG
        fprintf(stderr,"[WARN] write_bit_on_bin forcing real at y=%d x=%d (H=%zu W=%zu, conj=self)\n", y, x, F.size(), F[0].size());
        #endif
    }
}
static inline int read_bit_from_bin(const vector<vector<complex<double>>>& F, int y,int x, double alpha){
    auto v = F[y][x];
    double th = atan2(v.imag(), v.real());
    // decide by proximity to +alpha vs -alpha
    double dpos = fabs(th - (+alpha));
    double dneg = fabs(th - (-alpha));
    return (dpos <= dneg) ? 1 : 0;
}

// ============================ Turtle selection ===============================
struct Turtle {
    int y,x,plane,H,W;
    KS* ks_walk; // for turtle path selection
    array<KS*,3> ks_planes; // per-plane keystreams for jitter
    vector<vector<vector<uint8_t>>> visited;
    double rmin, rmax;
    const vector<vector<vector<complex<double>>>>* Fref;
    vector<double> thr; // per-plane mag threshold
    Turtle(int H,int W, KS* ks_walk, array<KS*,3> ks_planes,double rmin,double rmax,
           const vector<vector<vector<complex<double>>>>* Fref, vector<double> thr)
    : y(0),x(0),plane(0),H(H),W(W),ks_walk(ks_walk),ks_planes(ks_planes),visited(3, vector<vector<uint8_t>>(H, vector<uint8_t>(W,0))),
      rmin(rmin),rmax(rmax),Fref(Fref),thr(thr)
    {
    // deterministic seed from path key and dims (bind the walk to the pass)
    // Use walk keystream's key for the turtle walk itself (path selection)
    string seed = "seed:" + to_string(H) + "x" + to_string(W);
    seed.append("|key:");
    seed.append(string(reinterpret_cast<const char*>(ks_walk->key.data()), ks_walk->key.size()));
    auto h = sha256::hash(seed);
        uint64_t s=0; for(int i=0;i<8;i++) s=(s<<8)|h[i];
        y = (int)((s>>0)%H); x=(int)((s>>16)%W); plane=(int)((s>>32)%3);
    }
    inline bool annulus_ok(int yy,int xx){
        double r = hypot_idx(yy,xx);
        return (r >= rmin*min(H,W) && r <= rmax*min(H,W));
    }
    inline bool mag_ok(int p,int yy,int xx){
        return abs((*Fref)[p][yy][xx]) >= thr[p];
    }
    void advance_to_valid(){
        // Use walk keystream for turtle movement
        KS& ks = *ks_walk;
        while(true){
            int op = ks.next_opcode3();
            switch(op){
                case 0: plane=(plane+1)%3; break;
                case 1: x=(x+1)%W; break;
                case 2: y=(y+1)%H; break;
                case 3: x=(x-1+W)%W; break;
                case 4: y=(y-1+H)%H; break;
                case 5: x=(x+1)%W; y=(y+1)%H; break;
                case 6: x=(x-1+W)%W; y=(y+1)%H; break;
                case 7: default: break;
            }
            if(on_axis(y,x,H,W)) continue;
            if((y==0&&x==0)) continue;
            if(visited[plane][y][x]) continue;
            if(!annulus_ok(y,x)) continue;
            if(!mag_ok(plane,y,x)) continue;
            auto [cy,cx]=conj_idx(y,x,H,W);
            if(visited[plane][cy][cx]) continue;
            return;
        }
    }
    void mark_here(){
        visited[plane][y][x]=1;
        auto [cy,cx]=conj_idx(y,x,H,W);
        visited[plane][cy][cx]=1;
    }
};

// ============================ CLI / framing =================================
static void usage(){
    fprintf(stderr,
      "Usage:\n"
      "  Embed  : turtlefft embed   --in host.png --out stego.png --secret TEXT --pass PW\n"
      "            [--alpha 0.22 --jitter 0.05 --density 0.7 --rmin 0.05 --rmax 0.45 --magmin 0.01 --center 0 --pbkdf2_iter 200000]\n"
      "  Extract: turtlefft extract --in stego.png --pass PW\n");
}
struct Args {
    string mode, inPath, outPath, secret, pass;
    Params P;
};
static bool parse_args(int argc,char**argv, Args& A){
    if(argc<2) return false; A.mode=argv[1];
    for(int i=2;i<argc;i++){
        string k=argv[i]; auto need=[&](){ if(i+1>=argc) return string(); return string(argv[++i]); };
        if(k=="--in") A.inPath=need();
        else if(k=="--out") A.outPath=need();
        else if(k=="--secret") A.secret=need();
        else if(k=="--pass") A.pass=need();
        else if(k=="--alpha") A.P.alpha=stod(need());
        else if(k=="--jitter") A.P.jitter=stod(need());
        else if(k=="--density") A.P.density=stod(need());
        else if(k=="--rmin") A.P.rmin=stod(need());
        else if(k=="--rmax") A.P.rmax=stod(need());
        else if(k=="--magmin") A.P.magmin=stod(need());
        else if(k=="--center") { string v=need(); A.P.center=(v=="1"||v=="true"); }
        else if(k=="--pbkdf2_iter") A.P.pbkdf2_iter=(uint32_t)stoul(need());
        else { fprintf(stderr,"Unknown arg: %s\n", k.c_str()); return false; }
    }
    if(A.mode!="embed" && A.mode!="extract") return false;
    if(A.inPath.empty() || A.pass.empty()) return false;
    if(A.mode=="embed" && (A.outPath.empty() || A.secret.empty())) return false;
    return true;
}

static void u32be_push(vector<uint8_t>& v, uint32_t x){
    v.push_back((x>>24)&0xFF); v.push_back((x>>16)&0xFF); v.push_back((x>>8)&0xFF); v.push_back(x&0xFF);
}
static uint32_t u32be_read(const uint8_t* p){ return (uint32_t)p[0]<<24 | (uint32_t)p[1]<<16 | (uint32_t)p[2]<<8 | p[3]; }

// Header layout (plaintext):
// MAGIC(4)="FTTG", VER(1)=2, FLAGS(1), SALT(16), NONCE(12), CLEN(4), TAG(16) follows after ciphertext bits.
struct Header {
    array<uint8_t,4> magic{{'F','T','T','G'}};
    uint8_t ver=2, flags=0;
    array<uint8_t,16> salt{};
    array<uint8_t,12> nonce{};
    uint32_t clen=0;
    array<uint8_t,16> tag{};
    vector<uint8_t> to_bytes() const {
        vector<uint8_t> b;
        b.insert(b.end(), magic.begin(), magic.end());
        b.push_back(ver); b.push_back(flags);
        b.insert(b.end(), salt.begin(), salt.end());
        b.insert(b.end(), nonce.begin(), nonce.end());
        u32be_push(b, clen);
        // tag NOT included in header bits (we append after ciphertext bits)
        return b;
    }
    static size_t fixed_len(){ return 4+1+1+16+12+4; } // 38 bytes
};

// ============================ EMBED =========================================
static void do_embed(const Args& A){
    int W,H,comp;
    stbi_uc* img = stbi_load(A.inPath.c_str(), &W, &H, &comp, 3);
    if(!img){ fprintf(stderr,"Failed to load %s\n", A.inPath.c_str()); exit(1); }

    vector<double> R,G,B; to_planes_u8(img,W,H,3,R,G,B);
    stbi_image_free(img);
    apply_center(R,W,H,A.P.center); apply_center(G,W,H,A.P.center); apply_center(B,W,H,A.P.center);

    int PW,PH;
    auto FR=pad_to_fft(R,W,H,PW,PH), FG=pad_to_fft(G,W,H,PW,PH), FB=pad_to_fft(B,W,H,PW,PH);
    #if DEBUG
    fprintf(stderr,"[EMBED] Image size: %dx%d, FFT padded: %dx%d\n", W, H, PW, PH);
    #endif
    fft2d(FR,false); fft2d(FG,false); fft2d(FB,false);
    double medR=median_abs(FR), medG=median_abs(FG), medB=median_abs(FB);
    vector<double> thr={A.P.magmin*medR, A.P.magmin*medG, A.P.magmin*medB};

    // KDF: salt + key split
    array<uint8_t,16> salt{}; {
        std::random_device rd; for(auto &b:salt) b = (uint8_t)rd();
    }
    auto km = derive_keys(A.pass, salt, A.P.pbkdf2_iter);

    // Prepare header first (it will be AAD for AEAD)
    Header Hdr; Hdr.salt=km.salt; Hdr.nonce=km.nonce; Hdr.clen=(uint32_t)A.secret.size();
    vector<uint8_t> header_bytes = Hdr.to_bytes();
    
    #if DEBUG
    fprintf(stderr,"[DEBUG EMBED] clen=%u, header_bytes[34..37]=%02x %02x %02x %02x\n",
            Hdr.clen, header_bytes[34], header_bytes[35], header_bytes[36], header_bytes[37]);
    #endif

    // AEAD encrypt secret with header as AAD
    vector<uint8_t> pt(A.secret.begin(), A.secret.end());
    vector<uint8_t> ct = pt;
    array<uint8_t,16> tag{};
    {
        using namespace chacha_poly;
        if(!chacha20_poly1305_seal(km.aead_key.data(), km.nonce.data(),
                                   header_bytes.data(), header_bytes.size(),
                                   ct.data(), ct.size(), tag.data())){
            fprintf(stderr,"AEAD seal failed\n"); exit(1);
        }
    }

    // ECC-protected frame:
    // - Header: Repetition-3 of header bits
    // - Payload (ciphertext||tag): Hamming(7,4) over payload bits
    vector<uint8_t> header_bits = bits_from_bytes(header_bytes);
    auto header_rep3 = rep3_encode_bits(header_bits);
    vector<uint8_t> payload_bytes; payload_bytes.reserve(ct.size()+16);
    payload_bytes.insert(payload_bytes.end(), ct.begin(), ct.end()); payload_bytes.insert(payload_bytes.end(), tag.begin(), tag.end());
    auto payload_bits = bits_from_bytes(payload_bytes);
    auto payload_ham = ham74_encode_bits(payload_bits);
    // final bitstream to embed
    vector<uint8_t> bits; bits.reserve(header_rep3.size() + payload_ham.size());
    bits.insert(bits.end(), header_rep3.begin(), header_rep3.end());
    bits.insert(bits.end(), payload_ham.begin(), payload_ham.end());

    // capacity estimate (unique pairs, excluding axes/DC)
    size_t usable=0;
    auto count_plane=[&](const vector<vector<complex<double>>>& F, double t){
        size_t c=0; for(int y=0;y<PH;y++) for(int x=0;x<PW;x++){
            if(on_axis(y,x,PH,PW)) continue;
            if(y==0&&x==0) continue;
            double r=hypot_idx(y,x); if(r<A.P.rmin*min(PH,PW) || r>A.P.rmax*min(PH,PW)) continue;
            if(abs(F[y][x])<t) continue;
            auto [cy,cx]=conj_idx(y,x,PH,PW); if(!(cy==y&&cx==x)) c++;
        } return c/2;
    };
    usable += count_plane(FR,thr[0]); usable += count_plane(FG,thr[1]); usable += count_plane(FB,thr[2]);
    if(bits.size() > usable){
        fprintf(stderr,"Message too large. Need %zu bits (after ECC), capacity ~%zu bits.\n", bits.size(), usable);
        exit(1);
    }

    // Turtle with path_key, density & jitter
    vector<vector<vector<complex<double>>>> F3={FR,FG,FB};
    // Path key must be salt-independent so extractor can read header deterministically.
    auto path_key = sha256::hash(A.pass);
    
    // Derive walk keystream and per-plane subkeys from path_key using HKDF
    uint8_t sub[32*4]; // walk + R + G + B
    const uint8_t info[] = "turtle_keys";
    sha256::hkdf_sha256_expand(path_key.data(), info, sizeof(info)-1, sub, sizeof(sub));
    array<uint8_t,32> key_walk, key_r, key_g, key_b;
    memcpy(key_walk.data(), sub+0,   32);
    memcpy(key_r.data(),    sub+32,  32);
    memcpy(key_g.data(),    sub+64,  32);
    memcpy(key_b.data(),    sub+96,  32);
    KS ks_walk(key_walk, true);
    KS ks_r(key_r, true);
    KS ks_g(key_g, true);
    KS ks_b(key_b, true);
    array<KS*,3> ks_planes = {&ks_r, &ks_g, &ks_b};
    
    Turtle T(PH,PW, &ks_walk, ks_planes, A.P.rmin, A.P.rmax, &F3, thr);

    size_t written=0;
    for(size_t i=0;i<bits.size();++i){
        // advance to a candidate, but respect density: maybe skip this candidate (without consuming payload bit)
        while(true){
            T.advance_to_valid();
            if(ks_walk.hit_density(A.P.density)) break;
            // mark as used-but-empty to reduce detectability (we avoid landing again here)
            T.mark_here();
        }
        #if DEBUG
        if(i < 10) fprintf(stderr,"[EMBED bit %zu] plane=%d y=%d x=%d bit=%d\n", i, T.plane, T.y, T.x, bits[i]);
        #endif
        // Use the keystream for the current plane
        write_bit_on_bin(F3[T.plane], T.y, T.x, bits[i], A.P.alpha, A.P.jitter, *ks_planes[T.plane]);
        #if DEBUG
        if(i < 10){
            auto v = F3[T.plane][T.y][T.x];
            double ph = atan2(v.imag(), v.real());
            fprintf(stderr,"         after write: phase=%.4f (expect %s%.4f)\n", ph, bits[i]?"+":"", bits[i]?(+A.P.alpha):(-A.P.alpha));
        }
        #endif
        T.mark_here();
        written++;
    }

    // IFFT & save
    fft2d(F3[0],true); fft2d(F3[1],true); fft2d(F3[2],true);
    auto R2=ifft_crop(F3[0],W,H), G2=ifft_crop(F3[1],W,H), B2=ifft_crop(F3[2],W,H);
    apply_center(R2,W,H,A.P.center); apply_center(G2,W,H,A.P.center); apply_center(B2,W,H,A.P.center);
    vector<uint8_t> out; from_planes_u8(R2,G2,B2,W,H,out);
    if(!stbi_write_png(A.outPath.c_str(), W,H,3,out.data(), W*3)){
        fprintf(stderr,"PNG write failed: %s\n", A.outPath.c_str()); exit(1);
    }
    fprintf(stdout,"Embedded %zu bits into %s (payload %u bytes, ver=2, salt/nonce in header)\n",
            written, A.outPath.c_str(), Hdr.clen);
}

// ============================ EXTRACT =======================================
static void do_extract(const Args& A){
    int W,H,comp;
    stbi_uc* img = stbi_load(A.inPath.c_str(), &W, &H, &comp, 3);
    if(!img){ fprintf(stderr,"Failed to load %s\n", A.inPath.c_str()); exit(1); }
    vector<double> R,G,B; to_planes_u8(img,W,H,3,R,G,B); stbi_image_free(img);
    apply_center(R,W,H,A.P.center); apply_center(G,W,H,A.P.center); apply_center(B,W,H,A.P.center);
    int PW,PH;
    auto FR=pad_to_fft(R,W,H,PW,PH), FG=pad_to_fft(G,W,H,PW,PH), FB=pad_to_fft(B,W,H,PW,PH);
    #if DEBUG
    fprintf(stderr,"[EXTRACT] Image size: %dx%d, FFT padded: %dx%d\n", W, H, PW, PH);
    #endif
    fft2d(FR,false); fft2d(FG,false); fft2d(FB,false);
    double medR=median_abs(FR), medG=median_abs(FG), medB=median_abs(FB);
    #if DEBUG
    fprintf(stderr,"[EXTRACT] Median magnitudes: R=%.2f G=%.2f B=%.2f\n", medR, medG, medB);
    // Check a few specific bins that we wrote to
    fprintf(stderr,"[EXTRACT] FB[1][15] mag=%.4f phase=%.4f\n", abs(FB[1][15]), atan2(FB[1][15].imag(), FB[1][15].real()));
    fprintf(stderr,"[EXTRACT] FB[3][17] mag=%.4f phase=%.4f\n", abs(FB[3][17]), atan2(FB[3][17].imag(), FB[3][17].real()));
    #endif
    vector<double> thr={A.P.magmin*medR, A.P.magmin*medG, A.P.magmin*medB};
    vector<vector<vector<complex<double>>>> F3={FR,FG,FB};

    // We must first read fixed-size header bytes (38 bytes) + then CIPHERTEXT (clen) + TAG(16)
    // But we don't know clen yet; so: read 38 bytes first, parse, derive keys, then read (clen + 16) bytes.
    // 1) Build turtle with a provisional path_key: we need salt/nonce to derive keys -> we must read header first.
    // For extraction, the turtle path depends only on dims and path_key (derived from pass+salt), but SALT is in header.
    // So we initially read the header using a *temporary* path built from a provisional key: we can't — circular.
    // Fix: header is **plaintext**, and turtle path must be *independent of salt* for the first 38 bytes.
    // Therefore we derive path_key directly from pass with a constant salt for the first 38 bytes, then switch.
    // Simplify: path for entire stream uses path_key derived from PBKDF2(pass, SALT) -> circular.
    // Resolution: We keep turtle path always derived from **path_key = SHA256(pass)** (saltless),
    // while AEAD uses salted keys. That keeps determinism and breaks the circular dependency.

    // Recompute thresholds and set up turtle with path_key = SHA256(pass)
    auto path_key = sha256::hash(A.pass);
    
    // Derive walk keystream and per-plane subkeys from path_key using HKDF
    uint8_t sub[32*4]; // walk + R + G + B
    const uint8_t info[] = "turtle_keys";
    sha256::hkdf_sha256_expand(path_key.data(), info, sizeof(info)-1, sub, sizeof(sub));
    array<uint8_t,32> key_walk, key_r, key_g, key_b;
    memcpy(key_walk.data(), sub+0,   32);
    memcpy(key_r.data(),    sub+32,  32);
    memcpy(key_g.data(),    sub+64,  32);
    memcpy(key_b.data(),    sub+96,  32);
    KS ks_walk(key_walk, true);
    KS ks_r(key_r, true);
    KS ks_g(key_g, true);
    KS ks_b(key_b, true);
    array<KS*,3> ks_planes = {&ks_r, &ks_g, &ks_b};
    
    auto median_thr = thr;
    Turtle T(PH,PW, &ks_walk, ks_planes, A.P.rmin, A.P.rmax, &F3, median_thr);

    auto read_next_bit = [&](double alpha)->int{
        while(true){ T.advance_to_valid(); if(ks_walk.hit_density(A.P.density)) break; T.mark_here(); }
        // Consume the same jitter bytes the embedder used so KS stays in sync
        (void)ks_planes[T.plane]->jitter(A.P.jitter);
        int b = read_bit_from_bin(F3[T.plane], T.y, T.x, alpha);
        T.mark_here();
        #if DEBUG
        static int cnt=0;
        if(cnt<10){
            auto v = F3[T.plane][T.y][T.x];
            double ph = atan2(v.imag(), v.real());
            fprintf(stderr,"[EXTRACT bit %d] plane=%d y=%d x=%d bit=%d phase=%.4f\n", cnt++, T.plane, T.y, T.x, b, ph);
        }
        #endif
        return b;
    };

    // Read ECC-protected header: repetition-3 encoding
    size_t header_bits = Header::fixed_len()*8;
    size_t header_rep3_bits = header_bits * 3;
    vector<uint8_t> hdr_rep3; hdr_rep3.reserve(header_rep3_bits);
    for(size_t i=0;i<header_rep3_bits;i++) hdr_rep3.push_back(read_next_bit(A.P.alpha));
    bool ok_header=true;
    auto hdr_bits = rep3_decode_bits(hdr_rep3, ok_header);
    if(!ok_header){ fprintf(stderr,"Header ECC length mismatch.\n"); exit(1); }
    auto hdr_bytes = bytes_from_bits(hdr_bits);
    // Debug: print first 4 header bytes
    #if DEBUG
    fprintf(stderr,"[DEBUG] First 4 header bytes: %02x %02x %02x %02x (expect: 46 54 54 47 = FTTG)\n",
            hdr_bytes[0], hdr_bytes[1], hdr_bytes[2], hdr_bytes[3]);
    #endif
    if(hdr_bytes.size() < Header::fixed_len()){ fprintf(stderr,"Header truncated.\n"); exit(1); }
    if(!(hdr_bytes[0]=='F'&&hdr_bytes[1]=='T'&&hdr_bytes[2]=='T'&&hdr_bytes[3]=='G')){ fprintf(stderr,"Magic not found.\n"); exit(1); }
    if(hdr_bytes[4] != 2){ fprintf(stderr,"Unsupported version (%u).\n", hdr_bytes[4]); exit(1); }
    
    // Instead of parsing fields individually, just keep the original hdr_bytes for AAD
    // But also parse for our use
    Header Hdr;
    Hdr.magic[0]=hdr_bytes[0]; Hdr.magic[1]=hdr_bytes[1]; Hdr.magic[2]=hdr_bytes[2]; Hdr.magic[3]=hdr_bytes[3];
    Hdr.ver = hdr_bytes[4]; Hdr.flags=hdr_bytes[5];
    memcpy(Hdr.salt.data(),  &hdr_bytes[6], 16);
    memcpy(Hdr.nonce.data(), &hdr_bytes[22], 12);
    
    #if DEBUG
    fprintf(stderr,"[DEBUG EXTRACT] hdr_bytes[34..37]=%02x %02x %02x %02x\n",
            hdr_bytes[34], hdr_bytes[35], hdr_bytes[36], hdr_bytes[37]);
    #endif
    
    Hdr.clen = u32be_read(&hdr_bytes[34]);
    
    #if DEBUG
    fprintf(stderr,"[DEBUG] Parsed header: clen=%u\n", Hdr.clen);
    #endif

    // Now read Hamming(7,4)-encoded ciphertext + tag
    size_t rest_bytes = (size_t)Hdr.clen + 16;
    size_t payload_bits_len = rest_bytes * 8;
    size_t ham_blocks = (payload_bits_len + 3) / 4; // number of 4-bit blocks
    size_t ham_encoded_bits = ham_blocks * 7;
    vector<uint8_t> ham_bits; ham_bits.reserve(ham_encoded_bits);
    for(size_t i=0;i<ham_encoded_bits;i++) ham_bits.push_back(read_next_bit(A.P.alpha));
    auto payload_bits = ham74_decode_bits(ham_bits, payload_bits_len);
    auto rest = bytes_from_bits(payload_bits);
    if(rest.size() < rest_bytes){ fprintf(stderr,"Payload truncated after ECC decode.\n"); exit(1); }
    vector<uint8_t> ct(rest.begin(), rest.begin()+Hdr.clen);
    array<uint8_t,16> tag; memcpy(tag.data(), rest.data()+Hdr.clen, 16);

    // Derive AEAD keys using PBKDF2(pass, salt)
    auto km = derive_keys(A.pass, Hdr.salt, A.P.pbkdf2_iter);
    
    // Use the original decoded header bytes directly for AAD verification
    // (instead of reconstructing, to ensure exact match)
    vector<uint8_t> header_aad(hdr_bytes.begin(), hdr_bytes.begin() + Header::fixed_len());

    // Decrypt + verify with header as AAD
    using namespace chacha_poly;
    if(!chacha20_poly1305_open(km.aead_key.data(), km.nonce.data(),
                               header_aad.data(), header_aad.size(),
                               ct.data(), ct.size(), tag.data())){
        fprintf(stderr,"Auth failed (wrong pass or data corrupted).\n"); exit(1);
    }
    string secret(ct.begin(), ct.end());
    printf("%s\n", secret.c_str());
}

// ============================ main ==========================================
int main(int argc,char**argv){
    ios::sync_with_stdio(false); cin.tie(nullptr);
    Args A; if(!parse_args(argc,argv,A)){ usage(); return 1; }
    if(A.mode=="embed") do_embed(A); else do_extract(A);
    return 0;
}
