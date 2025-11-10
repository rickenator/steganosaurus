// steganosaur.cpp
// Steganography via 2D FFT phase quantization using a keystream-driven "turtle" across RGB planes.
// Build: g++ -std=c++17 -O3 -march=native turtle_fft_stego.cpp -o turtlefft

#include <bits/stdc++.h>
using namespace std;

// ============================ stb_image / stb_image_write ============================
#define STB_IMAGE_IMPLEMENTATION
#define STB_IMAGE_WRITE_IMPLEMENTATION
// Expect the headers in the same folder (see wget in instructions)
#include "stb_image.h"
#include "stb_image_write.h"

// ============================ SHA-256 (minimal) ======================================
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
        out[4*i+0]=(uint8_t)((H[i]>>24)&0xFF);
        out[4*i+1]=(uint8_t)((H[i]>>16)&0xFF);
        out[4*i+2]=(uint8_t)((H[i]>>8)&0xFF);
        out[4*i+3]=(uint8_t)(H[i]&0xFF);
    }
    return out;
}
static array<uint8_t,32> hash(const string& s){ return hash((const uint8_t*)s.data(), s.size()); }
} // namespace sha256

// ============================ CRC32 ==========================================
static uint32_t CRC_TABLE[256];
static void crc32_init(){
    for(uint32_t i=0;i<256;i++){
        uint32_t c=i;
        for(int j=0;j<8;j++) c = (c&1)?(0xEDB88320u^(c>>1)):(c>>1);
        CRC_TABLE[i]=c;
    }
}
static uint32_t crc32_bytes(const vector<uint8_t>& v){
    uint32_t c=0xFFFFFFFFu;
    for(uint8_t b: v) c = CRC_TABLE[(c^b)&0xFF] ^ (c>>8);
    return c^0xFFFFFFFFu;
}

// ============================ FFT (radix-2) ==================================
static void fft1d(vector<complex<double>>& a, bool inverse){
    const size_t n=a.size();
    // bit-reverse
    for(size_t i=1,j=0;i<n;i++){
        size_t bit=n>>1;
        for(; j&bit; bit>>=1) j^=bit;
        j^=bit;
        if(i<j) swap(a[i],a[j]);
    }
    for(size_t len=2; len<=n; len<<=1){
        double ang = 2*M_PI/len * (inverse?-1:1);
        complex<double> wlen(cos(ang), sin(ang));
        for(size_t i=0;i<n;i+=len){
            complex<double> w(1,0);
            for(size_t j=0;j<len/2;j++){
                auto u=a[i+j], v=a[i+j+len/2]*w;
                a[i+j]=u+v;
                a[i+j+len/2]=u-v;
                w*=wlen;
            }
        }
    }
    if(inverse){
        for(auto& z:a) z/=double(n);
    }
}
static void fft2d(vector<vector<complex<double>>>& A, bool inverse){
    const size_t H=A.size(), W=A[0].size();
    for(size_t y=0;y<H;y++) fft1d(A[y], inverse);
    for(size_t x=0;x<W;x++){
        vector<complex<double>> col(H);
        for(size_t y=0;y<H;y++) col[y]=A[y][x];
        fft1d(col, inverse);
        for(size_t y=0;y<H;y++) A[y][x]=col[y];
    }
}

// ============================ Utils ==========================================
static size_t next_pow2(size_t v){ size_t p=1; while(p<v) p<<=1; return p; }
static inline pair<int,int> conj_idx(int y,int x,int H,int W){
    int yy = (y==0)?0:(H - y);
    int xx = (x==0)?0:(W - x);
    return {yy%H, xx%W};
}
static inline double hypot_idx(int y,int x){ return hypot((double)y,(double)x); }

struct Params {
    double alpha = 0.22;
    double rmin = 0.05;
    double rmax = 0.45;
    double magmin = 0.01;  // fraction of median magnitude per plane
    bool center = false;   // if true, (-1)^(x+y) pre/post
};

static void to_planes_u8(const uint8_t* img, int W,int H,int comp, vector<double>& R, vector<double>& G, vector<double>& B){
    R.resize((size_t)W*H); G.resize((size_t)W*H); B.resize((size_t)W*H);
    for(int y=0;y<H;y++){
        for(int x=0;x<W;x++){
            int i = (y*W + x)*comp;
            uint8_t r = img[i+0], g = img[i+1], b = img[i+2];
            R[y*W+x]=r; G[y*W+x]=g; B[y*W+x]=b;
        }
    }
}
static void from_planes_u8(const vector<double>& R,const vector<double>& G,const vector<double>& B,
                           int W,int H, vector<uint8_t>& out){
    out.assign((size_t)W*H*3, 255);
    for(int y=0;y<H;y++){
        for(int x=0;x<W;x++){
            size_t i=y*W+x;
            auto clamp8=[&](double v){ return (uint8_t)std::max(0.0, std::min(255.0, round(v))); };
            out[3*i+0]=clamp8(R[i]);
            out[3*i+1]=clamp8(G[i]);
            out[3*i+2]=clamp8(B[i]);
        }
    }
}
static void apply_center(vector<double>& P, int W,int H, bool on){
    if(!on) return;
    for(int y=0;y<H;y++) for(int x=0;x<W;x++){
        if(((x+y)&1)) P[y*W+x]*=-1.0;
    }
}
static vector<vector<complex<double>>> pad_to_fft(const vector<double>& P, int W,int H, int& PW,int& PH){
    PW = (int)next_pow2(W); PH = (int)next_pow2(H);
    vector<vector<complex<double>>> F(PH, vector<complex<double>>(PW, {0.0,0.0}));
    for(int y=0;y<H;y++) for(int x=0;x<W;x++){
        F[y][x] = complex<double>(P[y*W+x], 0.0);
    }
    return F;
}
static vector<double> ifft_crop(const vector<vector<complex<double>>>& F, int W,int H){
    vector<double> P((size_t)W*H,0.0);
    for(int y=0;y<H;y++) for(int x=0;x<W;x++){
        P[y*W+x] = F[y][x].real();
    }
    return P;
}
static double median_abs(const vector<vector<complex<double>>>& F){
    vector<double> mags; mags.reserve(F.size()*F[0].size());
    for(auto& row:F) for(auto& z:row) mags.push_back(abs(z));
    nth_element(mags.begin(), mags.begin()+mags.size()/2, mags.end());
    return mags[mags.size()/2];
}

// ============================ Keystream & framing ============================
struct KS {
    string pass;
    array<uint8_t,32> buf{};
    size_t pos = 32;
    uint32_t ctr = 0;
    explicit KS(const string& p): pass(p) {}
    uint8_t next_byte(){
        if(pos>=32){
            string block=pass;
            block.push_back(char(0));
            block.append((const char*)&ctr, sizeof(ctr));
            buf = sha256::hash(block);
            ctr++; pos=0;
        }
        return buf[pos++];
    }
    // produce 3-bit opcodes
    int next_opcode3(){
        // pack 3 bits from successive bytes
        static int bitpool = 0, bits = 0;
        while(bits < 3){
            bitpool = (bitpool<<8) | next_byte();
            bits += 8;
        }
        int op = (bitpool >> (bits-3)) & 0x7;
        bits -= 3;
        return op;
    }
};
static void xor_keystream(vector<uint8_t>& data, const string& pass){
    KS ks(pass);
    for(size_t i=0;i<data.size();++i) data[i]^=ks.next_byte();
}
static void u32be_push(vector<uint8_t>& v, uint32_t x){
    v.push_back((x>>24)&0xFF);
    v.push_back((x>>16)&0xFF);
    v.push_back((x>>8)&0xFF);
    v.push_back(x&0xFF);
}
static uint32_t u32be_read(const uint8_t* p){
    return (uint32_t(p[0])<<24)|(uint32_t(p[1])<<16)|(uint32_t(p[2])<<8)|(uint32_t(p[3]));
}

// ============================ Turtle selection ===============================
struct Turtle {
    int y,x,plane;
    int H,W;
    KS &ks;
    vector<vector<vector<uint8_t>>> visited; // [plane][y][x]
    double rmin, rmax, magmin;
    const vector<vector<vector<complex<double>>>>* Fref;

    Turtle(int H,int W, KS& ks,double rmin,double rmax,double magmin,
           const vector<vector<vector<complex<double>>>>* Fref)
    : H(H),W(W),ks(ks),visited(3, vector<vector<uint8_t>>(H, vector<uint8_t>(W,0))),
      rmin(rmin),rmax(rmax),magmin(magmin),Fref(Fref)
    {
        auto seed = sha256::hash(string("seed:")+to_string(H)+"x"+to_string(W)+":");
        // Combine with pass to avoid trivial collisions
        auto ph = sha256::hash(string("pass:")+string((const char*)sha256::hash(ks.pass).data(), 8));
        uint64_t s = 0;
        for(int i=0;i<8;i++) s = (s<<8) | ph[i];
        y = (int)( (s>>0)  % (uint64_t)H );
        x = (int)( (s>>16) % (uint64_t)W );
        plane = (int)( (s>>32) % 3ull );
    }
    inline bool annulus_ok(int yy,int xx){
        double r = hypot_idx(yy,xx);
        return (r >= rmin*min(H,W) && r <= rmax*min(H,W));
    }
    inline bool mag_ok(int p,int yy,int xx){
        double m = abs((*Fref)[p][yy][xx]);
        return m >= magmin;
    }
    // advance turtle until valid unvisited bin
    void advance_to_valid(){
        while(true){
            int op = ks.next_opcode3();
            switch(op){
                case 0: plane=(plane+1)%3; break;          // hop plane
                case 1: x=(x+1)%W; break;
                case 2: y=(y+1)%H; break;
                case 3: x=(x-1+W)%W; break;
                case 4: y=(y-1+H)%H; break;
                case 5: x=(x+1)%W; y=(y+1)%H; break;
                case 6: x=(x-1+W)%W; y=(y+1)%H; break;
                case 7: default: break; // SKIP
            }
            if((y==0&&x==0)) continue; // avoid DC
            if(visited[plane][y][x]) continue;
            if(!annulus_ok(y,x)) continue;
            if(!mag_ok(plane,y,x)) continue;
            // also mark conjugate to avoid double-use
            auto [cy,cx] = conj_idx(y,x,H,W);
            if(visited[plane][cy][cx]) { continue; }
            return;
        }
    }
    void mark_here(){
        visited[plane][y][x]=1;
        auto [cy,cx]=conj_idx(y,x,H,W);
        visited[plane][cy][cx]=1;
    }
};

// ============================ Bit IO =========================================
static vector<uint8_t> bytes_from_bits(const vector<uint8_t>& bits){
    vector<uint8_t> out; out.reserve(bits.size()/8+1);
    for(size_t i=0;i<bits.size(); i+=8){
        uint8_t v=0;
        for(int j=0;j<8;j++){
            v = (v<<1) | ( (i+j<bits.size())?bits[i+j]:0 );
        }
        out.push_back(v);
    }
    return out;
}
static vector<uint8_t> bits_from_bytes(const vector<uint8_t>& bytes){
    vector<uint8_t> bits; bits.reserve(bytes.size()*8);
    for(uint8_t b: bytes){
        for(int i=7;i>=0;--i) bits.push_back( (b>>i)&1 );
    }
    return bits;
}

// ============================ Phase write/read ===============================
static inline void write_bit_on_bin(vector<vector<complex<double>>>& F, int y,int x, int bit, double alpha){
    auto v = F[y][x];
    double mag = abs(v);
    double target = bit? +alpha : -alpha;
    complex<double> nv = polar(mag, target);
    F[y][x] = nv;
    auto [cy,cx] = conj_idx(y,x,(int)F.size(),(int)F[0].size());
    if(!(cy==y && cx==x)) F[cy][cx] = conj(nv);
    else F[y][x] = complex<double>(mag, 0.0);
}
static inline int read_bit_from_bin(const vector<vector<complex<double>>>& F, int y,int x){
    auto v = F[y][x];
    double theta = atan2(v.imag(), v.real());
    return (theta >= 0.0) ? 1 : 0;
}

// ============================ CLI ===========================================
static void usage(){
    fprintf(stderr,
      "Usage:\n"
      "  Embed  : turtlefft embed   --in host.png --out stego.png --secret TEXT --pass PW [--alpha 0.22 --rmin 0.05 --rmax 0.45 --magmin 0.01]\n"
      "  Extract: turtlefft extract --in stego.png             --pass PW [--alpha 0.22 --rmin 0.05 --rmax 0.45 --magmin 0.01]\n");
}

struct Args {
    string mode, inPath, outPath, secret, pass;
    Params P;
};
static bool parse_args(int argc,char**argv, Args& A){
    if(argc<2) return false;
    A.mode=argv[1];
    for(int i=2;i<argc;i++){
        string k=argv[i], v;
        auto need=[&](){ if(i+1>=argc) return string(); return string(argv[++i]); };
        if(k=="--in") A.inPath = need();
        else if(k=="--out") A.outPath = need();
        else if(k=="--secret") A.secret = need();
        else if(k=="--pass") A.pass = need();
        else if(k=="--alpha") A.P.alpha = stod(need());
        else if(k=="--rmin") A.P.rmin = stod(need());
        else if(k=="--rmax") A.P.rmax = stod(need());
        else if(k=="--magmin") A.P.magmin = stod(need());
        else if(k=="--center") { string s=need(); A.P.center = (s=="1"||s=="true"); }
        else { fprintf(stderr,"Unknown arg: %s\n", k.c_str()); return false; }
    }
    if(A.mode!="embed" && A.mode!="extract") return false;
    if(A.inPath.empty() || A.pass.empty()) return false;
    if(A.mode=="embed" && (A.outPath.empty() || A.secret.empty())) return false;
    return true;
}

// ============================ EMBED =========================================
static void do_embed(const Args& A){
    int W,H,comp;
    stbi_uc* img = stbi_load(A.inPath.c_str(), &W, &H, &comp, 3);
    if(!img){ fprintf(stderr,"Failed to load %s\n", A.inPath.c_str()); exit(1); }

    vector<double> R,G,B; to_planes_u8(img,W,H,3,R,G,B);
    stbi_image_free(img);

    apply_center(R,W,H,A.P.center);
    apply_center(G,W,H,A.P.center);
    apply_center(B,W,H,A.P.center);

    int PW,PH;
    auto FR = pad_to_fft(R,W,H,PW,PH);
    auto FG = pad_to_fft(G,W,H,PW,PH);
    auto FB = pad_to_fft(B,W,H,PW,PH);

    fft2d(FR,false); fft2d(FG,false); fft2d(FB,false);

    // per-plane thresholds
    double medR = median_abs(FR), medG = median_abs(FG), medB = median_abs(FB);
    double thrR = A.P.magmin * medR, thrG = A.P.magmin * medG, thrB = A.P.magmin * medB;

    // Prepare payload
    vector<uint8_t> data(A.secret.begin(), A.secret.end());
    vector<uint8_t> data_enc = data; xor_keystream(data_enc, A.pass);

    vector<uint8_t> frame;
    // MAGIC "FTTG", ver=1, flags=0
    frame.insert(frame.end(), {'F','T','T','G'});
    frame.push_back(1); // ver
    frame.push_back(0); // flags
    u32be_push(frame, (uint32_t)data.size());
    frame.insert(frame.end(), data_enc.begin(), data_enc.end());
    crc32_init();
    u32be_push(frame, crc32_bytes(data_enc));

    auto bits = bits_from_bytes(frame);
    // Capacity check by pessimistic count of usable bins (across planes)
    // We'll approximate: count valid candidates by sampling
    size_t usable_est=0;
    for(int p=0;p<3;p++){
        auto &F = (p==0?FR:(p==1?FG:FB));
        double thr = (p==0?thrR:(p==1?thrG:thrB));
        for(int y=0;y<PH;y++){
            for(int x=0;x<PW;x++){
                if(y==0&&x==0) continue;
                double r = hypot_idx(y,x);
                if(r < A.P.rmin*min(PH,PW) || r > A.P.rmax*min(PH,PW)) continue;
                if(abs(F[y][x]) < thr) continue;
                auto [cy,cx]=conj_idx(y,x,PH,PW);
                if(!(cy==y&&cx==x)) usable_est++;
            }
        }
    }
    // each unique pair contributes 1 usable; above double-counts pairs roughly twice
    usable_est /= 2;
    if(bits.size() > usable_est){
        fprintf(stderr,"Message too large. Need %zu bits, capacity ~%zu bits.\n", bits.size(), usable_est);
        exit(1);
    }

    // Turtle embedding
    vector<vector<vector<complex<double>>>> F3 = {FR,FG,FB};
    // magnitude thresholds for mag_ok
    vector<double> Tthr = {thrR,thrG,thrB};
    KS ks(A.pass);
    Turtle T(PH,PW,ks, A.P.rmin, A.P.rmax, 0.0, &F3);
    // override Turtle.mag_ok to use plane threshold (quick hack via lambda-like)
    auto mag_ok_plane = [&](int p,int y,int x){
        return abs(F3[p][y][x]) >= Tthr[p];
    };
    size_t written=0;
    for(size_t i=0;i<bits.size();++i){
        // advance until valid according to annulus + per-plane mag
        while(true){
            T.advance_to_valid();
            if(mag_ok_plane(T.plane, T.y, T.x)) break;
        }
        // write bit on that plane
        write_bit_on_bin(F3[T.plane], T.y, T.x, bits[i], A.P.alpha);
        T.mark_here();
        written++;
    }

    // IFFT & reassemble
    fft2d(F3[0], true); fft2d(F3[1], true); fft2d(F3[2], true);
    auto R2 = ifft_crop(F3[0], W,H);
    auto G2 = ifft_crop(F3[1], W,H);
    auto B2 = ifft_crop(F3[2], W,H);
    apply_center(R2,W,H,A.P.center);
    apply_center(G2,W,H,A.P.center);
    apply_center(B2,W,H,A.P.center);

    vector<uint8_t> out; from_planes_u8(R2,G2,B2,W,H,out);
    if(!stbi_write_png(A.outPath.c_str(), W,H,3, out.data(), W*3)){
        fprintf(stderr,"PNG write failed: %s\n", A.outPath.c_str());
        exit(1);
    }
    fprintf(stdout,"Embedded %zu bits (%zu bytes frame). Wrote %s\n",
            written, frame.size(), A.outPath.c_str());
}

// ============================ EXTRACT =======================================
static void do_extract(const Args& A){
    int W,H,comp;
    stbi_uc* img = stbi_load(A.inPath.c_str(), &W, &H, &comp, 3);
    if(!img){ fprintf(stderr,"Failed to load %s\n", A.inPath.c_str()); exit(1); }
    vector<double> R,G,B; to_planes_u8(img,W,H,3,R,G,B);
    stbi_image_free(img);

    apply_center(R,W,H,A.P.center);
    apply_center(G,W,H,A.P.center);
    apply_center(B,W,H,A.P.center);

    int PW,PH;
    auto FR = pad_to_fft(R,W,H,PW,PH);
    auto FG = pad_to_fft(G,W,H,PW,PH);
    auto FB = pad_to_fft(B,W,H,PW,PH);
    fft2d(FR,false); fft2d(FG,false); fft2d(FB,false);

    double medR = median_abs(FR), medG = median_abs(FG), medB = median_abs(FB);
    double thrR = A.P.magmin * medR, thrG = A.P.magmin * medG, thrB = A.P.magmin * medB;

    vector<vector<vector<complex<double>>>> F3 = {FR,FG,FB};
    vector<double> Tthr = {thrR,thrG,thrB};

    KS ks(A.pass);
    Turtle T(PH,PW,ks, A.P.rmin, A.P.rmax, 0.0, &F3);
    auto mag_ok_plane = [&](int p,int y,int x){
        return abs(F3[p][y][x]) >= Tthr[p];
    };

    auto read_next_bit = [&]()->int{
        while(true){
            T.advance_to_valid();
            if(mag_ok_plane(T.plane, T.y, T.x)) break;
        }
        int b = read_bit_from_bin(F3[T.plane], T.y, T.x);
        T.mark_here();
        return b;
    };

    // Read header: 10 bytes => 80 bits
    vector<uint8_t> hdr_bits; hdr_bits.reserve(80);
    for(int i=0;i<80;i++) hdr_bits.push_back(read_next_bit());
    auto hdr = bytes_from_bits(hdr_bits);
    if(hdr.size()<10 || !(hdr[0]=='F'&&hdr[1]=='T'&&hdr[2]=='T'&&hdr[3]=='G')){
        fprintf(stderr,"Magic not found (wrong passphrase or not embedded).\n"); exit(1);
    }
    uint8_t ver = hdr[4]; (void)ver;
    uint8_t flags = hdr[5]; (void)flags;
    uint32_t LEN = u32be_read(&hdr[6]);

    // Read payload: LEN + CRC(4) bytes => (LEN+4)*8 bits
    vector<uint8_t> pay_bits; pay_bits.reserve((LEN+4)*8);
    for(size_t i=0;i< (size_t)(LEN+4)*8; ++i) pay_bits.push_back(read_next_bit());
    auto pay = bytes_from_bits(pay_bits);
    if(pay.size() < LEN+4){ fprintf(stderr,"Payload truncated.\n"); exit(1); }
    vector<uint8_t> data_enc(pay.begin(), pay.begin()+LEN);
    uint32_t crc_be = u32be_read((uint8_t*)&pay[LEN]);

    xor_keystream(data_enc, A.pass);
    crc32_init();
    uint32_t crc_calc = crc32_bytes(data_enc);
    if(crc_calc != crc_be){
        fprintf(stderr,"CRC mismatch (wrong pass or image corrupted).\n"); exit(1);
    }
    string s(data_enc.begin(), data_enc.end());
    printf("%s\n", s.c_str());
}

// ============================ main ==========================================
int main(int argc,char**argv){
    ios::sync_with_stdio(false);
    cin.tie(nullptr);

    Args A;
    if(!parse_args(argc,argv,A)){ usage(); return 1; }

    if(A.mode=="embed"){
        do_embed(A);
    } else {
        do_extract(A);
    }
    return 0;
}
