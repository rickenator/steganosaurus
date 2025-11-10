#define STB_IMAGE_WRITE_IMPLEMENTATION
#include "../include/stb_image_write.h"
#include <vector>
#include <cstdlib>
int main(){
    const int W=256, H=256;
    std::vector<unsigned char> img(W*H*3);
    // Add texture: light noise + gradient
    for(int y=0;y<H;y++) for(int x=0;x<W;x++){
        int i=(y*W+x)*3;
        int base_r = 180 + (x*40)/W;  // gradient
        int base_g = 180 + (y*40)/H;
        int base_b = 200;
        int noise = (rand() % 20) - 10; // ±10 noise
        img[i+0] = base_r + noise;
        img[i+1] = base_g + noise;
        img[i+2] = base_b + noise;
    }
    if(!stbi_write_png("host.png", W, H, 3, img.data(), W*3)) return 1;
    return 0;
}
