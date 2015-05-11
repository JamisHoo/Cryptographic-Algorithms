/******************************************************************************
 *  Copyright (c) 2015 Jamis Hoo
 *  Distributed under the MIT license 
 *  (See accompanying file LICENSE or copy at http://opensource.org/licenses/MIT)
 *  
 *  Project: 
 *  Filename: sha1.cc 
 *  Version: 1.0
 *  Author: Jamis Hoo
 *  E-mail: hoojamis@gmail.com
 *  Date: May 11, 2015
 *  Time: 15:47:06
 *  Description: SHA-1
 *****************************************************************************/
#include <cstring>
#include <cinttypes>
#include <cassert>
#include <iostream>

// data: must reserve extra 128 bytes available
// len: length in bytes
// hash: at least 20 bytes available
void sha1(unsigned char* data, size_t len, char* hash) {
    constexpr size_t block_size = 64;

    uint32_t h0 = 0x67452301, h1 = 0xEFCDAB89, h2 = 0x98BADCFE, h3 = 0x10325476, h4 = 0xC3D2E1F0;
    
    size_t ml = len * 8;

    // append bit '1'
    data[len++] = 0x80;

    // append thus the resulting message length (in bits) is congruent to 448 (mod 512)
    while (len % block_size != 56) data[len++] = 0x00;

    // append length
    data[len++] = ml >> 56, data[len++] = ml >> 48, 
    data[len++] = ml >> 40, data[len++] = ml >> 32,
    data[len++] = ml >> 24, data[len++] = ml >> 16,
    data[len++] = ml >> 8, data[len++] = ml;

    // rotate functions
    auto left_rotate = [](uint32_t x, const size_t i)->uint32_t { return x << i | x >> (sizeof(uint32_t) * 8 - i); };

    // for each trunk
    for (size_t i = 0; i < len / block_size; ++i) {
        // extend 16 32-bit words to 80 32-bit words
        uint32_t word[80];
        for (size_t j = 0; j < 16; ++j)
            word[j] = data[i * block_size + 4 * j + 0] << 24 | 
                      data[i * block_size + 4 * j + 1] << 16 | 
                      data[i * block_size + 4 * j + 2] <<  8 | 
                      data[i * block_size + 4 * j + 3];

        for (size_t j = 16; j < 80; ++j) {
            word[j] = left_rotate(word[j - 3] ^ word[j - 8] ^ word[j - 14] ^ word[j - 16], 1);
        }


        uint32_t a = h0, b = h1, c = h2, d = h3, e = h4;
        
        // main loop
        for (size_t j = 0; j < 80; ++j) {
            int f, k;
            if (j < 20) 
                f = (b & c) | (~b & d), k = 0x5A827999;
            else if (j < 40)
                f = b ^ c ^ d, k = 0x6ED9EBA1;
            else if (j < 60)
                f = (b & c) | (b & d) | (c & d), k = 0x8F1BBCDC;
            else 
                f = b ^ c ^ d, k = 0xCA62C1D6;
            
            uint32_t tmp = left_rotate(a, 5) + f + e + k + word[j];
            e = d, d = c, c = left_rotate(b, 30), b = a, a = tmp;
        }

        h0 += a, h1 += b, h2 += c, h3 += d, h4 += e;
    }

    hash[0] = h0 >> 24, hash[1] = h0 >> 16, hash[2] = h0 >> 8, hash[3] = h0;
    hash[4] = h1 >> 24, hash[5] = h1 >> 16, hash[6] = h1 >> 8, hash[7] = h1;
    hash[8] = h2 >> 24, hash[9] = h2 >> 16, hash[10] = h2 >> 8, hash[11] = h2;
    hash[12] = h3 >> 24, hash[13] = h3 >> 16, hash[14] = h3 >> 8, hash[15] = h3;
    hash[16] = h4 >> 24, hash[17] = h4 >> 16, hash[18] = h4 >> 8, hash[19] = h4;
}


int main() {

    uint8_t hash[20];
        
    unsigned char* buffer = new unsigned char[1000000];
    memset(buffer, 'a', 1000000);

    sha1(buffer, 1000000, (char*)hash);

    for (int i = 0; i < 20; ++i)
        printf("%02x", int(hash[i]) & 0xff);
    printf("\n");

}
