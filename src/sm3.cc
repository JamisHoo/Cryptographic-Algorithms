/******************************************************************************
 *  Copyright (c) 2015 Jamis Hoo
 *  Distributed under the MIT license 
 *  (See accompanying file LICENSE or copy at http://opensource.org/licenses/MIT)
 *  
 *  Project: 
 *  Filename: sm3.cc 
 *  Version: 1.0
 *  Author: Jamis Hoo
 *  E-mail: hoojamis@gmail.com
 *  Date: May 11, 2015
 *  Time: 22:13:27
 *  Description: SM3
 *****************************************************************************/
#include <cstring>
#include <cinttypes>
#include <iostream>
#include <fstream>
#include <streambuf>

void sm3_iteration(const uint8_t* data, uint32_t hi[]) {
    // rotate function
    auto left_rotate = [](uint32_t x, const size_t i)->uint32_t {
        return x << i | x >> (sizeof(uint32_t) * 8 - i);
    };

    uint32_t T[64];
    for (size_t i =  0; i < 16; ++i) T[i] = 0x79CC4519;
    for (size_t i = 16; i < 64; ++i) T[i] = 0x7A879D8A; 

    uint32_t W[68];
    for (size_t i =  0; i < 16; ++i)
        W[i] = data[4 * i + 0] << 24 | data[4 * i + 1] << 16 |
               data[4 * i + 2] <<  8 | data[4 * i + 3] <<  0;
    for (size_t i = 16; i < 68; ++i) {
        uint32_t tmp = W[i - 16] ^ W[i - 9] ^ left_rotate(W[i - 3], 15);
        tmp = tmp ^ left_rotate(tmp, 15) ^ left_rotate(tmp, 23);
        W[i] = tmp ^ left_rotate(W[i - 13], 7) ^ W[i - 6];
    }

    
    uint32_t W1[64];
    for (size_t i = 0; i < 64; ++i)
        W1[i] = W[i] ^ W[i + 4];

    uint32_t A = hi[0], B = hi[1], C = hi[2], D = hi[3], 
             E = hi[4], F = hi[5], G = hi[6], H = hi[7];

    for (size_t i = 0; i < 16; ++i) {
        uint32_t SS1 = left_rotate(left_rotate(A, 12) + E + left_rotate(T[i], i), 7);
        uint32_t SS2 = SS1 ^ left_rotate(A, 12);
        uint32_t TT1 = (A ^ B ^ C) + D + SS2 + W1[i];
        uint32_t TT2 = (E ^ F ^ G) + H + SS1 + W[i];
        D = C;
        C = left_rotate(B, 9);
        B = A;
        A = TT1;
        H = G;
        G = left_rotate(F, 19);
        F = E;
        E = TT2 ^ left_rotate(TT2, 9) ^ left_rotate(TT2, 17);
    }

    for (size_t i = 16; i < 64; ++i) {
        uint32_t SS1 = left_rotate(left_rotate(A, 12) + E + left_rotate(T[i], i), 7);
        uint32_t SS2 = SS1 ^ left_rotate(A, 12);
        uint32_t TT1 = ((A & B) | (B & C) | (A & C)) + D + SS2 + W1[i];
        uint32_t TT2 = ((E & F) | (~E & G)) + H + SS1 + W[i];
        D = C;
        C = left_rotate(B, 9);
        B = A;
        A = TT1;
        H = G;
        G = left_rotate(F, 19);
        F = E;
        E = TT2 ^ left_rotate(TT2, 9) ^ left_rotate(TT2, 17);
    }

    hi[0] ^= A, hi[1] ^= B, hi[2] ^= C, hi[3] ^= D,
    hi[4] ^= E, hi[5] ^= F, hi[6] ^= G, hi[7] ^= H;
}

// len: in bytes
// hash: at least 32 bytes available
void sm3(const void* data, size_t len, char* hash) {
    uint8_t* data_ = (uint8_t*)data;
    constexpr size_t block_size = 64;

    uint32_t h[8] = { 0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600, 
                      0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E };

    size_t ml = len * 8;

    for (size_t i = 0; i < len / block_size; ++i)
        sm3_iteration(data_ + i * block_size, h);

    uint8_t buffer[block_size];
    
    memcpy(buffer, data_ + len / block_size * block_size, len % block_size);
    len %= block_size;

    // append bit '1'
    buffer[len++] = 0x80;

    if (len % block_size == 0) {
        sm3_iteration(buffer, h);
        len = 0;
    }
    
    // append until the resulting message length (in bits) is congruent to 448 (mod 512)
    while (len % block_size != 56) {
        buffer[len++] = 0x00;
        if (len % block_size == 0) {
            sm3_iteration(buffer, h);
            len = 0;
        }
    }

    // append length
    buffer[len++] = ml >> 56, buffer[len++] = ml >> 48, 
    buffer[len++] = ml >> 40, buffer[len++] = ml >> 32,
    buffer[len++] = ml >> 24, buffer[len++] = ml >> 16,
    buffer[len++] = ml >>  8, buffer[len++] = ml;

    sm3_iteration(buffer, h);
    
    for (size_t i = 0; i < 32; i += 4)
        hash[i] = h[i / 4] >> 24, hash[i + 1] = h[i / 4] >> 16,
        hash[i + 2] = h[i / 4] >> 8, hash[i + 3] = h[i / 4];
}



int main(int argc, char** argv) {
    uint8_t hash[32];

    if (argc == 1) return 0;

    std::ifstream fin(argv[1]);

    fin.seekg(0, std::ios::end);
    std::string buffer;
    buffer.reserve(fin.tellg());
    fin.seekg(0, std::ios::beg);

    buffer.assign((std::istreambuf_iterator<char>(fin)),
                   std::istreambuf_iterator<char>());

    
    sm3(buffer.data(), buffer.length(), (char*)hash);

    for (int i = 0; i < 32; ++i)
        printf("%02x", int(hash[i]) & 0xff);
    printf("\n");
    
}
