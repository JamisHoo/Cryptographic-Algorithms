/******************************************************************************
 *  Copyright (c) 2015 Jamis Hoo
 *  Distributed under the MIT license 
 *  (See accompanying file LICENSE or copy at http://opensource.org/licenses/MIT)
 *  
 *  Project: 
 *  Filename: sha2_512.cc 
 *  Version: 1.0
 *  Author: Jamis Hoo
 *  E-mail: hoojamis@gmail.com
 *  Date: May 11, 2015
 *  Time: 22:13:27
 *  Description: SHA-2 (512 bit)
 *****************************************************************************/
#include <cstring>
#include <cinttypes>
#include <iostream>
#include <fstream>
#include <streambuf>

void sha2_iteration(const uint8_t* data, uint64_t hi[]) {
    // rotate function
    auto right_rotate = [](uint64_t x, const size_t i)->uint64_t {
        return x >> i | x << (sizeof(uint64_t) * 8 - i);
    };

    /*
    constexpr uint64_t k[64] = { 
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        */
    constexpr uint64_t k[80] = { 
        0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538, 
        0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe, 
        0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 
        0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 
        0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab, 
        0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725, 
        0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 
        0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b, 
        0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218, 
        0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 
        0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 
        0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec, 
        0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c, 
        0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6, 
        0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 
        0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
    };

    // extend 16 64-bit words to 80 64-bit words
    uint64_t word[80];
    for (size_t j = 0; j < 16; ++j)
        word[j] = uint64_t(data[8 * j + 0]) << 56 | uint64_t(data[8 * j + 1]) << 48 |
                  uint64_t(data[8 * j + 2]) << 40 | uint64_t(data[8 * j + 3]) << 32 |
                  uint64_t(data[8 * j + 4]) << 24 | uint64_t(data[8 * j + 5]) << 16 |
                  uint64_t(data[8 * j + 6]) <<  8 | uint64_t(data[8 * j + 7]) <<  0;

    for (size_t j = 16; j < 80; ++j) {
        /*
        uint32_t s0 = right_rotate(word[j - 15],  7) ^
                      right_rotate(word[j - 15], 18) ^
                      word[j - 15] >> 3;
        uint32_t s1 = right_rotate(word[j - 2], 17) ^
                      right_rotate(word[j - 2], 19) ^
                      word[j - 2] >> 10;
        */
        uint64_t s0 = right_rotate(word[j - 15], 1) ^
                      right_rotate(word[j - 15], 8) ^
                      word[j - 15] >> 7;
        uint64_t s1 = right_rotate(word[j - 2], 19) ^
                      right_rotate(word[j - 2], 61) ^
                      word[j - 2] >> 6;
        word[j] = word[j - 16] + s0 + word[j - 7] + s1;
    }

    uint64_t a = hi[0], b = hi[1], c = hi[2], d = hi[3], 
             e = hi[4], f = hi[5], g = hi[6], h = hi[7];
            
    
    // main loop
    for (size_t i = 0; i < 80; ++i) {
        /*
        uint32_t S1 = right_rotate(e, 6) ^ 
                      right_rotate(e, 11) ^
                      right_rotate(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t tmp1 = h + S1 + ch + k[i] + word[i];
        uint32_t S0 = right_rotate(a, 2) ^
                      right_rotate(a, 13) ^ 
                      right_rotate(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t tmp2 = S0 + maj;
        */

        uint64_t S1 = right_rotate(e, 14) ^ 
                      right_rotate(e, 18) ^
                      right_rotate(e, 41);
        uint64_t ch = (e & f) ^ (~e & g);
        uint64_t tmp1 = h + S1 + ch + k[i] + word[i];
        uint64_t S0 = right_rotate(a, 28) ^
                      right_rotate(a, 34) ^
                      right_rotate(a, 39);
        uint64_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint64_t tmp2 = S0 + maj;


        h = g, g = f, f = e, e = d + tmp1, d = c, c = b, b = a, a = tmp1 + tmp2;
    }

    hi[0] += a, hi[1] += b, hi[2] += c, hi[3] += d, 
    hi[4] += e, hi[5] += f, hi[6] += g, hi[7] += h;
}

// len: in bytes
// hash: at least 64 bytes available
void sha2(const void* data, size_t len, char* hash) {
    uint8_t* data_ = (uint8_t*)data;
    constexpr size_t block_size = 128;

    // uint32_t h[8] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };
    uint64_t h[8] = { 0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 
                      0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1, 
                      0x510e527fade682d1, 0x9b05688c2b3e6c1f, 
                      0x1f83d9abfb41bd6b, 0x5be0cd19137e2179 };

    size_t ml = len * 8;

    for (size_t i = 0; i < len / block_size; ++i)
        sha2_iteration(data_ + i * block_size, h);

    uint8_t buffer[block_size];
    
    memcpy(buffer, data_ + len / block_size * block_size, len % block_size);
    len %= block_size;

    // append bit '1'
    buffer[len++] = 0x80;

    if (len % block_size == 0) {
        sha2_iteration(buffer, h);
        len = 0;
    }
    
    // append until the resulting message length (in bits) is congruent to 448 (mod 512)
    while (len % block_size != block_size - 16) {
        buffer[len++] = 0x00;
        if (len % block_size == 0) {
            sha2_iteration(buffer, h);
            len = 0;
        }
    }

    // append length

    while (len % block_size) {
        buffer[len] = ml >> (120 - (len - (block_size - 16)) * 8);
        ++len;
    }

    // Code below may get a better performance on pipeline CPU than code above
    // because it has no branch instruction
    // But size_t is 64 bits long for now, so code below will generate compiler warnings.
    // When size_t is 128 bits long, replace code above with that below.

    // Plus, anybody knows how to concisely switch these tow pieces of code at 
    // compiling time please tells me. Thanks.

    /*
    buffer[len++] = ml >> 120, buffer[len++] = ml >> 112, 
    buffer[len++] = ml >> 104, buffer[len++] = ml >>  96, 
    buffer[len++] = ml >>  88, buffer[len++] = ml >>  80, 
    buffer[len++] = ml >>  72, buffer[len++] = ml >>  64, 

    buffer[len++] = ml >>  56, buffer[len++] = ml >>  48, 
    buffer[len++] = ml >>  40, buffer[len++] = ml >>  32,
    buffer[len++] = ml >>  24, buffer[len++] = ml >>  16,
    buffer[len++] = ml >>   8, buffer[len++] = ml;
    */

    sha2_iteration(buffer, h);
    
    /*
    for (size_t i = 0; i < 64; i += 8)
        hash[i] = h[i / 4] >> 24, hash[i + 1] = h[i / 4] >> 16,
        hash[i + 2] = h[i / 4] >> 8, hash[i + 3] = h[i / 4];
    */
    for (size_t i = 0; i < 64; i += 8)
        hash[i + 0] = h[i / 8] >> 56, hash[i + 1] = h[i / 8] >> 48,
        hash[i + 2] = h[i / 8] >> 40, hash[i + 3] = h[i / 8] >> 32,
        hash[i + 4] = h[i / 8] >> 24, hash[i + 5] = h[i / 8] >> 16,
        hash[i + 6] = h[i / 8] >>  8, hash[i + 7] = h[i / 8] >>  0;
}



int main(int argc, char** argv) {
    uint8_t hash[64];

    if (argc == 1) return 0;

    std::ifstream fin(argv[1]);

    fin.seekg(0, std::ios::end);
    std::string buffer;
    buffer.reserve(fin.tellg());
    fin.seekg(0, std::ios::beg);

    buffer.assign((std::istreambuf_iterator<char>(fin)),
                   std::istreambuf_iterator<char>());

    
    sha2(buffer.data(), buffer.length(), (char*)hash);

    for (int i = 0; i < 64; ++i)
        printf("%02x", int(hash[i]) & 0xff);
    printf("\n");
    
}
