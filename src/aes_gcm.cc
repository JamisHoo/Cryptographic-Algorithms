/******************************************************************************
 *  Copyright (c) 2015 Jamis Hoo
 *  Distributed under the MIT license 
 *  (See accompanying file LICENSE or copy at http://opensource.org/licenses/MIT)
 *  
 *  Project: 
 *  Filename: aes_gcm.cc 
 *  Version: 1.0
 *  Author: Jamis Hoo
 *  E-mail: hoojamis@gmail.com
 *  Date: May 17, 2015
 *  Time: 16:25:47
 *  Description: AES (128 bit) GCM
 *               block size 16 bytes, PKCS7 padding
 *               IV: 12 bytes (explicitly given) concatenate with counter (4 bytes)
 *               range of counter is [1, UINT_MAX]
 *****************************************************************************/
#include <cstdio>
#include <iostream>
#include <fstream>
#include <cinttypes>
#include <vector>
#include <cassert>

inline uint8_t gmult(uint8_t a, uint8_t b) {
    uint8_t p = 0, hbs = 0;

    for (size_t i = 0; i < 8; i++) {
        if (b & 1) 
            p ^= a;

        hbs = a & 0x80;
        a <<= 1;
        if (hbs) a ^= 0x1b; // 0000 0001 0001 1011    
        b >>= 1;
    }

    return (uint8_t)p;
}

constexpr uint8_t SubBytes[256] = {
   0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
   0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
   0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
   0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
   0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
   0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
   0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
   0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
   0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
   0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
   0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
   0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
   0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
   0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
   0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
   0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};

// key: initial key: 16 bytes
// keys : 44 * 4 bytes
void keyExpansion(const uint8_t key[], uint8_t keys[]) {
    constexpr uint8_t RCON[10][4] = {
        { 0x01, 0x00, 0x00, 0x00 },
        { 0x02, 0x00, 0x00, 0x00 },
        { 0x04, 0x00, 0x00, 0x00 },
        { 0x08, 0x00, 0x00, 0x00 },
        { 0x10, 0x00, 0x00, 0x00 },
        { 0x20, 0x00, 0x00, 0x00 },
        { 0x40, 0x00, 0x00, 0x00 },
        { 0x80, 0x00, 0x00, 0x00 },
        { 0x1b, 0x00, 0x00, 0x00 },
        { 0x36, 0x00, 0x00, 0x00 }
    };


    memcpy(keys, key, 4 * 4);

    for (size_t i = 4; i < 44; ++i) {
        uint8_t tmp[4] = { keys[4 * (i - 1) + 0], keys[4 * (i - 1) + 1],
                           keys[4 * (i - 1) + 2], keys[4 * (i - 1) + 3] };
        if (i % 4 == 0) {
            // rotate left one byte
            uint8_t temp = tmp[0];
            tmp[0] = tmp[1], tmp[1] = tmp[2], tmp[2] = tmp[3], tmp[3] = temp;
            // SubBytes
            tmp[0] = SubBytes[tmp[0]];
            tmp[1] = SubBytes[tmp[1]];
            tmp[2] = SubBytes[tmp[2]];
            tmp[3] = SubBytes[tmp[3]];
            // XOR round constants
            tmp[0] ^= RCON[i / 4 - 1][0], tmp[1] ^= RCON[i / 4 - 1][1], 
            tmp[2] ^= RCON[i / 4 - 1][2], tmp[3] ^= RCON[i / 4 - 1][3];
        }
        keys[4 * i + 0] = tmp[0], keys[4 * i + 1] = tmp[1],
        keys[4 * i + 2] = tmp[2], keys[4 * i + 3] = tmp[3];
        keys[4 * i + 0] ^= keys[4 * (i - 4) + 0], 
        keys[4 * i + 1] ^= keys[4 * (i - 4) + 1],
        keys[4 * i + 2] ^= keys[4 * (i - 4) + 2],
        keys[4 * i + 3] ^= keys[4 * (i - 4) + 3];
    }
}


inline void subBytes(uint8_t state[]) {
    for (size_t i = 0; i < 16; ++i)
        state[i] = SubBytes[state[i]];
}

inline void shiftRows(uint8_t state[]) {
    uint8_t tmp = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = tmp;

    tmp = state[2];
    state[2] = state[10];
    state[10] = tmp;
    tmp = state[6];
    state[6] = state[14];
    state[14] = tmp;
    
    tmp = state[3];
    state[3] = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = tmp;
}

inline void mixColumns(uint8_t state[]) {
    uint8_t tmp[4];
    for (size_t i = 0; i < 4; ++i) {
        tmp[0] = gmult(2, state[4 * i + 0]) ^ 
                 gmult(3, state[4 * i + 1]) ^
                 gmult(1, state[4 * i + 2]) ^ 
                 gmult(1, state[4 * i + 3]);
        tmp[1] = gmult(1, state[4 * i + 0]) ^
                 gmult(2, state[4 * i + 1]) ^
                 gmult(3, state[4 * i + 2]) ^
                 gmult(1, state[4 * i + 3]);
        tmp[2] = gmult(1, state[4 * i + 0]) ^
                 gmult(1, state[4 * i + 1]) ^
                 gmult(2, state[4 * i + 2]) ^
                 gmult(3, state[4 * i + 3]);
        tmp[3] = gmult(3, state[4 * i + 0]) ^
                 gmult(1, state[4 * i + 1]) ^
                 gmult(1, state[4 * i + 2]) ^
                 gmult(2, state[4 * i + 3]);
        state[4 * i + 0] = tmp[0], state[4 * i + 1] = tmp[1],
        state[4 * i + 2] = tmp[2], state[4 * i + 3] = tmp[3];
    }
}

inline void addRoundKey(uint8_t state[], const uint8_t word[]) {
    for (size_t i = 0; i < 16; ++i) 
        state[i] ^= word[i];
}

// in: 16 bytes
// out: 16 bytes
// key: 44 * 4 bytes
void aesIteration(const uint8_t in[], uint8_t out[], const uint8_t key[]) {
    uint8_t* state = out;
    memcpy(state, in, 16);
    
    // add round key
    addRoundKey(state, key);

    for (size_t round = 0; round < 9; ++round) {
        subBytes(state);
        shiftRows(state);
        mixColumns(state);
        addRoundKey(state, key + 16 * round + 16);
    }
    subBytes(state);
    shiftRows(state);
    addRoundKey(state, key + 16 * 10);
}

// X: 16 bytes
// Y: 16 bytes
// out: 16 bytes
void galois_multiply(const uint8_t X[], const uint8_t Y[], uint8_t out[]) {
    uint8_t V[16];
    memcpy(V, Y, 16);
    uint8_t Z[16] = { 0 };

    for (size_t i = 0; i < 16; ++i) {
        for (size_t j = 0; j < 8; ++j) {
            if (X[i] & 1 << (7 - j))
                for (size_t k = 0; k < 16; ++k) Z[k] ^= V[k];

            if (V[15] & 1) {
                for (size_t k = 0; k < 16; ++k) {
                    if (k && V[15 - k] & 1)
                        V[16 - k] |= 0x80;
                    V[15 - k] >>= 1;
                }
                
                V[0] ^= 0xe1;
            } else {
                for (size_t k = 0; k < 16; ++k) {
                    if (k && V[15 - k] & 1)
                        V[16 - k] |= 0x80;
                    V[15 - k] >>= 1;
                }
            }
        }
    }
    
    memcpy(out, Z, 16);
}

// in: len bytes
// hash_key: 16 bytes
// out: ??? bytes
void gHash(const uint8_t in[], const size_t len, const uint8_t hash_key[], uint8_t out[]) {
    memset(out, 0x00, 16);
    for (size_t i = 0; i < len / 16; ++i) {
        uint8_t tmp[16];
        for (size_t j = 0; j < 16; ++j)
            tmp[j] = out[j] ^ in[i * 16 + j];
        galois_multiply(tmp, hash_key, out);
    }
}

// plain: plain_len bytes
// key: 16 bytes
// IV: 12 bytes
// add: add_len bytes
// tag: 16 bytes
void aes_gcm(const void* plain, const size_t plain_len, 
            const void* key, const void* IV,
            const void* add, const size_t add_len, 
            void* cipher, void* tag) {
    const uint8_t* plain_text = (const uint8_t*)(plain);
    const uint8_t* key_ = (const uint8_t*)(key);
    const uint8_t* IV_ = (const uint8_t*)(IV);
    uint8_t* cipher_text = (uint8_t*)(cipher);
    uint8_t* tag_ = (uint8_t*)(tag);

    uint8_t keys[44 * 4];
    keyExpansion((uint8_t*)(key), keys);

    uint8_t counter[16] = { IV_[ 0], IV_[ 1], IV_[ 2], IV_[ 3],
                            IV_[ 4], IV_[ 5], IV_[ 6], IV_[ 7],
                            IV_[ 8], IV_[ 9], IV_[10], IV_[11],
                                  0,       0,       0,       1 };
    // counter mode AES
    {
        uint8_t CB[16];
        uint8_t encrypt_CB[16];
        // why initialize to 1?
        uint32_t ctr = 1;
        memcpy(CB, counter, 16);

        for (size_t i = 0; i < plain_len / 16; ++i) {
            ++ctr;
            if (ctr == 0) ctr = 1;
            CB[12] = ctr >> 24;
            CB[13] = ctr >> 16;
            CB[14] = ctr >>  8;
            CB[15] = ctr;

            aesIteration(CB, encrypt_CB, keys);

            for (size_t j = 0; j < 16; ++j)
                cipher_text[i * 16 + j] = encrypt_CB[j] ^ plain_text[i * 16 + j];
        }
    }

    uint8_t* add_cipher = new uint8_t[add_len + plain_len + 16];
    memcpy(add_cipher, add, add_len);
    memcpy(add_cipher + add_len, cipher_text, plain_len);
    uint64_t len_in_bit = add_len * 8;
    add_cipher[add_len + plain_len + 0] = len_in_bit >> 56;
    add_cipher[add_len + plain_len + 1] = len_in_bit >> 48;
    add_cipher[add_len + plain_len + 2] = len_in_bit >> 40;
    add_cipher[add_len + plain_len + 3] = len_in_bit >> 32;
    add_cipher[add_len + plain_len + 4] = len_in_bit >> 24;
    add_cipher[add_len + plain_len + 5] = len_in_bit >> 16;
    add_cipher[add_len + plain_len + 6] = len_in_bit >>  8;
    add_cipher[add_len + plain_len + 7] = len_in_bit >>  0;
    len_in_bit = plain_len * 8;
    add_cipher[add_len + plain_len +  8] = len_in_bit >> 56;
    add_cipher[add_len + plain_len +  9] = len_in_bit >> 48;
    add_cipher[add_len + plain_len + 10] = len_in_bit >> 40;
    add_cipher[add_len + plain_len + 11] = len_in_bit >> 32;
    add_cipher[add_len + plain_len + 12] = len_in_bit >> 24;
    add_cipher[add_len + plain_len + 13] = len_in_bit >> 16;
    add_cipher[add_len + plain_len + 14] = len_in_bit >>  8;
    add_cipher[add_len + plain_len + 15] = len_in_bit >>  0;

 
    uint8_t zero_data[16] = { 0 };
    uint8_t zero_data_cipher[16];
    aesIteration(zero_data, zero_data_cipher, keys);

    uint8_t Y[16];
    gHash(add_cipher, add_len + plain_len + 16, zero_data_cipher, Y);

    uint8_t en_counter[16];
    aesIteration(counter, en_counter, keys);

    for (size_t i = 0; i < 16; ++i)
        tag_[i] = en_counter[i] ^ Y[i];
}
            

int main(int argc, char** argv) {
    {
        /*
        const unsigned char key[16]={0x98,0xff,0xf6,0x7e,0x64,0xe4,0x6b,0xe5,0xee,0x2e,0x05,0xcc,0x9a,0xf6,0xd0,0x12};
        const unsigned char IV[12] ={0x2d,0xfb,0x42,0x9a,0x48,0x69,0x7c,0x34,0x00,0x6d,0xa8,0x86};

        const unsigned char plaintext[3*16]={0x29,0xb9,0x1b,0x4a,0x68,0xa9,0x9f,0x97,0xc4,0x1c,0x75,0x08,0xf1,0x7a,0x5c,0x7a,
                           0x7a,0xfc,0x9e,0x1a,0xca,0x83,0xe1,0x29,0xb0,0x85,0xbd,0x63,0x7f,0xf6,0x7c,0x01,
                           0x29,0xb9,0x1b,0x4a,0x68,0xa9,0x9f,0x97,0xc4,0x1c,0x75,0x08,0xf1,0x7a,0x5c,0x7a};

        const unsigned char add_data[3*16]={0xa0,0xca,0x58,0x61,0xc0,0x22,0x6c,0x5b,0x5a,0x65,0x14,0xc8,0x2b,0x77,0x81,0x5a,
                          0x9e,0x0e,0xb3,0x59,0xd0,0xd4,0x6d,0x03,0x33,0xc3,0xf2,0xba,0xe1,0x4d,0xa0,0xc4,
                          0x03,0x30,0xc0,0x02,0x16,0xb4,0xaa,0x64,0xb7,0xc1,0xed,0xb8,0x71,0xc3,0x28,0xf6};
        unsigned char ciphertext[4096];
        unsigned char tag[4096];

        aes_gcm(plaintext, 48, key, IV, add_data, 48, ciphertext, tag);

        for (size_t i = 0; i < 16; ++i) printf("%02x ", tag[i]); printf("\n");
				 
        //tag
        //{0x9e,0x27,0xe2,0x10,0xd6,0xe1,0xef,0x0f,0x18,0xde,0x98,0xf4,0xc3,0xd0,0xf9,0x68},
        */
    }
    if (argc == 1) return 0;

    std::ifstream fin(argv[1]);

    fin.seekg(0, std::ios::end);
    std::string buffer;
    size_t len = fin.tellg();
    fin.seekg(0, std::ios::beg);

    uint8_t pad = 0;
    if (len % 16) {
        pad = 16 - len % 16;
        len = len / 16 * 16 + 16;
    }

    buffer.reserve(len);

    buffer.assign((std::istreambuf_iterator<char>(fin)),
                   std::istreambuf_iterator<char>());
    // PKCS7 padding
    for (size_t i = 0; i < pad; ++i)
        buffer += pad;

    assert(buffer.length() == len);

    fin.close();

    // 128 bit key size
    unsigned char key[16] = { 0 };

    if (argc == 3) {
        fin.open(argv[2]);
        fin.seekg(0, std::ios::beg);
        char buffer[3] = { 0 };
        for (size_t i = 0; i < 16; ++i) {
            fin.read(buffer, 2);
            key[i] = std::stoi(buffer, 0, 16);
        }
        fin.close();
    }
    
    unsigned char IV[12] = { 0 };
    unsigned char add_data[0];
    unsigned char tag[16];

    std::vector<char> cipher(buffer.length(), 0);
    aes_gcm(buffer.data(), buffer.length(), key, IV, add_data, 0, &cipher[0], tag);

    for (size_t i = 0; i < buffer.length(); ++i)
        printf("%02x", int(cipher[i]) & 0xff);
    printf("\n\n");

    for (size_t i = 0; i < 16; ++i)
        printf("%02x", tag[i]);
    printf("\n");
    
}

