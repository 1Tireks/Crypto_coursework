// src/algorithms/des/des.cpp

#include "../../../include/crypto/algorithms/des/des.hpp"
#include "../../../include/crypto/core/utils.hpp"
#include "../../../include/crypto/core/endianness.hpp"
#include <cstring>

namespace crypto {

DES::DES() : roundKeys_{0} {}

void DES::setKey(const Key& key) {
    if (!isValidKey(key)) {
        throw InvalidKeyException("DES requires 8-byte key");
    }
    key_ = key.data;
    generateRoundKeys(key.bytes());
}

uint64_t DES::permute(const uint8_t* table, size_t tableSize, 
                     uint64_t input, size_t inputBits) {
    uint64_t result = 0;
    
    for (size_t i = 0; i < tableSize; ++i) {
        uint64_t bitPos = table[i] - 1;
        if (bitPos < inputBits) {
            uint64_t bit = (input >> (inputBits - 1 - bitPos)) & 1;
            result |= (bit << (tableSize - 1 - i));
        }
    }
    
    return result;
}

void DES::generateRoundKeys(const Byte* key) {
    uint64_t key64 = endianness::bytesToUint64BE(key);
    
    uint64_t permutedKey = permute(des::PC1_TABLE, 56, key64, 64);
    
    uint32_t left = static_cast<uint32_t>(permutedKey >> 28);
    uint32_t right = static_cast<uint32_t>(permutedKey & 0xFFFFFFF);
    
    for (int round = 0; round < NUM_ROUNDS; ++round) {
        left = utils::rotateLeft(left, des::SHIFT_SCHEDULE[round]) & 0xFFFFFFF;
        right = utils::rotateLeft(right, des::SHIFT_SCHEDULE[round]) & 0xFFFFFFF;
        
        uint64_t combined = (static_cast<uint64_t>(left) << 28) | right;
        roundKeys_[round] = permute(des::PC2_TABLE, 48, combined, 56);
    }
}

uint32_t DES::sBoxSubstitution(uint64_t input) {
    uint32_t output = 0;
    
    for (int i = 0; i < 8; ++i) {
        uint8_t bits = static_cast<uint8_t>((input >> (42 - i * 6)) & 0x3F);
        
        uint8_t row = ((bits & 0x20) >> 4) | (bits & 0x01);
        uint8_t col = (bits >> 1) & 0x0F;
        
        uint8_t sboxValue = des::S_BOXES[i][row][col];
        
        output = (output << 4) | sboxValue;
    }
    
    return output;
}

uint32_t DES::feistelFunction(uint32_t right, uint64_t roundKey) {
    uint64_t expanded = permute(des::E_TABLE, 48, right, 32);
    
    expanded ^= roundKey;
    
    uint32_t substituted = sBoxSubstitution(expanded);
    
    return static_cast<uint32_t>(permute(des::P_TABLE, 32, substituted, 32));
}

void DES::encryptBlock(const Byte* input, Byte* output) {
    uint64_t block = endianness::bytesToUint64BE(input);
    
    block = permute(des::IP_TABLE, 64, block, 64);
    
    uint32_t left = static_cast<uint32_t>(block >> 32);
    uint32_t right = static_cast<uint32_t>(block & 0xFFFFFFFF);
    
    for (int round = 0; round < NUM_ROUNDS; ++round) {
        uint32_t newLeft = right;
        uint32_t newRight = left ^ feistelFunction(right, roundKeys_[round]);
        
        left = newLeft;
        right = newRight;
    }
    
    block = (static_cast<uint64_t>(right) << 32) | left;
    
    block = permute(des::FP_TABLE, 64, block, 64);
    
    endianness::uint64ToBytesBE(block, output);
}

void DES::decryptBlock(const Byte* input, Byte* output) {
    uint64_t block = endianness::bytesToUint64BE(input);

    block = permute(des::IP_TABLE, 64, block, 64);

    uint32_t left = static_cast<uint32_t>(block >> 32);
    uint32_t right = static_cast<uint32_t>(block & 0xFFFFFFFF);

    for (int round = NUM_ROUNDS - 1; round >= 0; --round) {
        uint32_t newLeft = right;
        uint32_t newRight = left ^ feistelFunction(right, roundKeys_[round]);

        left = newLeft;
        right = newRight;
    }

    block = (static_cast<uint64_t>(right) << 32) | left;

    block = permute(des::FP_TABLE, 64, block, 64);

    endianness::uint64ToBytesBE(block, output);
}

}