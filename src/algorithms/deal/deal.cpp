// src/algorithms/deal/deal.cpp

#include "../../../include/crypto/algorithms/deal/deal.hpp"
#include "../../../include/crypto/core/utils.hpp"
#include <cstring>

namespace crypto {

DEAL::DEAL(size_t keySize) : keySize_(keySize), roundCiphers_(NUM_ROUNDS) {
    if (keySize != 16 && keySize != 24 && keySize != 32) {
        throw InvalidKeyException("DEAL key must be 16, 24, or 32 bytes");
    }
}

void DEAL::setKey(const Key& key) {
    if (!isValidKey(key)) {
        throw InvalidKeyException("Invalid DEAL key size");
    }
    
    keySize_ = key.size();
    keySchedule(key.bytes(), key.size());
}

void DEAL::keySchedule(const Byte* key, size_t keyLength) {
    generateSubkeys(key, keyLength);
    
    for (size_t i = 0; i < NUM_ROUNDS; ++i) {
        Key desKey(ByteArray(subkeys_[i].begin(), subkeys_[i].end()));
        roundCiphers_[i].setKey(desKey);
    }
}

void DEAL::generateSubkeys(const Byte* key, size_t keyLength) {
    size_t halfKey = keyLength / 2;
    for (size_t i = 0; i <= NUM_ROUNDS && i * 8 < halfKey; ++i) {
        std::memcpy(subkeys_[i].data(), key + (i * 8), 8);
    }
    
    for (size_t i = halfKey / 8; i <= NUM_ROUNDS; ++i) {
        size_t offset = (i * 8) % halfKey;
        std::memcpy(subkeys_[i].data(), key + offset, 8);
        
        for (size_t j = 0; j < 8; ++j) {
            subkeys_[i][j] ^= static_cast<Byte>(i * 0x11 + j * 0x17);
        }
    }
}

Block128 DEAL::feistelNetwork(const Block128& block, bool encrypt) {
    Block128 result = block;
    
    Block64 left, right;
    std::memcpy(left.data(), result.data(), 8);
    std::memcpy(right.data(), result.data() + 8, 8);
    
    if (encrypt) {
        for (size_t round = 0; round < NUM_ROUNDS; ++round) {
            Block64 newRight;

            roundCiphers_[round].encryptBlock(right.data(), newRight.data());
            
            utils::xorBlocksInPlace(newRight.data(), left.data(), 8);
            
            left = right;
            right = newRight;
        }
    } else {
        for (size_t round = NUM_ROUNDS; round > 0; --round) {
            Block64 newLeft;
            
            roundCiphers_[round - 1].encryptBlock(left.data(), newLeft.data());
            
            utils::xorBlocksInPlace(newLeft.data(), right.data(), 8);
            
            right = left;
            left = newLeft;
        }
    }
    
    std::memcpy(result.data(), left.data(), 8);
    std::memcpy(result.data() + 8, right.data(), 8);
    
    return result;
}

void DEAL::encryptBlock(const Byte* input, Byte* output) {
    Block128 block;
    std::memcpy(block.data(), input, BLOCK_SIZE);
    
    Block128 encrypted = feistelNetwork(block, true);
    std::memcpy(output, encrypted.data(), BLOCK_SIZE);
}

void DEAL::decryptBlock(const Byte* input, Byte* output) {
    Block128 block;
    std::memcpy(block.data(), input, BLOCK_SIZE);
    
    Block128 decrypted = feistelNetwork(block, false);
    std::memcpy(output, decrypted.data(), BLOCK_SIZE);
}

}