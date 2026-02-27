#include "../../../include/crypto/algorithms/rijndael/rijndael.hpp"
#include "../../../include/crypto/algorithms/rijndael/aes_constants.hpp"
#include "../../../include/crypto/core/exceptions.hpp"
#include <cstring>

namespace crypto {
namespace rijndael {

Rijndael::Rijndael(KeySize keySize, BlockSize blockSize, uint16_t irreduciblePoly) 
    : keySize_(keySize), blockSize_(blockSize), blockBytes_(16), keyBytes_(static_cast<size_t>(keySize) / 8),
      galoisField_(irreduciblePoly) {
    if (keySize == KeySize::AES128) numRounds_ = 10;
    else if (keySize == KeySize::AES192) numRounds_ = 12;
    else numRounds_ = 14;
}

std::string Rijndael::name() const {
    return "Rijndael-" + std::to_string(static_cast<int>(keySize_));
}

size_t Rijndael::blockSize() const {
    return blockBytes_;
}

size_t Rijndael::keySize() const {
    return keyBytes_;
}

void Rijndael::setKey(const Key& key) {
    if (!isValidKey(key)) {
        throw InvalidKeyException("Invalid Rijndael key size");
    }
    key_ = key;
    keyExpansion(key.bytes());
}

bool Rijndael::isValidKey(const Key& key) const {
    return key.size() == keyBytes_;
}

void Rijndael::blockToState(const Byte* block) {
    for (size_t i = 0; i < 4; ++i) {
        for (size_t j = 0; j < 4; ++j) {
            state_[i + 4*j] = block[i + 4*j];
        }
    }
}

void Rijndael::stateToBlock(Byte* block) {
    for (size_t i = 0; i < 4; ++i) {
        for (size_t j = 0; j < 4; ++j) {
            block[i + 4*j] = state_[i + 4*j];
        }
    }
}

void Rijndael::subBytes() {
    for (size_t i = 0; i < STATE_SIZE; ++i) {
        state_[i] = S_BOX[state_[i]];
    }
}

void Rijndael::invSubBytes() {
    for (size_t i = 0; i < STATE_SIZE; ++i) {
        state_[i] = INV_S_BOX[state_[i]];
    }
}

void Rijndael::shiftRows() {
    uint8_t temp;
    
    temp = state_[1]; state_[1] = state_[5]; state_[5] = state_[9]; state_[9] = state_[13]; state_[13] = temp;
    
    temp = state_[2]; state_[2] = state_[10]; state_[10] = temp; temp = state_[6]; state_[6] = state_[14]; state_[14] = temp;
    
    temp = state_[3]; state_[3] = state_[15]; state_[15] = state_[11]; state_[11] = state_[7]; state_[7] = temp;
}

void Rijndael::invShiftRows() {
    uint8_t temp;
    
    temp = state_[13]; state_[13] = state_[9]; state_[9] = state_[5]; state_[5] = state_[1]; state_[1] = temp;
    
    temp = state_[2]; state_[2] = state_[10]; state_[10] = temp; temp = state_[6]; state_[6] = state_[14]; state_[14] = temp;
    
    temp = state_[3]; state_[3] = state_[7]; state_[7] = state_[11]; state_[11] = state_[15]; state_[15] = temp;
}

void Rijndael::mixColumns() {
    uint8_t temp[4];
    for (size_t c = 0; c < 4; ++c) {
        temp[0] = MULT_2[state_[4*c]] ^ MULT_3[state_[4*c+1]] ^ state_[4*c+2] ^ state_[4*c+3];
        temp[1] = state_[4*c] ^ MULT_2[state_[4*c+1]] ^ MULT_3[state_[4*c+2]] ^ state_[4*c+3];
        temp[2] = state_[4*c] ^ state_[4*c+1] ^ MULT_2[state_[4*c+2]] ^ MULT_3[state_[4*c+3]];
        temp[3] = MULT_3[state_[4*c]] ^ state_[4*c+1] ^ state_[4*c+2] ^ MULT_2[state_[4*c+3]];
        state_[4*c] = temp[0]; state_[4*c+1] = temp[1]; state_[4*c+2] = temp[2]; state_[4*c+3] = temp[3];
    }
}

void Rijndael::invMixColumns() {
    uint8_t temp[4];
    for (size_t c = 0; c < 4; ++c) {
        temp[0] = MULT_14[state_[4*c]] ^ MULT_11[state_[4*c+1]] ^ MULT_13[state_[4*c+2]] ^ MULT_9[state_[4*c+3]];
        temp[1] = MULT_9[state_[4*c]] ^ MULT_14[state_[4*c+1]] ^ MULT_11[state_[4*c+2]] ^ MULT_13[state_[4*c+3]];
        temp[2] = MULT_13[state_[4*c]] ^ MULT_9[state_[4*c+1]] ^ MULT_14[state_[4*c+2]] ^ MULT_11[state_[4*c+3]];
        temp[3] = MULT_11[state_[4*c]] ^ MULT_13[state_[4*c+1]] ^ MULT_9[state_[4*c+2]] ^ MULT_14[state_[4*c+3]];
        state_[4*c] = temp[0]; state_[4*c+1] = temp[1]; state_[4*c+2] = temp[2]; state_[4*c+3] = temp[3];
    }
}

void Rijndael::addRoundKey(size_t round) {
    for (size_t i = 0; i < 4; ++i) {
        uint32_t keyWord = roundKeys_[round * 4 + i];
        state_[4*i] ^= (keyWord >> 24) & 0xFF;
        state_[4*i+1] ^= (keyWord >> 16) & 0xFF;
        state_[4*i+2] ^= (keyWord >> 8) & 0xFF;
        state_[4*i+3] ^= keyWord & 0xFF;
    }
}

uint32_t Rijndael::subWord(uint32_t word) {
    return (S_BOX[(word >> 24) & 0xFF] << 24) |
           (S_BOX[(word >> 16) & 0xFF] << 16) |
           (S_BOX[(word >> 8) & 0xFF] << 8) |
           S_BOX[word & 0xFF];
}

uint32_t Rijndael::rotWord(uint32_t word) {
    return ((word << 8) | (word >> 24));
}

void Rijndael::keyExpansion(const Byte* key) {
    size_t nk = keyBytes_ / 4;
    size_t totalWords = (numRounds_ + 1) * 4;
    roundKeys_.resize(totalWords);
    
    for (size_t i = 0; i < nk; ++i) {
        roundKeys_[i] = (static_cast<uint32_t>(key[4*i]) << 24) |
                        (static_cast<uint32_t>(key[4*i+1]) << 16) |
                        (static_cast<uint32_t>(key[4*i+2]) << 8) |
                        static_cast<uint32_t>(key[4*i+3]);
    }
    
    for (size_t i = nk; i < totalWords; ++i) {
        uint32_t temp = roundKeys_[i-1];
        if (i % nk == 0) {
            temp = subWord(rotWord(temp)) ^ RCON[i/nk - 1];
        } else if (nk > 6 && i % nk == 4) {
            temp = subWord(temp);
        }
        roundKeys_[i] = roundKeys_[i-nk] ^ temp;
    }
}

void Rijndael::encryptBlock(const Byte* input, Byte* output) {
    blockToState(input);
    
    addRoundKey(0);
    
    for (size_t round = 1; round < numRounds_; ++round) {
        subBytes();
        shiftRows();
        mixColumns();
        addRoundKey(round);
    }
    
    subBytes();
    shiftRows();
    addRoundKey(numRounds_);
    
    stateToBlock(output);
}

void Rijndael::decryptBlock(const Byte* input, Byte* output) {
    blockToState(input);
    
    addRoundKey(numRounds_);
    
    for (size_t round = numRounds_ - 1; round > 0; --round) {
        invShiftRows();
        invSubBytes();
        addRoundKey(round);
        invMixColumns();
    }
    
    invShiftRows();
    invSubBytes();
    addRoundKey(0);
    
    stateToBlock(output);
}

}
}

