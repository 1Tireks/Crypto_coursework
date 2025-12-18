// src/modes/ctr.cpp

#include "../../include/crypto/modes/ctr.hpp"
#include "../../include/crypto/core/utils.hpp"
#include "../../include/crypto/math/random.hpp"
#include <stdexcept>
#include <cstring>
#include <limits>

namespace crypto {

CTRMode::CTRMode(std::shared_ptr<IBlockCipher> cipher, 
                 std::unique_ptr<IPadding> padding)
    : cipher_(std::move(cipher))
    , padding_(std::move(padding))
    , counter_(0)
    , usePadding_(padding_ != nullptr) {
    
    if (!cipher_) {
        throw CryptoException("Cipher cannot be null");
    }
    
    blockSize_ = cipher_->blockSize();
    generateRandomIV();
}

void CTRMode::setCipher(std::shared_ptr<IBlockCipher> cipher) {
    if (!cipher) {
        throw CryptoException("Cipher cannot be null");
    }
    cipher_ = std::move(cipher);
    blockSize_ = cipher_->blockSize();
    generateRandomIV();
}

void CTRMode::setPadding(std::unique_ptr<IPadding> padding) {
    padding_ = std::move(padding);
    usePadding_ = (padding_ != nullptr);
}

void CTRMode::setIV(const ByteArray& iv) {
    if (iv.size() > blockSize_) {
        throw CryptoException("IV/nonce too large for block size");
    }
    
    nonce_.resize(blockSize_);
    std::fill(nonce_.begin(), nonce_.end(), 0);
    std::copy(iv.begin(), iv.end(), nonce_.begin());
    counter_ = 0;
}

ByteArray CTRMode::getIV() const {
    return nonce_;
}

void CTRMode::generateRandomIV() {
    size_t nonceSize = blockSize_ / 2;
    nonce_ = math::randomBytes(nonceSize);
    nonce_.resize(blockSize_, 0); // Дополняем нулями для счетчика
    counter_ = 0;
}

void CTRMode::incrementCounter() {
    ++counter_;
    if (counter_ == 0) {
        for (size_t i = blockSize_ - 1; i >= blockSize_ / 2; --i) {
            if (++nonce_[i] != 0) break;
        }
    }
}

void CTRMode::getCounterBlock(Byte* block) {
    std::memcpy(block, nonce_.data(), blockSize_);
    
    uint64_t tempCounter = counter_;
    for (size_t i = 0; i < sizeof(uint64_t) && i < blockSize_; ++i) {
        block[blockSize_ - 1 - i] |= (tempCounter & 0xFF);
        tempCounter >>= 8;
    }
}

ByteArray CTRMode::encrypt(const ByteArray& plaintext) {
    ByteArray data = plaintext;
    
    if (usePadding_) {
        data = padding_->pad(data, blockSize_);
    }
    
    ByteArray ciphertext(data.size());
    encrypt(data.data(), ciphertext.data(), data.size());
    return ciphertext;
}

ByteArray CTRMode::decrypt(const ByteArray& ciphertext) {
    ByteArray plaintext(ciphertext.size());
    decrypt(ciphertext.data(), plaintext.data(), ciphertext.size());
    
    if (usePadding_) {
        plaintext = padding_->unpad(plaintext);
    }
    
    return plaintext;
}

void CTRMode::encrypt(const Byte* input, Byte* output, size_t length) {
    size_t processed = 0;
    
    while (processed < length) {
        ByteArray counterBlock(blockSize_);
        getCounterBlock(counterBlock.data());
        
        ByteArray keystream(blockSize_);
        cipher_->encryptBlock(counterBlock.data(), keystream.data());
        
        size_t toProcess = std::min(blockSize_, length - processed);
        
        for (size_t i = 0; i < toProcess; ++i) {
            output[processed + i] = input[processed + i] ^ keystream[i];
        }
        
        processed += toProcess;
        incrementCounter();
    }
}

void CTRMode::decrypt(const Byte* input, Byte* output, size_t length) {
    encrypt(input, output, length);
}

void CTRMode::reset() {
    counter_ = 0;
}

}