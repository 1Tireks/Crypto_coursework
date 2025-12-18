// src/modes/random_delta.cpp

#include "../../include/crypto/modes/random_delta.hpp"
#include "../../include/crypto/core/utils.hpp"
#include "../../include/crypto/math/random.hpp"
#include <stdexcept>
#include <cstring>

namespace crypto {

RandomDeltaMode::RandomDeltaMode(std::shared_ptr<IBlockCipher> cipher, 
                                 std::unique_ptr<IPadding> padding)
    : cipher_(std::move(cipher))
    , padding_(std::move(padding))
    , usePadding_(padding_ != nullptr) {
    
    if (!cipher_) {
        throw CryptoException("Cipher cannot be null");
    }
    
    blockSize_ = cipher_->blockSize();
    generateRandomIV();
    delta_.resize(blockSize_);
}

void RandomDeltaMode::setCipher(std::shared_ptr<IBlockCipher> cipher) {
    if (!cipher) {
        throw CryptoException("Cipher cannot be null");
    }
    cipher_ = std::move(cipher);
    blockSize_ = cipher_->blockSize();
    generateRandomIV();
    delta_.resize(blockSize_);
}

void RandomDeltaMode::setPadding(std::unique_ptr<IPadding> padding) {
    padding_ = std::move(padding);
    usePadding_ = (padding_ != nullptr);
}

void RandomDeltaMode::setIV(const ByteArray& iv) {
    if (iv.size() != blockSize_) {
        throw CryptoException("IV size must equal block size");
    }
    iv_ = iv;
}

ByteArray RandomDeltaMode::getIV() const {
    return iv_;
}

void RandomDeltaMode::generateRandomIV() {
    iv_ = math::randomBytes(blockSize_);
}

void RandomDeltaMode::generateDelta(size_t blockIndex) {
    for (size_t i = 0; i < blockSize_; ++i) {
        uint32_t seed = static_cast<uint32_t>(iv_[i % iv_.size()]) + 
                       static_cast<uint32_t>(blockIndex * 256 + i);
        seed = (seed * 1103515245 + 12345) & 0x7fffffff;
        delta_[i] = static_cast<Byte>(seed & 0xFF);
    }
}

ByteArray RandomDeltaMode::encrypt(const ByteArray& plaintext) {
    ByteArray data = plaintext;
    
    if (usePadding_) {
        data = padding_->pad(data, blockSize_);
    } else if (data.size() % blockSize_ != 0) {
        throw CryptoException("Data size must be multiple of block size when padding is disabled");
    }
    
    ByteArray ciphertext(data.size());
    encrypt(data.data(), ciphertext.data(), data.size());
    return ciphertext;
}

ByteArray RandomDeltaMode::decrypt(const ByteArray& ciphertext) {
    if (ciphertext.size() % blockSize_ != 0) {
        throw CryptoException("Ciphertext size must be multiple of block size");
    }
    
    ByteArray plaintext(ciphertext.size());
    decrypt(ciphertext.data(), plaintext.data(), ciphertext.size());
    
    if (usePadding_) {
        plaintext = padding_->unpad(plaintext);
    }
    
    return plaintext;
}

void RandomDeltaMode::encrypt(const Byte* input, Byte* output, size_t length) {
    if (length % blockSize_ != 0) {
        throw CryptoException("Input length must be multiple of block size");
    }
    
    size_t numBlocks = length / blockSize_;
    ByteArray currentIV = iv_;
    
    for (size_t i = 0; i < numBlocks; ++i) {
        const Byte* blockInput = input + i * blockSize_;
        Byte* blockOutput = output + i * blockSize_;
        
        generateDelta(i);
        
        ByteArray modifiedIV(blockSize_);
        utils::xorBlocks(currentIV.data(), delta_.data(), modifiedIV.data(), blockSize_);
        
        ByteArray xored(blockSize_);
        utils::xorBlocks(blockInput, modifiedIV.data(), xored.data(), blockSize_);
        
        cipher_->encryptBlock(xored.data(), blockOutput);
        
        utils::xorBlocksInPlace(blockOutput, delta_.data(), blockSize_);
        
        ByteArray ciphertextWithoutDelta(blockOutput, blockOutput + blockSize_);
        utils::xorBlocksInPlace(ciphertextWithoutDelta.data(), delta_.data(), blockSize_);
        currentIV = ciphertextWithoutDelta;
    }
}

void RandomDeltaMode::decrypt(const Byte* input, Byte* output, size_t length) {
    if (length % blockSize_ != 0) {
        throw CryptoException("Input length must be multiple of block size");
    }
    
    size_t numBlocks = length / blockSize_;
    ByteArray currentIV = iv_;
    
    for (size_t i = 0; i < numBlocks; ++i) {
        const Byte* blockInput = input + i * blockSize_;
        Byte* blockOutput = output + i * blockSize_;
        
        generateDelta(i);
        
        ByteArray ciphertextWithoutDelta(blockSize_);
        utils::xorBlocks(blockInput, delta_.data(), ciphertextWithoutDelta.data(), blockSize_);
        
        ByteArray decrypted(blockSize_);
        cipher_->decryptBlock(ciphertextWithoutDelta.data(), decrypted.data());
        
        ByteArray modifiedIV(blockSize_);
        utils::xorBlocks(currentIV.data(), delta_.data(), modifiedIV.data(), blockSize_);
        
        utils::xorBlocks(decrypted.data(), modifiedIV.data(), blockOutput, blockSize_);
        
        currentIV = ciphertextWithoutDelta;
    }
}

void RandomDeltaMode::reset() {}

}