// src/modes/ecb.cpp
#include "../../include/crypto/modes/ecb.hpp"
#include "../../include/crypto/core/utils.hpp"
#include "../../include/crypto/math/random.hpp"
#include <stdexcept>
#include <cstring>

namespace crypto {

ECBMode::ECBMode(std::shared_ptr<IBlockCipher> cipher, 
                 std::unique_ptr<IPadding> padding)
    : cipher_(std::move(cipher))
    , padding_(std::move(padding))
    , usePadding_(padding_ != nullptr) {
    
    if (!cipher_) {
        throw CryptoException("Cipher cannot be null");
    }
    
    blockSize_ = cipher_->blockSize();
}

void ECBMode::setCipher(std::shared_ptr<IBlockCipher> cipher) {
    if (!cipher) {
        throw CryptoException("Cipher cannot be null");
    }
    cipher_ = std::move(cipher);
    blockSize_ = cipher_->blockSize();
}

void ECBMode::setPadding(std::unique_ptr<IPadding> padding) {
    padding_ = std::move(padding);
    usePadding_ = (padding_ != nullptr);
}

ByteArray ECBMode::encrypt(const ByteArray& plaintext) {
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

ByteArray ECBMode::decrypt(const ByteArray& ciphertext) {
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

void ECBMode::encrypt(const Byte* input, Byte* output, size_t length) {
    if (length % blockSize_ != 0) {
        throw CryptoException("Input length must be multiple of block size");
    }
    
    size_t numBlocks = length / blockSize_;
    
    for (size_t i = 0; i < numBlocks; ++i) {
        const Byte* blockInput = input + i * blockSize_;
        Byte* blockOutput = output + i * blockSize_;
        cipher_->encryptBlock(blockInput, blockOutput);
    }
}

void ECBMode::decrypt(const Byte* input, Byte* output, size_t length) {
    if (length % blockSize_ != 0) {
        throw CryptoException("Input length must be multiple of block size");
    }
    
    size_t numBlocks = length / blockSize_;
    
    for (size_t i = 0; i < numBlocks; ++i) {
        const Byte* blockInput = input + i * blockSize_;
        Byte* blockOutput = output + i * blockSize_;
        cipher_->decryptBlock(blockInput, blockOutput);
    }
}

}