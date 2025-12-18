// src/modes/cbc.cpp

#include "../../include/crypto/modes/cbc.hpp"
#include "../../include/crypto/core/utils.hpp"
#include "../../include/crypto/math/random.hpp"
#include <stdexcept>
#include <cstring>

namespace crypto {

CBCMode::CBCMode(std::shared_ptr<IBlockCipher> cipher, 
                 std::unique_ptr<IPadding> padding)
    : cipher_(std::move(cipher))
    , padding_(std::move(padding))
    , usePadding_(padding_ != nullptr) {
    
    if (!cipher_) {
        throw CryptoException("Cipher cannot be null");
    }
    
    blockSize_ = cipher_->blockSize();
    generateRandomIV();
}

void CBCMode::setCipher(std::shared_ptr<IBlockCipher> cipher) {
    if (!cipher) {
        throw CryptoException("Cipher cannot be null");
    }
    cipher_ = std::move(cipher);
    blockSize_ = cipher_->blockSize();
    generateRandomIV();
}

void CBCMode::setPadding(std::unique_ptr<IPadding> padding) {
    padding_ = std::move(padding);
    usePadding_ = (padding_ != nullptr);
}

void CBCMode::setIV(const ByteArray& iv) {
    if (iv.size() != blockSize_) {
        throw CryptoException("IV size must equal block size");
    }
    iv_ = iv;
}

ByteArray CBCMode::getIV() const {
    return iv_;
}

void CBCMode::generateRandomIV() {
    iv_ = math::randomBytes(blockSize_);
}

ByteArray CBCMode::encrypt(const ByteArray& plaintext) {
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

ByteArray CBCMode::decrypt(const ByteArray& ciphertext) {
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

void CBCMode::encrypt(const Byte* input, Byte* output, size_t length) {
    if (length % blockSize_ != 0) {
        throw CryptoException("Input length must be multiple of block size");
    }
    
    size_t numBlocks = length / blockSize_;
    ByteArray currentIV = iv_;
    
    for (size_t i = 0; i < numBlocks; ++i) {
        const Byte* blockInput = input + i * blockSize_;
        Byte* blockOutput = output + i * blockSize_;
        ByteArray xored(blockSize_);
        
        // XOR с предыдущим зашифрованным блоком (или IV для первого блока)
        utils::xorBlocks(blockInput, currentIV.data(), xored.data(), blockSize_);
        
        // Шифруем
        cipher_->encryptBlock(xored.data(), blockOutput);
        
        // Обновляем текущий IV для следующего блока
        currentIV.assign(blockOutput, blockOutput + blockSize_);
    }
}

void CBCMode::decrypt(const Byte* input, Byte* output, size_t length) {
    if (length % blockSize_ != 0) {
        throw CryptoException("Input length must be multiple of block size");
    }
    
    size_t numBlocks = length / blockSize_;
    ByteArray previousBlock = iv_;
    
    for (size_t i = 0; i < numBlocks; ++i) {
        const Byte* blockInput = input + i * blockSize_;
        Byte* blockOutput = output + i * blockSize_;
        ByteArray decrypted(blockSize_);
        
        cipher_->decryptBlock(blockInput, decrypted.data());
        
        utils::xorBlocks(decrypted.data(), previousBlock.data(), blockOutput, blockSize_);
        
        previousBlock.assign(blockInput, blockInput + blockSize_);
    }
}

}