#include "../../include/crypto/modes/pcbc.hpp"
#include "../../include/crypto/core/utils.hpp"
#include "../../include/crypto/math/random.hpp"
#include <stdexcept>
#include <cstring>

namespace crypto {

PCBCMode::PCBCMode(std::shared_ptr<IBlockCipher> cipher, 
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

void PCBCMode::setCipher(std::shared_ptr<IBlockCipher> cipher) {
    if (!cipher) {
        throw CryptoException("Cipher cannot be null");
    }
    cipher_ = std::move(cipher);
    blockSize_ = cipher_->blockSize();
    generateRandomIV();
}

void PCBCMode::setPadding(std::unique_ptr<IPadding> padding) {
    padding_ = std::move(padding);
    usePadding_ = (padding_ != nullptr);
}

void PCBCMode::setIV(const ByteArray& iv) {
    if (iv.size() != blockSize_) {
        throw CryptoException("IV size must equal block size");
    }
    iv_ = iv;
}

ByteArray PCBCMode::getIV() const {
    return iv_;
}

void PCBCMode::generateRandomIV() {
    iv_ = math::randomBytes(blockSize_);
}

ByteArray PCBCMode::encrypt(const ByteArray& plaintext) {
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

ByteArray PCBCMode::decrypt(const ByteArray& ciphertext) {
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

void PCBCMode::encrypt(const Byte* input, Byte* output, size_t length) {
    if (length % blockSize_ != 0) {
        throw CryptoException("Input length must be multiple of block size");
    }
    
    size_t numBlocks = length / blockSize_;
    ByteArray previousPlain = iv_;
    ByteArray previousCipher(blockSize_);
    
    for (size_t i = 0; i < numBlocks; ++i) {
        const Byte* blockInput = input + i * blockSize_;
        Byte* blockOutput = output + i * blockSize_;
        ByteArray xored(blockSize_);
        
        utils::xorBlocks(blockInput, previousPlain.data(), xored.data(), blockSize_);
        utils::xorBlocksInPlace(xored.data(), previousCipher.data(), blockSize_);
        
        cipher_->encryptBlock(xored.data(), blockOutput);
        
        previousPlain.assign(blockInput, blockInput + blockSize_);
        previousCipher.assign(blockOutput, blockOutput + blockSize_);
    }
}

void PCBCMode::decrypt(const Byte* input, Byte* output, size_t length) {
    if (length % blockSize_ != 0) {
        throw CryptoException("Input length must be multiple of block size");
    }
    
    size_t numBlocks = length / blockSize_;
    ByteArray previousPlain = iv_;
    ByteArray previousCipher(blockSize_);
    
    for (size_t i = 0; i < numBlocks; ++i) {
        const Byte* blockInput = input + i * blockSize_;
        Byte* blockOutput = output + i * blockSize_;
        ByteArray decrypted(blockSize_);
        
        cipher_->decryptBlock(blockInput, decrypted.data());
        
        utils::xorBlocks(decrypted.data(), previousPlain.data(), blockOutput, blockSize_);
        utils::xorBlocksInPlace(blockOutput, previousCipher.data(), blockSize_);
        
        previousPlain.assign(blockOutput, blockOutput + blockSize_);
        previousCipher.assign(blockInput, blockInput + blockSize_);
    }
}

void PCBCMode::reset() {}

}