// src/modes/cfb.cpp

#include "../../include/crypto/modes/cfb.hpp"
#include "../../include/crypto/core/utils.hpp"
#include "../../include/crypto/math/random.hpp"
#include <stdexcept>
#include <cstring>

namespace crypto {

CFBMode::CFBMode(std::shared_ptr<IBlockCipher> cipher, 
                 std::unique_ptr<IPadding> padding,
                 size_t segmentSizeBits)
    : cipher_(std::move(cipher))
    , padding_(std::move(padding))
    , usePadding_(padding_ != nullptr) {
    
    if (!cipher_) {
        throw CryptoException("Cipher cannot be null");
    }
    
    blockSize_ = cipher_->blockSize();
    
    // Определяем размер сегмента
    if (segmentSizeBits == 0 || segmentSizeBits > blockSize_ * 8) {
        segmentSize_ = blockSize_;
    } else {
        segmentSize_ = (segmentSizeBits + 7) / 8;
    }
    
    generateRandomIV();
    feedback_ = iv_;
}

void CFBMode::setCipher(std::shared_ptr<IBlockCipher> cipher) {
    if (!cipher) {
        throw CryptoException("Cipher cannot be null");
    }
    cipher_ = std::move(cipher);
    blockSize_ = cipher_->blockSize();
    generateRandomIV();
    feedback_ = iv_;
}

void CFBMode::setPadding(std::unique_ptr<IPadding> padding) {
    padding_ = std::move(padding);
    usePadding_ = (padding_ != nullptr);
}

void CFBMode::setIV(const ByteArray& iv) {
    if (iv.size() != blockSize_) {
        throw CryptoException("IV size must equal block size");
    }
    iv_ = iv;
    feedback_ = iv;
}

ByteArray CFBMode::getIV() const {
    return iv_;
}

void CFBMode::generateRandomIV() {
    iv_ = math::randomBytes(blockSize_);
    feedback_ = iv_;
}

ByteArray CFBMode::encrypt(const ByteArray& plaintext) {
    ByteArray data = plaintext;
    
    if (usePadding_) {
        data = padding_->pad(data, blockSize_);
    }
    
    ByteArray ciphertext(data.size());
    encrypt(data.data(), ciphertext.data(), data.size());
    return ciphertext;
}

ByteArray CFBMode::decrypt(const ByteArray& ciphertext) {
    ByteArray plaintext(ciphertext.size());
    decrypt(ciphertext.data(), plaintext.data(), ciphertext.size());
    
    if (usePadding_) {
        plaintext = padding_->unpad(plaintext);
    }
    
    return plaintext;
}

void CFBMode::encrypt(const Byte* input, Byte* output, size_t length) {
    size_t processed = 0;
    
    while (processed < length) {
        ByteArray encrypted(blockSize_);
        cipher_->encryptBlock(feedback_.data(), encrypted.data());
        
        size_t toProcess = std::min(segmentSize_, length - processed);
        
        for (size_t i = 0; i < toProcess; ++i) {
            output[processed + i] = input[processed + i] ^ encrypted[i];
        }
        
        if (segmentSize_ == blockSize_) {
            feedback_.assign(output + processed, output + processed + blockSize_);
        } else {
            std::memmove(feedback_.data(), feedback_.data() + segmentSize_, 
                        blockSize_ - segmentSize_);
            std::memcpy(feedback_.data() + blockSize_ - segmentSize_, 
                       output + processed, segmentSize_);
        }
        
        processed += toProcess;
    }
}

void CFBMode::decrypt(const Byte* input, Byte* output, size_t length) {
    size_t processed = 0;
    
    while (processed < length) {
        ByteArray encrypted(blockSize_);
        cipher_->encryptBlock(feedback_.data(), encrypted.data());
        
        size_t toProcess = std::min(segmentSize_, length - processed);
        
        for (size_t i = 0; i < toProcess; ++i) {
            output[processed + i] = input[processed + i] ^ encrypted[i];
        }
        
        if (segmentSize_ == blockSize_) {
            feedback_.assign(input + processed, input + processed + blockSize_);
        } else {
            std::memmove(feedback_.data(), feedback_.data() + segmentSize_, 
                        blockSize_ - segmentSize_);
            std::memcpy(feedback_.data() + blockSize_ - segmentSize_, 
                       input + processed, segmentSize_);
        }
        
        processed += toProcess;
    }
}

void CFBMode::reset() {
    feedback_ = iv_;
}

}