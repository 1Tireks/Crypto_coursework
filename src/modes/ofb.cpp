#include "../../include/crypto/modes/ofb.hpp"
#include "../../include/crypto/core/utils.hpp"
#include "../../include/crypto/math/random.hpp"
#include <stdexcept>
#include <cstring>

namespace crypto {

OFBMode::OFBMode(std::shared_ptr<IBlockCipher> cipher, 
                 std::unique_ptr<IPadding> padding)
    : cipher_(std::move(cipher))
    , padding_(std::move(padding))
    , keystreamPos_(0)
    , usePadding_(padding_ != nullptr) {
    
    if (!cipher_) {
        throw CryptoException("Cipher cannot be null");
    }
    
    blockSize_ = cipher_->blockSize();
    generateRandomIV();
    keystream_.resize(blockSize_);
    generateKeystream();
}

void OFBMode::setCipher(std::shared_ptr<IBlockCipher> cipher) {
    if (!cipher) {
        throw CryptoException("Cipher cannot be null");
    }
    cipher_ = std::move(cipher);
    blockSize_ = cipher_->blockSize();
    generateRandomIV();
    keystream_.resize(blockSize_);
    keystreamPos_ = 0;
    generateKeystream();
}

void OFBMode::setPadding(std::unique_ptr<IPadding> padding) {
    padding_ = std::move(padding);
    usePadding_ = (padding_ != nullptr);
}

void OFBMode::setIV(const ByteArray& iv) {
    if (iv.size() != blockSize_) {
        throw CryptoException("IV size must equal block size");
    }
    iv_ = iv;
    reset();
}

ByteArray OFBMode::getIV() const {
    return iv_;
}

void OFBMode::generateRandomIV() {
    iv_ = math::randomBytes(blockSize_);
    reset();
}

ByteArray OFBMode::encrypt(const ByteArray& plaintext) {
    ByteArray data = plaintext;
    
    if (usePadding_) {
        data = padding_->pad(data, blockSize_);
    }
    
    ByteArray ciphertext(data.size());
    encrypt(data.data(), ciphertext.data(), data.size());
    return ciphertext;
}

ByteArray OFBMode::decrypt(const ByteArray& ciphertext) {
    ByteArray plaintext(ciphertext.size());
    decrypt(ciphertext.data(), plaintext.data(), ciphertext.size());
    
    if (usePadding_) {
        plaintext = padding_->unpad(plaintext);
    }
    
    return plaintext;
}

void OFBMode::generateKeystream() {
    ByteArray input = iv_;
    
    while (keystream_.size() < blockSize_ * 4) {
        ByteArray output(blockSize_);
        cipher_->encryptBlock(input.data(), output.data());
        keystream_.insert(keystream_.end(), output.begin(), output.end());
        input = output;
    }
}

void OFBMode::generateMoreKeystream() {
    if (keystreamPos_ + blockSize_ > keystream_.size()) {
        ByteArray input(keystream_.end() - blockSize_, keystream_.end());
        ByteArray output(blockSize_);
        cipher_->encryptBlock(input.data(), output.data());
        keystream_.insert(keystream_.end(), output.begin(), output.end());
    }
}

void OFBMode::encrypt(const Byte* input, Byte* output, size_t length) {
    size_t processed = 0;
    
    while (processed < length) {
        generateMoreKeystream();
        
        size_t toProcess = std::min(blockSize_ - keystreamPos_, length - processed);
        
        for (size_t i = 0; i < toProcess; ++i) {
            output[processed + i] = input[processed + i] ^ keystream_[keystreamPos_ + i];
        }
        
        keystreamPos_ += toProcess;
        processed += toProcess;
        
        if (keystreamPos_ >= blockSize_) {
            keystreamPos_ = 0;
            if (keystream_.size() > blockSize_ * 8) {
                keystream_.erase(keystream_.begin(), keystream_.begin() + blockSize_ * 4);
                keystreamPos_ = 0;
            }
        }
    }
}

void OFBMode::decrypt(const Byte* input, Byte* output, size_t length) {
    encrypt(input, output, length);
}

void OFBMode::reset() {
    keystream_.clear();
    keystreamPos_ = 0;
    generateKeystream();
}

}