#include "../../include/crypto/modes/asymmetric_cipher_mode.hpp"
#include "../../include/crypto/core/exceptions.hpp"

namespace crypto {

AsymmetricCipherMode::AsymmetricCipherMode(std::shared_ptr<IAsymmetricCipher> cipher)
    : cipher_(std::move(cipher)) {
    if (!cipher_) {
        throw CryptoException("AsymmetricCipherMode: cipher cannot be null");
    }
}

std::string AsymmetricCipherMode::name() const {
    if (cipher_) {
        return "AsymmetricCipherMode(" + cipher_->name() + ")";
    }
    return "AsymmetricCipherMode";
}

void AsymmetricCipherMode::setCipher(std::shared_ptr<IBlockCipher> cipher) {
    throw CryptoException("AsymmetricCipherMode: cannot set block cipher, use setAsymmetricCipher");
}

void AsymmetricCipherMode::setPadding(std::unique_ptr<IPadding> padding) {
}

void AsymmetricCipherMode::setIV(const ByteArray& iv) {
}

void AsymmetricCipherMode::generateRandomIV() {
}

ByteArray AsymmetricCipherMode::encrypt(const ByteArray& plaintext) {
    if (!cipher_) {
        throw CryptoException("AsymmetricCipherMode: cipher not set");
    }
    
    return cipher_->encrypt(plaintext);
}

ByteArray AsymmetricCipherMode::decrypt(const ByteArray& ciphertext) {
    if (!cipher_) {
        throw CryptoException("AsymmetricCipherMode: cipher not set");
    }
    
    return cipher_->decrypt(ciphertext);
}

void AsymmetricCipherMode::encrypt(const Byte* input, Byte* output, size_t length) {
    if (!cipher_) {
        throw CryptoException("AsymmetricCipherMode: cipher not set");
    }
    
    ByteArray plaintext(input, input + length);
    ByteArray ciphertext = cipher_->encrypt(plaintext);
    
    if (ciphertext.size() > length) {
        size_t copySize = std::min(ciphertext.size(), length);
        std::copy(ciphertext.begin(), ciphertext.begin() + copySize, output);
    } else {
        std::copy(ciphertext.begin(), ciphertext.end(), output);
        if (ciphertext.size() < length) {
            std::fill(output + ciphertext.size(), output + length, 0);
        }
    }
}

void AsymmetricCipherMode::decrypt(const Byte* input, Byte* output, size_t length) {
    if (!cipher_) {
        throw CryptoException("AsymmetricCipherMode: cipher not set");
    }
    
    ByteArray ciphertext(input, input + length);
    ByteArray plaintext = cipher_->decrypt(ciphertext);
    
    if (plaintext.size() > length) {
        size_t copySize = std::min(plaintext.size(), length);
        std::copy(plaintext.begin(), plaintext.begin() + copySize, output);
    } else {
        std::copy(plaintext.begin(), plaintext.end(), output);
        if (plaintext.size() < length) {
            std::fill(output + plaintext.size(), output + length, 0);
        }
    }
}

void AsymmetricCipherMode::reset() {
}

}

