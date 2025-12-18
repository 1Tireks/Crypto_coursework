// src/modes/asymmetric_cipher_mode.cpp
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
    // Не поддерживается - используем асимметричный шифр
    throw CryptoException("AsymmetricCipherMode: cannot set block cipher, use setAsymmetricCipher");
}

void AsymmetricCipherMode::setPadding(std::unique_ptr<IPadding> padding) {
    // Асимметричные шифры используют встроенный паддинг (OAEP, PKCS#1)
    // Игнорируем внешний паддинг
}

void AsymmetricCipherMode::setIV(const ByteArray& iv) {
    // Асимметричные шифры не используют IV
    // Игнорируем
}

void AsymmetricCipherMode::generateRandomIV() {
    // Асимметричные шифры не используют IV
    // Игнорируем
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
        // Для асимметричных шифров размер шифротекста может быть больше
        // Копируем сколько можем
        size_t copySize = std::min(ciphertext.size(), length);
        std::copy(ciphertext.begin(), ciphertext.begin() + copySize, output);
    } else {
        std::copy(ciphertext.begin(), ciphertext.end(), output);
        // Заполняем остаток нулями, если нужно
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
        // Копируем сколько можем
        size_t copySize = std::min(plaintext.size(), length);
        std::copy(plaintext.begin(), plaintext.begin() + copySize, output);
    } else {
        std::copy(plaintext.begin(), plaintext.end(), output);
        // Заполняем остаток нулями, если нужно
        if (plaintext.size() < length) {
            std::fill(output + plaintext.size(), output + length, 0);
        }
    }
}

void AsymmetricCipherMode::reset() {
    // Асимметричные шифры не имеют состояния для сброса
}

} // namespace crypto

