// src/modes/stream_cipher_mode.cpp
#include "../../include/crypto/modes/stream_cipher_mode.hpp"
#include "../../include/crypto/core/exceptions.hpp"

namespace crypto {

StreamCipherMode::StreamCipherMode(std::shared_ptr<IStreamCipher> cipher)
    : cipher_(std::move(cipher)) {
    if (!cipher_) {
        throw CryptoException("StreamCipherMode: cipher cannot be null");
    }
}

std::string StreamCipherMode::name() const {
    if (cipher_) {
        return "StreamCipherMode(" + cipher_->name() + ")";
    }
    return "StreamCipherMode";
}

void StreamCipherMode::setCipher(std::shared_ptr<IBlockCipher> cipher) {
    // Не поддерживается - используем потоковый шифр
    throw CryptoException("StreamCipherMode: cannot set block cipher, use setStreamCipher");
}

void StreamCipherMode::setPadding(std::unique_ptr<IPadding> padding) {
    // Потоковые шифры не используют паддинг
    // Игнорируем
}

void StreamCipherMode::setIV(const ByteArray& iv) {
    // Потоковые шифры не используют IV
    // Игнорируем
}

void StreamCipherMode::generateRandomIV() {
    // Потоковые шифры не используют IV
    // Игнорируем
}

ByteArray StreamCipherMode::encrypt(const ByteArray& plaintext) {
    if (!cipher_) {
        throw CryptoException("StreamCipherMode: cipher not set");
    }
    
    ByteArray ciphertext(plaintext.size());
    cipher_->encrypt(plaintext.data(), ciphertext.data(), plaintext.size());
    
    return ciphertext;
}

ByteArray StreamCipherMode::decrypt(const ByteArray& ciphertext) {
    if (!cipher_) {
        throw CryptoException("StreamCipherMode: cipher not set");
    }
    
    ByteArray plaintext(ciphertext.size());
    cipher_->decrypt(ciphertext.data(), plaintext.data(), ciphertext.size());
    
    return plaintext;
}

void StreamCipherMode::encrypt(const Byte* input, Byte* output, size_t length) {
    if (!cipher_) {
        throw CryptoException("StreamCipherMode: cipher not set");
    }
    cipher_->encrypt(input, output, length);
}

void StreamCipherMode::decrypt(const Byte* input, Byte* output, size_t length) {
    if (!cipher_) {
        throw CryptoException("StreamCipherMode: cipher not set");
    }
    cipher_->decrypt(input, output, length);
}

void StreamCipherMode::reset() {
    if (cipher_) {
        cipher_->reset();
    }
}

} // namespace crypto

