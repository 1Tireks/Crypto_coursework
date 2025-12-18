// src/algorithms/rc4/rc4.cpp
#include "../../../include/crypto/algorithms/rc4/rc4.hpp"
#include "../../../include/crypto/core/exceptions.hpp"
#include <algorithm>

namespace crypto {

RC4::RC4() : i_(0), j_(0), initialized_(false) {
    // Инициализация S-блока
    for (size_t i = 0; i < STATE_SIZE; ++i) {
        S_[i] = static_cast<Byte>(i);
    }
}

void RC4::keySchedule(const Byte* key, size_t keyLength) {
    if (keyLength == 0 || keyLength > 256) {
        throw InvalidKeyException("RC4 key length must be between 1 and 256 bytes");
    }
    
    // KSA (Key Scheduling Algorithm)
    size_t j = 0;
    for (size_t i = 0; i < STATE_SIZE; ++i) {
        j = (j + S_[i] + key[i % keyLength]) % STATE_SIZE;
        std::swap(S_[i], S_[j]);
    }
    
    i_ = 0;
    j_ = 0;
    initialized_ = true;
}

Byte RC4::generateByte() {
    if (!initialized_) {
        throw CryptoException("RC4 not initialized with key");
    }
    
    // PRGA (Pseudo-Random Generation Algorithm)
    i_ = (i_ + 1) % STATE_SIZE;
    j_ = (j_ + S_[i_]) % STATE_SIZE;
    std::swap(S_[i_], S_[j_]);
    
    Byte K = S_[(S_[i_] + S_[j_]) % STATE_SIZE];
    return K;
}

void RC4::setKey(const Key& key) {
    if (!isValidKey(key)) {
        throw InvalidKeyException("RC4 key must be between 1 and 256 bytes");
    }
    
    // Сбрасываем состояние
    for (size_t i = 0; i < STATE_SIZE; ++i) {
        S_[i] = static_cast<Byte>(i);
    }
    
    key_ = key;
    keySchedule(key.bytes(), key.size());
}

bool RC4::isValidKey(const Key& key) const {
    size_t len = key.size();
    return len >= 1 && len <= 256;
}

void RC4::encrypt(const Byte* input, Byte* output, size_t length) {
    if (!initialized_) {
        throw CryptoException("RC4 not initialized with key");
    }
    
    for (size_t k = 0; k < length; ++k) {
        Byte keystreamByte = generateByte();
        output[k] = input[k] ^ keystreamByte;
    }
}

void RC4::decrypt(const Byte* input, Byte* output, size_t length) {
    // Для RC4 расшифрование идентично шифрованию
    encrypt(input, output, length);
}

void RC4::reset() {
    // Переинициализация с тем же ключом
    if (!key_.empty()) {
        setKey(key_);
    } else {
        initialized_ = false;
        i_ = 0;
        j_ = 0;
    }
}

} // namespace crypto

