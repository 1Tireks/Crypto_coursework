// include/crypto/core/exceptions.hpp

#pragma once
#include <stdexcept>
#include <string>

namespace crypto {

// Базовое исключение для всех криптографических ошибок
class CryptoException : public std::runtime_error {
public:
    explicit CryptoException(const std::string& message);
};

// Исключение для ошибок, связанных с некорректными ключами
class InvalidKeyException : public CryptoException {
public:
    explicit InvalidKeyException(const std::string& message);
};

// Исключение для ошибок, связанных с неправильным размером блока
class InvalidBlockSizeException : public CryptoException {
public:
    explicit InvalidBlockSizeException(size_t expected, size_t actual);
};

// Исключение для ошибок, связанных с паддингом
class PaddingException : public CryptoException {
public:
    explicit PaddingException(const std::string& msg);
};

}