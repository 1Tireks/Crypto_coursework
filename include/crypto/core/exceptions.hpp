#pragma once
#include <stdexcept>
#include <string>

namespace crypto {


class CryptoException : public std::runtime_error {
public:
    explicit CryptoException(const std::string& message);
};


class InvalidKeyException : public CryptoException {
public:
    explicit InvalidKeyException(const std::string& message);
};


class InvalidBlockSizeException : public CryptoException {
public:
    explicit InvalidBlockSizeException(size_t expected, size_t actual);
};


class PaddingException : public CryptoException {
public:
    explicit PaddingException(const std::string& msg);
};

}