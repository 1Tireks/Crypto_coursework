#include "../../include/crypto/core/exceptions.hpp"

namespace crypto {

CryptoException::CryptoException(const std::string& message) 
    : std::runtime_error("Crypto Error: " + message) {
}

InvalidKeyException::InvalidKeyException(const std::string& message) 
    : CryptoException("Invalid key: " + message) {
}

InvalidBlockSizeException::InvalidBlockSizeException(size_t expected, size_t actual)
    : CryptoException("Invalid block size: expected " + 
                     std::to_string(expected) + ", got " + 
                     std::to_string(actual)) {
}

PaddingException::PaddingException(const std::string& msg)
    : CryptoException("Padding error: " + msg) {
}

}

