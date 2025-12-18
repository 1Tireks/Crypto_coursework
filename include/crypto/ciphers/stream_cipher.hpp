// include/crypto/ciphers/stream_cipher.hpp
#pragma once
#include "cipher.hpp"

namespace crypto {

class IStreamCipher : public ICipher {
public:
    // Для потоковых шифров blockSize обычно 1 байт
    virtual void encrypt(const Byte* input, Byte* output, size_t length) = 0;
    virtual void decrypt(const Byte* input, Byte* output, size_t length) = 0;
    
    // Сброс состояния (для некоторых потоковых шифров)
    virtual void reset() {}
};

} // namespace crypto

