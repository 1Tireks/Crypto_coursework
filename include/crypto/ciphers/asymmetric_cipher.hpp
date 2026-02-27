#pragma once
#include "cipher.hpp"

namespace crypto {

class IAsymmetricCipher : public ICipher {
public:
    virtual ~IAsymmetricCipher() = default;
    
    virtual ByteArray encrypt(const ByteArray& plaintext) = 0;
    virtual ByteArray decrypt(const ByteArray& ciphertext) = 0;
};

}

