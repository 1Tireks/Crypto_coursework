// include/crypto/ciphers/asymmetric_cipher.hpp
#pragma once
#include "../core/types.hpp"

namespace crypto {

class IAsymmetricCipher {
public:
    virtual ~IAsymmetricCipher() = default;
    virtual std::string name() const = 0;
    virtual ByteArray encrypt(const ByteArray& plaintext) = 0;
    virtual ByteArray decrypt(const ByteArray& ciphertext) = 0;
};

} // namespace crypto

