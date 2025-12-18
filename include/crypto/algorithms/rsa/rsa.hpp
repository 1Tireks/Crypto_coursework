// include/crypto/algorithms/rsa/rsa.hpp
#pragma once
#include "rsa_key.hpp"
#include "../../core/types.hpp"
#include "../../ciphers/asymmetric_cipher.hpp"
#include <memory>

namespace crypto {
namespace rsa {

class RSA : public IAsymmetricCipher {
private:
    RSAKey key_;
    bool hasPrivateKey_;
    
public:
    RSA();
    explicit RSA(const RSAKey& key);
    
    std::string name() const override { return "RSA"; }
    
    // Установка ключей
    void setPublicKey(const BigInteger& n, const BigInteger& e);
    void setPrivateKey(const BigInteger& n, const BigInteger& d);
    void setKey(const RSAKey& key);
    const RSAKey& getKey() const { return key_; }
    
    // Шифрование/расшифрование
    ByteArray encrypt(const ByteArray& plaintext) override;
    ByteArray decrypt(const ByteArray& ciphertext) override;
    
    // Шифрование больших данных (с разбиением на блоки)
    ByteArray encryptBlock(const ByteArray& block) const;
    ByteArray decryptBlock(const ByteArray& block) const;
    
    // Вспомогательные методы
    size_t getBlockSize() const;
    ByteArray padOAEP(const ByteArray& data) const;
    ByteArray unpadOAEP(const ByteArray& padded) const;
    
private:
    BigInteger encryptInteger(const BigInteger& m) const;
    BigInteger decryptInteger(const BigInteger& c) const;
};

} // namespace rsa
} // namespace crypto

