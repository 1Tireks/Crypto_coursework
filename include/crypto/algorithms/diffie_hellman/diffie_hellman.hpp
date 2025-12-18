// include/crypto/algorithms/diffie_hellman/diffie_hellman.hpp
#pragma once
#include "../../algorithms/rsa/big_integer.hpp"
#include "../../core/types.hpp"
#include <memory>

namespace crypto {
namespace diffie_hellman {

// Параметры для протокола Диффи-Хеллмана
struct DHParams {
    rsa::BigInteger p;  // Большое простое число (модуль)
    rsa::BigInteger g;  // Генератор (примитивный корень по модулю p)
    
    DHParams() = default;
    DHParams(const rsa::BigInteger& p, const rsa::BigInteger& g) : p(p), g(g) {}
};

// Участник протокола Диффи-Хеллмана
class DiffieHellman {
private:
    DHParams params_;
    rsa::BigInteger privateKey_;  // Секретный ключ (a или b)
    rsa::BigInteger publicKey_;   // Публичный ключ (A = g^a mod p или B = g^b mod p)
    bool initialized_;
    
public:
    DiffieHellman();
    explicit DiffieHellman(const DHParams& params);
    
    // Генерация параметров (p и g)
    static DHParams generateParams(size_t primeBits = 512);
    
    // Установка параметров
    void setParams(const DHParams& params);
    
    // Генерация секретного и публичного ключей
    void generateKeys();
    void generateKeys(const rsa::BigInteger& privateKey); // С заданным секретным ключом
    
    // Получение ключей
    const rsa::BigInteger& getPrivateKey() const { return privateKey_; }
    const rsa::BigInteger& getPublicKey() const { return publicKey_; }
    const DHParams& getParams() const { return params_; }
    
    // Вычисление общего секрета (K = otherPublicKey^privateKey mod p)
    rsa::BigInteger computeSharedSecret(const rsa::BigInteger& otherPublicKey) const;
    
    // Генерация ключа для симметричного шифра из общего секрета
    Key deriveSymmetricKey(const rsa::BigInteger& sharedSecret, size_t keySize) const;
};

} // namespace diffie_hellman
} // namespace crypto

