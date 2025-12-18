// include/crypto/algorithms/rsa/rsa_keygen.hpp
#pragma once
#include "rsa_key.hpp"
#include "../../math/prime.hpp"
#include <cstdint>

namespace crypto {
namespace rsa {

class RSAKeyGenerator {
public:
    // Генерация ключей RSA
    static RSAKey generate(size_t keySizeBits = 512);
    
    // Генерация с защитой от атаки Винера
    static RSAKey generateSecure(size_t keySizeBits = 512);
    
    // Проверка защищенности от атаки Винера
    static bool isVulnerableToWiener(const RSAKey& key);
    
private:
    // Генерация простых чисел
    static BigInteger generatePrime(size_t bits);
    
    // Вычисление открытой экспоненты
    static BigInteger choosePublicExponent(const BigInteger& phi);
    
    // Вычисление секретной экспоненты с защитой от Винера
    static BigInteger computePrivateExponentSecure(const BigInteger& e, const BigInteger& phi, const BigInteger& n);
    
    // Проверка условия для защиты от Винера: d > n^(1/4)/3
    static bool satisfiesWienerProtection(const BigInteger& d, const BigInteger& n);
};

} // namespace rsa
} // namespace crypto

