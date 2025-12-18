// include/crypto/algorithms/rsa/rsa_key.hpp
#pragma once
#include "big_integer.hpp"
#include <string>

namespace crypto {
namespace rsa {

struct RSAKey {
    BigInteger n;  // Модуль
    BigInteger e;  // Открытая экспонента
    BigInteger d;  // Секретная экспонента
    BigInteger p;  // Простое число 1 (секретное)
    BigInteger q;  // Простое число 2 (секретное)
    
    RSAKey() = default;
    
    // Публичный ключ
    RSAKey(const BigInteger& n, const BigInteger& e) : n(n), e(e) {}
    
    // Приватный ключ
    RSAKey(const BigInteger& n, const BigInteger& e, const BigInteger& d)
        : n(n), e(e), d(d) {}
    
    // Полный ключ
    RSAKey(const BigInteger& n, const BigInteger& e, const BigInteger& d,
           const BigInteger& p, const BigInteger& q)
        : n(n), e(e), d(d), p(p), q(q) {}
    
    bool isPrivate() const { return !d.isZero(); }
    bool isValid() const { return !n.isZero() && !e.isZero(); }
};

} // namespace rsa
} // namespace crypto

