// include/crypto/algorithms/rsa/wiener_attack.hpp
#pragma once
#include "rsa_key.hpp"
#include "../../math/continued_fraction.hpp"
#include <vector>

namespace crypto {
namespace rsa {

class WienerAttack {
public:
    // Выполняет атаку Винера на RSA
    // Возвращает секретный ключ d, если атака успешна
    static bool attack(const BigInteger& n, const BigInteger& e, BigInteger& d);
    
    // Проверяет, уязвим ли ключ к атаке Винера
    static bool isVulnerable(const BigInteger& n, const BigInteger& e);
    
private:
    // Проверяет, является ли кандидат правильным секретным ключом
    static bool testPrivateKey(const BigInteger& n, const BigInteger& e, const BigInteger& d);
    
    // Вычисляет φ(n) из n и d
    static bool computePhi(const BigInteger& n, const BigInteger& e, const BigInteger& d, BigInteger& phi);
};

} // namespace rsa
} // namespace crypto

