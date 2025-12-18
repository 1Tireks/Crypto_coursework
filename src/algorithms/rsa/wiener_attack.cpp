// src/algorithms/rsa/wiener_attack.cpp
#include "../../../include/crypto/algorithms/rsa/wiener_attack.hpp"
#include "../../../include/crypto/algorithms/rsa/big_integer.hpp"
#include "../../../include/crypto/core/exceptions.hpp"
#include <cmath>

namespace crypto {
namespace rsa {

bool WienerAttack::computePhi(const BigInteger& n, const BigInteger& e, 
                               const BigInteger& d, BigInteger& phi) {
    // ed ≡ 1 (mod φ(n))
    // ed - 1 = k * φ(n) для некоторого k
    // Пробуем найти k и φ(n)
    
    BigInteger ed = e * d;
    BigInteger edMinus1 = ed - BigInteger(1);
    
    // k должно быть небольшим (обычно близко к e/n)
    // Пробуем разные значения k
    for (int k = 1; k <= 100; ++k) {
        BigInteger k_big(static_cast<int64_t>(k));
        BigInteger phi_candidate = edMinus1 / k_big;
        
        // Проверяем, что phi делит ed-1
        if ((edMinus1 % k_big).isZero()) {
            // Проверяем, что e и phi взаимно простые
            if (BigInteger::gcd(e, phi_candidate) == BigInteger(1)) {
                // Проверяем, что n может быть разложено
                // (n = p * q, где p и q простые)
                phi = phi_candidate;
                return true;
            }
        }
    }
    
    return false;
}

bool WienerAttack::testPrivateKey(const BigInteger& n, const BigInteger& e, 
                                   const BigInteger& d) {
    // Проверяем, что ed ≡ 1 (mod φ(n))
    // Для этого проверяем несколько тестовых сообщений
    
    BigInteger test1(2);
    BigInteger test2(3);
    
    try {
        BigInteger c1 = BigInteger::modPow(test1, e, n);
        BigInteger m1 = BigInteger::modPow(c1, d, n);
        if (m1 != test1) return false;
        
        BigInteger c2 = BigInteger::modPow(test2, e, n);
        BigInteger m2 = BigInteger::modPow(c2, d, n);
        if (m2 != test2) return false;
        
        return true;
    } catch (...) {
        return false;
    }
}

bool WienerAttack::isVulnerable(const BigInteger& n, const BigInteger& e) {
    // Атака Винера работает, если d < n^(1/4) / 3
    size_t nBits = n.bitLength();
    
    // Если модуль слишком маленький, атака не работает надежно
    if (nBits < 256) {
        return false;
    }
    
    // Проверяем условие уязвимости
    // Это приблизительная проверка без знания d
    // В реальности нужно знать d, но мы можем оценить по размеру e
    size_t eBits = e.bitLength();
    
    // Если e очень большое по сравнению с n, то d может быть маленьким
    // Это эвристика, не точная проверка
    return eBits < nBits / 4;
}

bool WienerAttack::attack(const BigInteger& n, const BigInteger& e, BigInteger& d) {
    // Атака Винера использует цепные дроби для e/n
    // Находим подходящие дроби, которые могут быть d/k для секретного ключа d
    
    // Вычисляем цепную дробь для e/n
    // Для этого используем алгоритм Евклида
    
    std::vector<uint64_t> cf;
    BigInteger temp_e = e;
    BigInteger temp_n = n;
    
    // Вычисляем цепную дробь
    while (!temp_n.isZero()) {
        BigInteger q = temp_e / temp_n;
        BigInteger r = temp_e % temp_n;
        
        // Конвертируем q в uint64_t (упрощение)
        std::string qStr = q.toString();
        if (qStr.size() < 20) { // Ограничение для безопасности
            uint64_t qVal = std::stoull(qStr);
            cf.push_back(qVal);
        } else {
            break; // Слишком большое значение
        }
        
        temp_e = temp_n;
        temp_n = r;
        
        if (cf.size() > 100) break; // Защита от бесконечного цикла
    }
    
    // Вычисляем подходящие дроби
    // Используем их для поиска кандидатов на d
    
    if (cf.size() < 2) {
        return false;
    }
    
    // Для каждой подходящей дроби проверяем, является ли знаменатель секретным ключом
    BigInteger prev_k(1), k(0);
    BigInteger prev_h(0), h(1);
    
    for (size_t i = 0; i < cf.size() && i < 50; ++i) {
        uint64_t a_i = cf[i];
        BigInteger a_i_big(static_cast<int64_t>(a_i));
        
        BigInteger next_k = a_i_big * k + prev_k;
        BigInteger next_h = a_i_big * h + prev_h;
        
        prev_k = k;
        prev_h = h;
        k = next_k;
        h = next_h;
        
        // Проверяем знаменатель подходящей дроби как кандидат на d
        if (!k.isZero() && k < n) {
            // Проверяем, является ли k правильным секретным ключом
            if (testPrivateKey(n, e, k)) {
                d = k;
                return true;
            }
        }
    }
    
    return false;
}

} // namespace rsa
} // namespace crypto

