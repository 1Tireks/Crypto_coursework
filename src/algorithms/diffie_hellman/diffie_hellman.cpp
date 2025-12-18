// src/algorithms/diffie_hellman/diffie_hellman.cpp
#include "../../../include/crypto/algorithms/diffie_hellman/diffie_hellman.hpp"
#include "../../../include/crypto/algorithms/rsa/big_integer.hpp"
#include "../../../include/crypto/core/exceptions.hpp"
#include "../../../include/crypto/math/prime.hpp"
#include <random>

namespace crypto {
namespace diffie_hellman {

using BigInteger = rsa::BigInteger;

DiffieHellman::DiffieHellman() : initialized_(false) {
}

DiffieHellman::DiffieHellman(const DHParams& params) : params_(params), initialized_(true) {
}

DHParams DiffieHellman::generateParams(size_t primeBits) {
    if (primeBits < 64) {
        throw CryptoException("Prime bits must be at least 64");
    }
    
    // Генерируем простое число p
    BigInteger p = BigInteger::random(primeBits);
    
    // Делаем его нечетным
    if (p.isEven()) {
        p = p + BigInteger(1);
    }
    
    // Проверяем на простоту (упрощенная проверка)
    // В реальной реализации нужен тест Миллера-Рабина
    
    // Генератор g обычно выбирается как 2 или небольшое простое число
    // Для упрощения используем g = 2
    BigInteger g(static_cast<int64_t>(2));
    
    return DHParams(p, g);
}

void DiffieHellman::setParams(const DHParams& params) {
    params_ = params;
    initialized_ = true;
}

void DiffieHellman::generateKeys() {
    if (!initialized_) {
        throw CryptoException("Diffie-Hellman parameters not set");
    }
    
    // Генерируем случайный секретный ключ (1 < a < p-1)
    BigInteger one(static_cast<int64_t>(1));
    BigInteger two(static_cast<int64_t>(2));
    BigInteger pMinus1 = params_.p - one;
    privateKey_ = BigInteger::randomInRange(two, pMinus1);
    
    // Вычисляем публичный ключ: A = g^a mod p
    publicKey_ = BigInteger::modPow(params_.g, privateKey_, params_.p);
}

void DiffieHellman::generateKeys(const rsa::BigInteger& privateKey) {
    if (!initialized_) {
        throw CryptoException("Diffie-Hellman parameters not set");
    }
    
    BigInteger one(static_cast<int64_t>(1));
    if (privateKey <= one || privateKey >= params_.p) {
        throw CryptoException("Invalid private key for Diffie-Hellman");
    }
    
    privateKey_ = privateKey;
    publicKey_ = BigInteger::modPow(params_.g, privateKey_, params_.p);
}

rsa::BigInteger DiffieHellman::computeSharedSecret(const rsa::BigInteger& otherPublicKey) const {
    if (!initialized_) {
        throw CryptoException("Diffie-Hellman not initialized");
    }
    
    if (privateKey_.isZero()) {
        throw CryptoException("Private key not generated");
    }
    
    // K = otherPublicKey^privateKey mod p
    return BigInteger::modPow(otherPublicKey, privateKey_, params_.p);
}

Key DiffieHellman::deriveSymmetricKey(const rsa::BigInteger& sharedSecret, size_t keySize) const {
    ByteArray keyBytes = sharedSecret.toBytes();
    
    // Если ключ слишком короткий, повторяем его
    while (keyBytes.size() < keySize) {
        keyBytes.insert(keyBytes.end(), keyBytes.begin(), keyBytes.end());
    }
    
    // Обрезаем до нужного размера
    keyBytes.resize(keySize);
    
    return Key(keyBytes);
}

} // namespace diffie_hellman
} // namespace crypto

