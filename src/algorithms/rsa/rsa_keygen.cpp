#include "../../../include/crypto/algorithms/rsa/rsa_keygen.hpp"
#include "../../../include/crypto/algorithms/rsa/big_integer.hpp"
#include "../../../include/crypto/core/exceptions.hpp"
#include "../../../include/crypto/math/prime.hpp"
#include <random>
#include <cmath>
#include <algorithm>

namespace crypto {
namespace rsa {

BigInteger RSAKeyGenerator::generatePrime(size_t bits) {
    if (bits <= 32) {
        uint64_t prime = crypto::math::generatePrime(bits);
        return BigInteger(static_cast<int64_t>(prime));
    }
    
    for (int attempts = 0; attempts < 1000; ++attempts) {
        BigInteger candidate = BigInteger::random(bits);
        
        if (candidate.isEven()) {
            BigInteger one(static_cast<int64_t>(1));
            candidate = candidate + one;
        }
        
        BigInteger two(static_cast<int64_t>(2));
        BigInteger three(static_cast<int64_t>(3));
        
        if (candidate == two || candidate == three) {
            return candidate;
        }
        
        bool isPrime = true;
        int smallPrimes[] = {3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47};
        for (int prime : smallPrimes) {
            BigInteger divisor(static_cast<int64_t>(prime));
            BigInteger remainder = candidate % divisor;
            if (remainder.isZero()) {
                isPrime = false;
                break;
            }
        }
        
        if (isPrime) {
            
            
            if (bits > 32) {
                if (isPrimeMillerRabin(candidate, 1)) {
                    return candidate;
                }
            } else {
                return candidate;
            }
        }
    }
    
    throw CryptoException("Could not generate prime number");
}

BigInteger RSAKeyGenerator::choosePublicExponent(const BigInteger& phi) {
    BigInteger e(static_cast<int64_t>(65537));
    
    if (BigInteger::gcd(e, phi) == BigInteger(1)) {
        return e;
    }
    
    BigInteger three(static_cast<int64_t>(3));
    BigInteger five(static_cast<int64_t>(5));
    BigInteger seventeen(static_cast<int64_t>(17));
    
    if (BigInteger::gcd(three, phi) == BigInteger(1)) {
        return three;
    }
    if (BigInteger::gcd(five, phi) == BigInteger(1)) {
        return five;
    }
    if (BigInteger::gcd(seventeen, phi) == BigInteger(1)) {
        return seventeen;
    }
    
    e = three;
    BigInteger maxIterations(static_cast<int64_t>(10000)); 
    BigInteger iterations(static_cast<int64_t>(0));
    
    while (e < phi && iterations < maxIterations) {
        if (BigInteger::gcd(e, phi) == BigInteger(1)) {
            return e;
        }
        e = e + BigInteger(static_cast<int64_t>(2));
        iterations = iterations + BigInteger(static_cast<int64_t>(1));
    }
    
    throw CryptoException("Could not find suitable public exponent");
}

bool RSAKeyGenerator::satisfiesWienerProtection(const BigInteger& d, const BigInteger& n) {
    size_t nBits = n.bitLength();
    size_t quarterBits = nBits / 4;
    
    BigInteger threshold = BigInteger::random(quarterBits);
    threshold = threshold >> 2;
    
    BigInteger three(3);
    threshold = threshold / three;
    
    return d > threshold;
}

BigInteger RSAKeyGenerator::computePrivateExponentSecure(
    const BigInteger& e, const BigInteger& phi, const BigInteger& n) {
    
    BigInteger d = BigInteger::modInv(e, phi);
    
    while (!satisfiesWienerProtection(d, n)) {
        d += phi;
        if (d >= phi) {
            break;
        }
    }
    
    return d;
}

RSAKey RSAKeyGenerator::generate(size_t keySizeBits) {
    if (keySizeBits < 32) {
        throw CryptoException("RSA key size must be at least 32 bits");
    }
    
    size_t halfBits = keySizeBits / 2;
    
    BigInteger p = generatePrime(halfBits);
    BigInteger q = generatePrime(halfBits);
    
    BigInteger n = p * q;
    
    BigInteger p1 = p - BigInteger(1);
    BigInteger q1 = q - BigInteger(1);
    BigInteger phi = p1 * q1;
    
    BigInteger e = choosePublicExponent(phi);
    
    BigInteger d = BigInteger::modInv(e, phi);
    
    return RSAKey(n, e, d, p, q);
}

RSAKey RSAKeyGenerator::generateSecure(size_t keySizeBits) {
    if (keySizeBits < 512) {
        throw CryptoException("Secure RSA key size must be at least 512 bits");
    }
    
    size_t halfBits = keySizeBits / 2;
    
    BigInteger p = generatePrime(halfBits);
    BigInteger q = generatePrime(halfBits);
    
    BigInteger n = p * q;
    
    BigInteger p1 = p - BigInteger(1);
    BigInteger q1 = q - BigInteger(1);
    BigInteger phi = p1 * q1;
    
    BigInteger e = choosePublicExponent(phi);
    
    BigInteger d = computePrivateExponentSecure(e, phi, n);
    
    return RSAKey(n, e, d, p, q);
}

bool RSAKeyGenerator::isVulnerableToWiener(const RSAKey& key) {
    if (!key.isPrivate()) {
        return false;
    }
    
    return !satisfiesWienerProtection(key.d, key.n);
}

bool RSAKeyGenerator::isPrimeMillerRabin(const BigInteger& n, int k) {
    if (n < BigInteger(2)) return false;
    if (n == BigInteger(2) || n == BigInteger(3)) return true;
    if (n.isEven()) return false;
    
    
    BigInteger d = n - BigInteger(1);
    int r = 0;
    while (d.isEven()) {
        d = d >> 1;
        r++;
    }
    
    std::random_device rd;
    std::mt19937 gen(rd());
    
    BigInteger nMinus2 = n - BigInteger(2);
    BigInteger two(2);
    
    
    
    
    int smallBases[] = {2, 3, 5};
    int numBases = std::min(k, 3);
    
    for (int i = 0; i < numBases; ++i) {
        BigInteger a(smallBases[i]);
        
        
        if (a >= nMinus2) {
            continue;
        }
        
        BigInteger x = BigInteger::modPow(a, d, n);
        
        if (x == BigInteger(1) || x == nMinus2) {
            continue;
        }
        
        bool composite = true;
        for (int j = 0; j < r - 1; ++j) {
            x = BigInteger::modPow(x, two, n);
            if (x == nMinus2) {
                composite = false;
                break;
            }
        }
        
        if (composite) {
            return false;
        }
    }
    
    return true;
}

}
}

