#pragma once
#include "rsa_key.hpp"
#include "../../math/prime.hpp"
#include <cstdint>

namespace crypto {
namespace rsa {

class RSAKeyGenerator {
public:
    
    static RSAKey generate(size_t keySizeBits = 1024);
    
    
    static RSAKey generateSecure(size_t keySizeBits = 1024);
    
    
    static bool isVulnerableToWiener(const RSAKey& key);
    
private:
    
    static BigInteger generatePrime(size_t bits);
    
    
    static BigInteger choosePublicExponent(const BigInteger& phi);
    
    
    static BigInteger computePrivateExponentSecure(const BigInteger& e, const BigInteger& phi, const BigInteger& n);
    
    
    static bool satisfiesWienerProtection(const BigInteger& d, const BigInteger& n);
    
    
    static bool isPrimeMillerRabin(const BigInteger& n, int k = 10);
};

}
}

