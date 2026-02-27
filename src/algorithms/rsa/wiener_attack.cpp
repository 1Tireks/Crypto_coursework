#include "../../../include/crypto/algorithms/rsa/wiener_attack.hpp"
#include "../../../include/crypto/algorithms/rsa/big_integer.hpp"
#include "../../../include/crypto/core/exceptions.hpp"
#include <cmath>

namespace crypto {
namespace rsa {

bool WienerAttack::computePhi(const BigInteger& n, const BigInteger& e, 
                               const BigInteger& d, BigInteger& phi) {
    
    BigInteger ed = e * d;
    BigInteger edMinus1 = ed - BigInteger(1);
    
    for (int k = 1; k <= 100; ++k) {
        BigInteger k_big(static_cast<int64_t>(k));
        BigInteger phi_candidate = edMinus1 / k_big;
        
        if ((edMinus1 % k_big).isZero()) {
            if (BigInteger::gcd(e, phi_candidate) == BigInteger(1)) {
                phi = phi_candidate;
                return true;
            }
        }
    }
    
    return false;
}

bool WienerAttack::testPrivateKey(const BigInteger& n, const BigInteger& e, 
                                   const BigInteger& d) {
    
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
    size_t nBits = n.bitLength();
    
    if (nBits < 256) {
        return false;
    }
    
    size_t eBits = e.bitLength();
    
    return eBits < nBits / 4;
}

bool WienerAttack::attack(const BigInteger& n, const BigInteger& e, BigInteger& d) {
    std::vector<uint64_t> cf;
    BigInteger temp_e = e;
    BigInteger temp_n = n;
    
    while (!temp_n.isZero()) {
        BigInteger q = temp_e / temp_n;
        BigInteger r = temp_e % temp_n;

        std::string qStr = q.toString();
        if (qStr.size() < 20) {
            uint64_t qVal = std::stoull(qStr);
            cf.push_back(qVal);
        } else {
            break;
        }
        
        temp_e = temp_n;
        temp_n = r;
        
        if (cf.size() > 100) break;
    }
    
    if (cf.size() < 2) {
        return false;
    }
    
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
        
        if (!k.isZero() && k < n) {
            if (testPrivateKey(n, e, k)) {
                d = k;
                return true;
            }
        }
    }
    
    return false;
}

}
}

