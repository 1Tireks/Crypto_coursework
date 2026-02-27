#pragma once
#include "big_integer.hpp"
#include <string>

namespace crypto {
namespace rsa {

struct RSAKey {
    BigInteger n;  
    BigInteger e;  
    BigInteger d;  
    BigInteger p;  
    BigInteger q;  
    
    RSAKey() = default;
    
    
    RSAKey(const BigInteger& n, const BigInteger& e) : n(n), e(e) {}
    
    
    RSAKey(const BigInteger& n, const BigInteger& e, const BigInteger& d)
        : n(n), e(e), d(d) {}
    
    
    RSAKey(const BigInteger& n, const BigInteger& e, const BigInteger& d,
           const BigInteger& p, const BigInteger& q)
        : n(n), e(e), d(d), p(p), q(q) {}
    
    bool isPrivate() const { return !d.isZero(); }
    bool isValid() const { return !n.isZero() && !e.isZero(); }
};

}
}

