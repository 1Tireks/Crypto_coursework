#pragma once
#include "rsa_key.hpp"
#include "../../math/continued_fraction.hpp"
#include <vector>

namespace crypto {
namespace rsa {

class WienerAttack {
public:
    static bool attack(const BigInteger& n, const BigInteger& e, BigInteger& d);
    
    static bool isVulnerable(const BigInteger& n, const BigInteger& e);
    
private:
    
    static bool testPrivateKey(const BigInteger& n, const BigInteger& e, const BigInteger& d);
    
    
    static bool computePhi(const BigInteger& n, const BigInteger& e, const BigInteger& d, BigInteger& phi);
};

}
}

