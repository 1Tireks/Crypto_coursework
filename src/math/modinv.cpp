#include "../../include/crypto/math/modinv.hpp"
#include "../../include/crypto/core/exceptions.hpp"
#include <stdexcept>

namespace crypto {
namespace math {

uint64_t modinv(uint64_t a, uint64_t m) {
    if (m == 0 || m == 1) {
        throw CryptoException("Modulus must be greater than 1");
    }
    
    int64_t old_r = static_cast<int64_t>(a);
    int64_t r = static_cast<int64_t>(m);
    int64_t old_s = 1;
    int64_t s = 0;
    
    while (r != 0) {
        int64_t quotient = old_r / r;
        
        int64_t temp = r;
        r = old_r - quotient * r;
        old_r = temp;
        
        temp = s;
        s = old_s - quotient * s;
        old_s = temp;
    }
    
    if (old_r > 1) {
        throw CryptoException("Modular inverse does not exist");
    }
    
    if (old_s < 0) {
        old_s += static_cast<int64_t>(m);
    }
    
    return static_cast<uint64_t>(old_s);
}

}
}

