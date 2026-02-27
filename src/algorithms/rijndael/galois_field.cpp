#include "../../../include/crypto/algorithms/rijndael/galois_field.hpp"
#include <algorithm>

namespace crypto {
namespace rijndael {

size_t IrreduciblePolynomials::findIndex(uint16_t polynomial) {
    auto it = std::find(ALL_POLYNOMIALS.begin(), ALL_POLYNOMIALS.end(), polynomial);
    if (it != ALL_POLYNOMIALS.end()) {
        return std::distance(ALL_POLYNOMIALS.begin(), it);
    }
    return 0;
}

GaloisField::GaloisField(uint16_t irreduciblePoly)
    : irreduciblePoly_(irreduciblePoly) {
    bool found = false;
    for (uint16_t poly : IrreduciblePolynomials::ALL_POLYNOMIALS) {
        if (poly == irreduciblePoly) {
            found = true;
            break;
        }
    }
    if (!found) {
        irreduciblePoly_ = IrreduciblePolynomials::DEFAULT;
    }
}

GaloisField::Element GaloisField::multiplyByX(Element a) const {
    Element result = a << 1;
    if (a & 0x80) {
        result ^= static_cast<Element>(irreduciblePoly_ & 0xFF);
    }
    return result;
}

GaloisField::Element GaloisField::multiply(Element a, Element b) const {
    Element result = 0;
    Element temp = a;
    
    for (int i = 0; i < 8; ++i) {
        if (b & (1 << i)) {
            result ^= temp;
        }
        temp = multiplyByX(temp);
    }
    
    return result;
}

GaloisField::Element GaloisField::inverse(Element a) const {
    if (a == 0) {
        return 0;
    }
    
    return pow(a, 254);
}

GaloisField::Element GaloisField::pow(Element a, int n) const {
    if (a == 0) return 0;
    if (n == 0) return 1;
    if (n < 0) {
        a = inverse(a);
        n = -n;
    }
    
    Element result = 1;
    Element base = a;
    
    while (n > 0) {
        if (n & 1) {
            result = multiply(result, base);
        }
        base = multiply(base, base);
        n >>= 1;
    }
    
    return result;
}

GaloisField::Element GaloisField::divide(Element a, Element b) const {
    if (b == 0) {
        return 0;
    }
    
    Element b_inv = inverse(b);
    return multiply(a, b_inv);
}

}
}
