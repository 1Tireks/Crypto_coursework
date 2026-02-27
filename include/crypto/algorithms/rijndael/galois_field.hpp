#pragma once
#include <cstdint>
#include <array>

namespace crypto {
namespace rijndael {

namespace IrreduciblePolynomials {
    
    static constexpr std::array<uint16_t, 30> ALL_POLYNOMIALS = {
        0x11B,  
        0x11D,  
        0x12B,  
        0x12D,  
        0x139,  
        0x13F,  
        0x14D,  
        0x15F,  
        0x163,  
        0x165,  
        0x169,  
        0x171,  
        0x177,  
        0x17B,  
        0x187,  
        0x18D,  
        0x18F,  
        0x195,  
        0x199,  
        0x1A3,  
        0x1A9,  
        0x1B1,  
        0x1BD,  
        0x1C3,  
        0x1CF,  
        0x1D7,  
        0x1DD,  
        0x1E7,  
        0x1F3,  
        0x1F5   
    };
    
    static constexpr uint16_t DEFAULT = 0x11B;
    
    static constexpr uint16_t getPolynomial(size_t index) {
        return (index < ALL_POLYNOMIALS.size()) ? ALL_POLYNOMIALS[index] : DEFAULT;
    }
    
    static size_t findIndex(uint16_t polynomial);
}


class GaloisField {
public:
    using Element = uint8_t;
    
private:
    uint16_t irreduciblePoly_;
    
    Element multiplyByX(Element a) const;
    
public:
    explicit GaloisField(uint16_t irreduciblePoly = IrreduciblePolynomials::DEFAULT);
    
    uint16_t getPolynomial() const { return irreduciblePoly_; }
    
    static Element add(Element a, Element b) {
        return a ^ b;
    }
    
    static Element subtract(Element a, Element b) {
        return a ^ b;
    }
    
    Element multiply(Element a, Element b) const;
    
    Element divide(Element a, Element b) const;
    
    Element inverse(Element a) const;
    
    Element pow(Element a, int n) const;
};


inline GaloisField::Element multiply(GaloisField::Element a, GaloisField::Element b) {
    static thread_local GaloisField defaultField(IrreduciblePolynomials::DEFAULT);
    return defaultField.multiply(a, b);
}

inline GaloisField::Element divide(GaloisField::Element a, GaloisField::Element b) {
    static thread_local GaloisField defaultField(IrreduciblePolynomials::DEFAULT);
    return defaultField.divide(a, b);
}

inline GaloisField::Element inverse(GaloisField::Element a) {
    static thread_local GaloisField defaultField(IrreduciblePolynomials::DEFAULT);
    return defaultField.inverse(a);
}

inline GaloisField::Element pow(GaloisField::Element a, int n) {
    static thread_local GaloisField defaultField(IrreduciblePolynomials::DEFAULT);
    return defaultField.pow(a, n);
}

}
}

