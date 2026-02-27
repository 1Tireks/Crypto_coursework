#pragma once
#include "galois_field.hpp"
#include <array>
#include <cstdint>

namespace crypto {
namespace rijndael {


class Polynomial {
public:
    static constexpr size_t DEGREE = 4;
    std::array<GaloisField::Element, DEGREE> coefficients;
    
    Polynomial();
    explicit Polynomial(const std::array<GaloisField::Element, DEGREE>& coeffs);
    
    
    Polynomial operator+(const Polynomial& other) const;
    Polynomial operator*(const Polynomial& other) const;
    Polynomial operator*(GaloisField::Element scalar) const;
    
    
    Polynomial multiplyMod(const Polynomial& other) const;
    
    
    GaloisField::Element evaluate(GaloisField::Element x) const;
};

}
}

