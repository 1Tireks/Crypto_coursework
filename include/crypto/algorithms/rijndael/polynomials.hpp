// include/crypto/algorithms/rijndael/polynomials.hpp
#pragma once
#include "galois_field.hpp"
#include <array>
#include <cstdint>

namespace crypto {
namespace rijndael {

// Полином над GF(2^8) степени до 3 (для Rijndael)
class Polynomial {
public:
    static constexpr size_t DEGREE = 4; // x^3, x^2, x^1, x^0
    std::array<GaloisField::Element, DEGREE> coefficients;
    
    Polynomial();
    explicit Polynomial(const std::array<GaloisField::Element, DEGREE>& coeffs);
    
    // Арифметические операции
    Polynomial operator+(const Polynomial& other) const;
    Polynomial operator*(const Polynomial& other) const;
    Polynomial operator*(GaloisField::Element scalar) const;
    
    // Умножение по модулю неприводимого полинома x^4 + 1
    Polynomial multiplyMod(const Polynomial& other) const;
    
    // Вычисление значения полинома
    GaloisField::Element evaluate(GaloisField::Element x) const;
};

} // namespace rijndael
} // namespace crypto

