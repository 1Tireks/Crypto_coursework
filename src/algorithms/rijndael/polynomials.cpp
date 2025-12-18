// src/algorithms/rijndael/polynomials.cpp
#include "../../../include/crypto/algorithms/rijndael/polynomials.hpp"

namespace crypto {
namespace rijndael {

using crypto::rijndael::multiply;

Polynomial::Polynomial() {
    coefficients.fill(0);
}

Polynomial::Polynomial(const std::array<GaloisField::Element, DEGREE>& coeffs)
    : coefficients(coeffs) {
}

Polynomial Polynomial::operator+(const Polynomial& other) const {
    Polynomial result;
    for (size_t i = 0; i < DEGREE; ++i) {
        result.coefficients[i] = GaloisField::add(coefficients[i], other.coefficients[i]);
    }
    return result;
}

Polynomial Polynomial::operator*(GaloisField::Element scalar) const {
    Polynomial result;
    for (size_t i = 0; i < DEGREE; ++i) {
        result.coefficients[i] = multiply(coefficients[i], scalar);
    }
    return result;
}

Polynomial Polynomial::operator*(const Polynomial& other) const {
    // Обычное умножение полиномов (до степени 6)
    std::array<GaloisField::Element, 7> temp{};
    
    for (size_t i = 0; i < DEGREE; ++i) {
        for (size_t j = 0; j < DEGREE; ++j) {
            temp[i + j] = GaloisField::add(
                temp[i + j],
                multiply(coefficients[i], other.coefficients[j])
            );
        }
    }
    
    Polynomial result;
    for (size_t i = 0; i < DEGREE; ++i) {
        result.coefficients[i] = temp[i];
    }
    
    return result;
}

Polynomial Polynomial::multiplyMod(const Polynomial& other) const {
    // Умножение по модулю x^4 + 1
    // В GF(2^8) x^4 = -1 = 1 (так как -1 = 1 в поле характеристики 2)
    Polynomial result;
    
    for (size_t i = 0; i < DEGREE; ++i) {
        for (size_t j = 0; j < DEGREE; ++j) {
            size_t index = (i + j) % DEGREE;
            result.coefficients[index] = GaloisField::add(
                result.coefficients[index],
                multiply(coefficients[i], other.coefficients[j])
            );
        }
    }
    
    return result;
}

GaloisField::Element Polynomial::evaluate(GaloisField::Element x) const {
    GaloisField::Element result = 0;
    GaloisField::Element x_power = 1;
    
    for (size_t i = 0; i < DEGREE; ++i) {
        result = GaloisField::add(result, multiply(coefficients[i], x_power));
        x_power = multiply(x_power, x);
    }
    
    return result;
}

} // namespace rijndael
} // namespace crypto

