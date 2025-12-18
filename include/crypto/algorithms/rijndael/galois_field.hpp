// include/crypto/algorithms/rijndael/galois_field.hpp
#pragma once
#include <cstdint>
#include <array>

namespace crypto {
namespace rijndael {

/**
 * Все 30 неприводимых полиномов степени 8 над GF(2)
 * Каждый полином представлен в виде байта, где биты соответствуют коэффициентам
 * Например, 0x11B = x^8 + x^4 + x^3 + x + 1
 */
namespace IrreduciblePolynomials {
    // Список всех 30 неприводимых полиномов степени 8 над GF(2)
    static constexpr std::array<uint16_t, 30> ALL_POLYNOMIALS = {
        0x11B,  // x^8 + x^4 + x^3 + x + 1 (AES стандарт)
        0x11D,  // x^8 + x^4 + x^3 + x^2 + 1
        0x12B,  // x^8 + x^5 + x^3 + x + 1
        0x12D,  // x^8 + x^5 + x^3 + x^2 + 1
        0x139,  // x^8 + x^5 + x^4 + x^3 + 1
        0x13F,  // x^8 + x^5 + x^4 + x^3 + x^2 + x + 1
        0x14D,  // x^8 + x^6 + x^3 + x^2 + 1
        0x15F,  // x^8 + x^6 + x^4 + x^3 + x^2 + x + 1
        0x163,  // x^8 + x^6 + x^5 + x + 1
        0x165,  // x^8 + x^6 + x^5 + x^2 + 1
        0x169,  // x^8 + x^6 + x^5 + x^3 + 1
        0x171,  // x^8 + x^6 + x^5 + x^4 + 1
        0x177,  // x^8 + x^6 + x^5 + x^4 + x^2 + x + 1
        0x17B,  // x^8 + x^6 + x^5 + x^4 + x^3 + x + 1
        0x187,  // x^8 + x^7 + x^2 + x + 1
        0x18D,  // x^8 + x^7 + x^3 + x^2 + 1
        0x18F,  // x^8 + x^7 + x^3 + x^2 + x + 1
        0x195,  // x^8 + x^7 + x^4 + x^2 + 1
        0x199,  // x^8 + x^7 + x^4 + x^3 + 1
        0x1A3,  // x^8 + x^7 + x^5 + x + 1
        0x1A9,  // x^8 + x^7 + x^5 + x^3 + 1
        0x1B1,  // x^8 + x^7 + x^5 + x^4 + 1
        0x1BD,  // x^8 + x^7 + x^5 + x^4 + x^3 + x^2 + 1
        0x1C3,  // x^8 + x^7 + x^6 + x + 1
        0x1CF,  // x^8 + x^7 + x^6 + x^3 + x^2 + x + 1
        0x1D7,  // x^8 + x^7 + x^6 + x^4 + x^2 + x + 1
        0x1DD,  // x^8 + x^7 + x^6 + x^4 + x^3 + x^2 + 1
        0x1E7,  // x^8 + x^7 + x^6 + x^5 + x^2 + x + 1
        0x1F3,  // x^8 + x^7 + x^6 + x^5 + x^4 + x + 1
        0x1F5   // x^8 + x^7 + x^6 + x^5 + x^4 + x^2 + 1
    };
    
    // Полином по умолчанию (AES стандарт)
    static constexpr uint16_t DEFAULT = 0x11B;
    
    // Получить полином по индексу (0-29)
    static constexpr uint16_t getPolynomial(size_t index) {
        return (index < ALL_POLYNOMIALS.size()) ? ALL_POLYNOMIALS[index] : DEFAULT;
    }
    
    // Найти индекс полинома
    static size_t findIndex(uint16_t polynomial);
}

// Поле Галуа GF(2^8) для Rijndael
class GaloisField {
public:
    using Element = uint8_t;
    
private:
    uint16_t irreduciblePoly_; // Неприводимый полином (9 бит: x^8 + ...)
    
    // Умножение на x с учетом текущего полинома
    Element multiplyByX(Element a) const;
    
public:
    // Конструктор с выбором неприводимого полинома
    explicit GaloisField(uint16_t irreduciblePoly = IrreduciblePolynomials::DEFAULT);
    
    // Получить используемый полином
    uint16_t getPolynomial() const { return irreduciblePoly_; }
    
    // Сложение в GF(2^8) = XOR
    static Element add(Element a, Element b) {
        return a ^ b;
    }
    
    // Вычитание в GF(2^8) = XOR (то же, что сложение)
    static Element subtract(Element a, Element b) {
        return a ^ b;
    }
    
    // Умножение в GF(2^8)
    Element multiply(Element a, Element b) const;
    
    // Деление в GF(2^8)
    Element divide(Element a, Element b) const;
    
    // Обратный элемент в GF(2^8)
    Element inverse(Element a) const;
    
    // Возведение в степень
    Element pow(Element a, int n) const;
};

// Глобальные функции для обратной совместимости (используют DEFAULT полином)
// Эти функции используют полином по умолчанию (0x11B)
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

} // namespace rijndael
} // namespace crypto

