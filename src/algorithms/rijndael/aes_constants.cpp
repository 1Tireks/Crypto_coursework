// src/algorithms/rijndael/aes_constants.cpp
// Генерация констант AES

#include "../../../include/crypto/algorithms/rijndael/aes_constants.hpp"
#include "../../../include/crypto/algorithms/rijndael/galois_field.hpp"

namespace crypto {
namespace rijndael {

using crypto::rijndael::multiply;
using crypto::rijndael::inverse;

// S-box генерируется на основе обратного элемента в GF(2^8) и аффинного преобразования
uint8_t S_BOX[256] = {0};
uint8_t INV_S_BOX[256] = {0};
uint32_t RCON[10] = {0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000,
                     0x20000000, 0x40000000, 0x80000000, 0x1b000000, 0x36000000};

uint8_t MULT_2[256] = {0};
uint8_t MULT_3[256] = {0};
uint8_t MULT_9[256] = {0};
uint8_t MULT_11[256] = {0};
uint8_t MULT_13[256] = {0};
uint8_t MULT_14[256] = {0};

// Аффинное преобразование для S-box
static uint8_t affineTransform(uint8_t x) {
    // Упрощенная версия - используем стандартную таблицу
    // В реальной реализации это матричное умножение + XOR с константой
    static const uint8_t affine_matrix[8] = {0xF1, 0xE3, 0xC7, 0x8F, 0x1F, 0x3E, 0x7C, 0xF8};
    uint8_t result = 0;
    uint8_t c = 0x63;
    
    for (int i = 0; i < 8; ++i) {
        uint8_t bit = 0;
        for (int j = 0; j < 8; ++j) {
            if ((x >> j) & 1) {
                bit ^= ((affine_matrix[i] >> (7 - j)) & 1);
            }
        }
        result |= (bit ^ ((c >> i) & 1)) << i;
    }
    
    return result;
}

void initializeSBoxes() {
    // Инициализация S-box
    S_BOX[0] = 0x63; // 0 обращается в 0x63
    for (int i = 1; i < 256; ++i) {
        uint8_t inv = inverse(static_cast<uint8_t>(i));
        S_BOX[i] = affineTransform(inv);
    }
    
    // Обратный S-box
    for (int i = 0; i < 256; ++i) {
        INV_S_BOX[S_BOX[i]] = static_cast<uint8_t>(i);
    }
    
    // Таблицы умножения
    for (int i = 0; i < 256; ++i) {
        MULT_2[i] = multiply(static_cast<uint8_t>(i), 2);
        MULT_3[i] = multiply(static_cast<uint8_t>(i), 3);
        MULT_9[i] = multiply(static_cast<uint8_t>(i), 9);
        MULT_11[i] = multiply(static_cast<uint8_t>(i), 11);
        MULT_13[i] = multiply(static_cast<uint8_t>(i), 13);
        MULT_14[i] = multiply(static_cast<uint8_t>(i), 14);
    }
}

// Статическая инициализация при загрузке модуля
static struct SBoxInitializer {
    SBoxInitializer() {
        initializeSBoxes();
    }
} sbox_init;

} // namespace rijndael
} // namespace crypto

