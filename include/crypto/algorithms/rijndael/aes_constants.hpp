// include/crypto/algorithms/rijndael/aes_constants.hpp
#pragma once
#include <cstdint>

namespace crypto {
namespace rijndael {

// S-box для AES (не const, так как инициализируется динамически)
extern uint8_t S_BOX[256];
extern uint8_t INV_S_BOX[256];

// Round constants для расширения ключа
extern uint32_t RCON[10];

// Генерация S-box (вычисляется один раз)
void initializeSBoxes();

// Таблица умножения для MixColumns
extern uint8_t MULT_2[256];
extern uint8_t MULT_3[256];
extern uint8_t MULT_9[256];
extern uint8_t MULT_11[256];
extern uint8_t MULT_13[256];
extern uint8_t MULT_14[256];

} // namespace rijndael
} // namespace crypto

