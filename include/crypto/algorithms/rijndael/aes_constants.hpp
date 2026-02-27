#pragma once
#include <cstdint>

namespace crypto {
namespace rijndael {

extern uint8_t S_BOX[256];
extern uint8_t INV_S_BOX[256];

extern uint32_t RCON[10];

void initializeSBoxes();

extern uint8_t MULT_2[256];
extern uint8_t MULT_3[256];
extern uint8_t MULT_9[256];
extern uint8_t MULT_11[256];
extern uint8_t MULT_13[256];
extern uint8_t MULT_14[256];

}
}

