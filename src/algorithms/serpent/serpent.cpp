// src/algorithms/serpent/serpent.cpp
// Базовая реализация Serpent (упрощенная версия)
#include "../../../include/crypto/algorithms/serpent/serpent.hpp"
#include "../../../include/crypto/core/exceptions.hpp"
#include <cstring>
#include <algorithm>

namespace crypto {
namespace serpent {

Serpent::Serpent(size_t keySize) : keySizeBytes_(keySize) {
    if (keySize != 16 && keySize != 24 && keySize != 32) {
        throw InvalidKeyException("Serpent key must be 16, 24, or 32 bytes");
    }
}

std::string Serpent::name() const {
    return "Serpent-" + std::to_string(keySizeBytes_ * 8);
}

void Serpent::setKey(const Key& key) {
    if (!isValidKey(key)) {
        throw InvalidKeyException("Invalid Serpent key size");
    }
    key_ = key;
    keySchedule(key.bytes(), key.size());
}

bool Serpent::isValidKey(const Key& key) const {
    size_t len = key.size();
    return len == 16 || len == 24 || len == 32;
}

uint32_t Serpent::rotateLeft(uint32_t x, int n) {
    n = n % 32;
    return (x << n) | (x >> (32 - n));
}

uint32_t Serpent::sBox(int boxIndex, uint32_t input) {
    // Упрощенные S-boxы для Serpent (базовая реализация)
    // В реальной реализации используются таблицы из спецификации
    static const uint8_t sboxes[8][16] = {
        {3, 8, 15, 1, 10, 6, 5, 11, 14, 13, 4, 2, 7, 0, 9, 12},
        {15, 12, 2, 7, 9, 0, 5, 10, 1, 11, 14, 8, 6, 13, 3, 4},
        {8, 6, 7, 9, 3, 12, 10, 15, 13, 1, 14, 4, 0, 11, 5, 2},
        {0, 15, 11, 8, 12, 9, 6, 3, 13, 1, 2, 4, 10, 7, 5, 14},
        {1, 15, 8, 3, 12, 0, 11, 6, 2, 5, 4, 10, 9, 14, 7, 13},
        {15, 5, 2, 11, 4, 10, 9, 12, 0, 3, 14, 8, 13, 6, 7, 1},
        {7, 2, 12, 5, 8, 4, 6, 11, 14, 9, 1, 15, 13, 3, 10, 0},
        {1, 13, 15, 0, 14, 8, 2, 11, 7, 4, 12, 10, 9, 3, 5, 6}
    };
    
    uint32_t result = 0;
    for (int i = 0; i < 4; ++i) {
        uint8_t nibble = (input >> (i * 4)) & 0xF;
        uint8_t outputNibble = sboxes[boxIndex % 8][nibble];
        result |= (static_cast<uint32_t>(outputNibble) << (i * 4));
    }
    return result;
}

uint32_t Serpent::invSBox(int boxIndex, uint32_t input) {
    // Обратные S-boxы - строим обратную таблицу для каждого S-box
    static const uint8_t sboxes[8][16] = {
        {3, 8, 15, 1, 10, 6, 5, 11, 14, 13, 4, 2, 7, 0, 9, 12},
        {15, 12, 2, 7, 9, 0, 5, 10, 1, 11, 14, 8, 6, 13, 3, 4},
        {8, 6, 7, 9, 3, 12, 10, 15, 13, 1, 14, 4, 0, 11, 5, 2},
        {0, 15, 11, 8, 12, 9, 6, 3, 13, 1, 2, 4, 10, 7, 5, 14},
        {1, 15, 8, 3, 12, 0, 11, 6, 2, 5, 4, 10, 9, 14, 7, 13},
        {15, 5, 2, 11, 4, 10, 9, 12, 0, 3, 14, 8, 13, 6, 7, 1},
        {7, 2, 12, 5, 8, 4, 6, 11, 14, 9, 1, 15, 13, 3, 10, 0},
        {1, 13, 15, 0, 14, 8, 2, 11, 7, 4, 12, 10, 9, 3, 5, 6}
    };
    
    // Строим обратную таблицу для данного S-box
    uint8_t invTable[16];
    const uint8_t* sbox = sboxes[boxIndex % 8];
    for (int i = 0; i < 16; ++i) {
        invTable[sbox[i]] = i;
    }
    
    uint32_t result = 0;
    for (int i = 0; i < 4; ++i) {
        uint8_t nibble = (input >> (i * 4)) & 0xF;
        uint8_t outputNibble = invTable[nibble];
        result |= (static_cast<uint32_t>(outputNibble) << (i * 4));
    }
    return result;
}

void Serpent::linearTransform(uint32_t* state) {
    // Линейное преобразование для Serpent
    state[0] = rotateLeft(state[0], 13);
    state[2] = rotateLeft(state[2], 3);
    state[1] = state[1] ^ state[0] ^ state[2];
    state[3] = state[3] ^ state[2] ^ (state[0] << 3);
    state[1] = rotateLeft(state[1], 1);
    state[3] = rotateLeft(state[3], 7);
    state[0] = state[0] ^ state[1] ^ state[3];
    state[2] = state[2] ^ state[3] ^ (state[1] << 7);
    state[0] = rotateLeft(state[0], 5);
    state[2] = rotateLeft(state[2], 22);
}

void Serpent::invLinearTransform(uint32_t* state) {
    // Обратное линейное преобразование
    state[2] = rotateLeft(state[2], 10);
    state[0] = rotateLeft(state[0], 27);
    state[2] = state[2] ^ state[3] ^ (state[1] << 7);
    state[0] = state[0] ^ state[1] ^ state[3];
    state[3] = rotateLeft(state[3], 25);
    state[1] = rotateLeft(state[1], 31);
    state[3] = state[3] ^ state[2] ^ (state[0] << 3);
    state[1] = state[1] ^ state[0] ^ state[2];
    state[2] = rotateLeft(state[2], 29);
    state[0] = rotateLeft(state[0], 19);
}

void Serpent::initialPermutation(uint32_t* block) {
    // Начальная перестановка битов (упрощенная)
    // В реальной реализации используется полная перестановка битов
}

void Serpent::finalPermutation(uint32_t* block) {
    // Конечная перестановка битов (обратная к начальной)
}

void Serpent::keySchedule(const Byte* key, size_t keyLength) {
    roundKeys_.clear();
    roundKeys_.resize(33 * 4); // 33 раунда, каждый использует 4 слова
    
    // Расширение ключа (упрощенная версия)
    std::vector<uint32_t> w(132);
    
    // Преобразуем ключ в массив 32-битных слов
    for (size_t i = 0; i < keyLength / 4; ++i) {
        w[i] = (static_cast<uint32_t>(key[4*i]) << 24) |
               (static_cast<uint32_t>(key[4*i+1]) << 16) |
               (static_cast<uint32_t>(key[4*i+2]) << 8) |
               static_cast<uint32_t>(key[4*i+3]);
    }
    
    // Дополняем до 8 слов
    if (keyLength < 32) {
        w[keyLength/4] = 1;
        for (size_t i = keyLength/4 + 1; i < 8; ++i) {
            w[i] = 0;
        }
    }
    
    // Генерируем остальные слова
    for (size_t i = 8; i < 132; ++i) {
        uint32_t temp = w[i-8] ^ w[i-5] ^ w[i-3] ^ w[i-1] ^ 0x9e3779b9 ^ static_cast<uint32_t>(i-8);
        w[i] = rotateLeft(temp, 11);
    }
    
    // Формируем раундовые ключи
    for (size_t i = 0; i < 33; ++i) {
        for (int j = 0; j < 4; ++j) {
            roundKeys_[i*4 + j] = w[i*4 + j];
        }
    }
}

void Serpent::encryptBlock(const Byte* input, Byte* output) {
    uint32_t block[4];
    
    // Преобразуем входной блок в массив 32-битных слов
    for (int i = 0; i < 4; ++i) {
        block[i] = (static_cast<uint32_t>(input[4*i]) << 24) |
                   (static_cast<uint32_t>(input[4*i+1]) << 16) |
                   (static_cast<uint32_t>(input[4*i+2]) << 8) |
                   static_cast<uint32_t>(input[4*i+3]);
    }
    
    initialPermutation(block);
    
    // Добавляем начальный ключ
    for (int i = 0; i < 4; ++i) {
        block[i] ^= roundKeys_[i];
    }
    
    // 32 раунда
    for (int round = 0; round < NUM_ROUNDS; ++round) {
        // S-box замена (используем S-box номер round % 8)
        for (int i = 0; i < 4; ++i) {
            block[i] = sBox(round % 8, block[i]);
        }
        
        // Линейное преобразование (кроме последнего раунда)
        if (round < NUM_ROUNDS - 1) {
            linearTransform(block);
        }
        
        // Добавляем раундовый ключ
        for (int i = 0; i < 4; ++i) {
            block[i] ^= roundKeys_[(round + 1) * 4 + i];
        }
    }
    
    finalPermutation(block);
    
    // Преобразуем обратно в байты
    for (int i = 0; i < 4; ++i) {
        output[4*i] = (block[i] >> 24) & 0xFF;
        output[4*i+1] = (block[i] >> 16) & 0xFF;
        output[4*i+2] = (block[i] >> 8) & 0xFF;
        output[4*i+3] = block[i] & 0xFF;
    }
}

void Serpent::decryptBlock(const Byte* input, Byte* output) {
    uint32_t block[4];
    
    // Преобразуем входной блок
    for (int i = 0; i < 4; ++i) {
        block[i] = (static_cast<uint32_t>(input[4*i]) << 24) |
                   (static_cast<uint32_t>(input[4*i+1]) << 16) |
                   (static_cast<uint32_t>(input[4*i+2]) << 8) |
                   static_cast<uint32_t>(input[4*i+3]);
    }
    
    // Обратная перестановка (финальная становится начальной при расшифровке)
    finalPermutation(block);
    
    // Обратные раунды (в обратном порядке от шифрования)
    // В шифровании: для каждого раунда: S-box -> Linear (если round < NUM_ROUNDS-1) -> AddRoundKey(round+1)
    // В расшифровке: для каждого раунда (обратный порядок): AddRoundKey(round+1) -> InvLinear (если round < NUM_ROUNDS-1) -> InvS-box
    for (int round = NUM_ROUNDS - 1; round >= 0; --round) {
        // Удаляем раундовый ключ
        for (int i = 0; i < 4; ++i) {
            block[i] ^= roundKeys_[(round + 1) * 4 + i];
        }
        
        // Обратное линейное преобразование
        // В шифровании Linear не применяется к последнему раунду (round == NUM_ROUNDS-1)
        // В расшифровке InvLinear не применяется к первому раунду в обратном порядке (round == NUM_ROUNDS-1)
        if (round < NUM_ROUNDS - 1) {
            invLinearTransform(block);
        }
        
        // Обратный S-box
        for (int i = 0; i < 4; ++i) {
            block[i] = invSBox(round % 8, block[i]);
        }
    }
    
    // Удаляем начальный ключ (раунд 0)
    for (int i = 0; i < 4; ++i) {
        block[i] ^= roundKeys_[0 * 4 + i];
    }
    
    // Обратная начальная перестановка
    initialPermutation(block);
    
    // Преобразуем обратно в байты
    for (int i = 0; i < 4; ++i) {
        output[4*i] = (block[i] >> 24) & 0xFF;
        output[4*i+1] = (block[i] >> 16) & 0xFF;
        output[4*i+2] = (block[i] >> 8) & 0xFF;
        output[4*i+3] = block[i] & 0xFF;
    }
}

} // namespace serpent
} // namespace crypto

