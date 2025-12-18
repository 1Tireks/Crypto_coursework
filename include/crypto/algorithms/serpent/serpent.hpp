// include/crypto/algorithms/serpent/serpent.hpp
#pragma once
#include "../../ciphers/block_cipher.hpp"
#include "../../core/types.hpp"
#include <array>
#include <cstdint>
#include <vector>

namespace crypto {
namespace serpent {

class Serpent : public IBlockCipher {
private:
    static constexpr size_t BLOCK_SIZE = 16; // 128 бит
    static constexpr size_t NUM_ROUNDS = 32;
    
    size_t keySizeBytes_;
    Key key_;
    std::vector<uint32_t> roundKeys_;
    
    // S-boxes для Serpent (8 различных S-boxов)
    static uint32_t sBox(int boxIndex, uint32_t input);
    static uint32_t invSBox(int boxIndex, uint32_t input);
    
    // Линейное преобразование
    static void linearTransform(uint32_t* state);
    static void invLinearTransform(uint32_t* state);
    
    // Начальная и конечная перестановки
    static void initialPermutation(uint32_t* block);
    static void finalPermutation(uint32_t* block);
    
    // Расширение ключа
    void keySchedule(const Byte* key, size_t keyLength);
    static uint32_t rotateLeft(uint32_t x, int n);
    
public:
    explicit Serpent(size_t keySize = 32); // По умолчанию 256 бит (32 байта)
    
    std::string name() const override;
    size_t blockSize() const override { return BLOCK_SIZE; }
    size_t keySize() const override { return keySizeBytes_; }
    
    void setKey(const Key& key) override;
    bool isValidKey(const Key& key) const override;
    
    void encryptBlock(const Byte* input, Byte* output) override;
    void decryptBlock(const Byte* input, Byte* output) override;
};

} // namespace serpent
} // namespace crypto

