// include/crypto/algorithms/rijndael/rijndael.hpp
#pragma once
#include "../../ciphers/block_cipher.hpp"
#include "../../core/types.hpp"
#include "galois_field.hpp"
#include <vector>
#include <array>
#include <cstdint>

namespace crypto {
namespace rijndael {

enum class KeySize {
    AES128 = 128,  // 16 bytes
    AES192 = 192,  // 24 bytes
    AES256 = 256   // 32 bytes
};

enum class BlockSize {
    AES128_BLOCK = 128,  // 16 bytes
    AES192_BLOCK = 192,  // 24 bytes (редко используется)
    AES256_BLOCK = 256   // 32 bytes (редко используется)
};

class Rijndael : public IBlockCipher {
private:
    KeySize keySize_;
    BlockSize blockSize_;
    size_t numRounds_;
    size_t blockBytes_;
    size_t keyBytes_;
    Key key_;
    GaloisField galoisField_; // Поле Галуа с выбранным полиномом
    
    std::vector<uint32_t> roundKeys_;
    
    static constexpr size_t STATE_SIZE = 16; // 4x4 bytes для AES-128
    std::array<uint8_t, STATE_SIZE> state_;
    
    // Основные операции
    void subBytes();
    void invSubBytes();
    void shiftRows();
    void invShiftRows();
    void mixColumns();
    void invMixColumns();
    void addRoundKey(size_t round);
    
    // Расширение ключа
    void keyExpansion(const Byte* key);
    uint32_t subWord(uint32_t word);
    uint32_t rotWord(uint32_t word);
    
    // Преобразование между state и блоками
    void stateToBlock(Byte* block);
    void blockToState(const Byte* block);
    
public:
    // Конструктор с выбором неприводимого полинома
    Rijndael(KeySize keySize = KeySize::AES128, 
             BlockSize blockSize = BlockSize::AES128_BLOCK,
             uint16_t irreduciblePoly = IrreduciblePolynomials::DEFAULT);
    
    // Получить используемый полином
    uint16_t getIrreduciblePolynomial() const { return galoisField_.getPolynomial(); }
    
    std::string name() const override;
    size_t blockSize() const override;
    size_t keySize() const override;
    
    void setKey(const Key& key) override;
    bool isValidKey(const Key& key) const override;
    
    void encryptBlock(const Byte* input, Byte* output) override;
    void decryptBlock(const Byte* input, Byte* output) override;
};

} // namespace rijndael
} // namespace crypto

