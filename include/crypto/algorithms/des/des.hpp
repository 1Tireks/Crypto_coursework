// include/crypto/algorithms/des/des.hpp

#pragma once
#include "../../ciphers/block_cipher.hpp"
#include "des_constants.hpp"

namespace crypto {

class DES : public IBlockCipher {
private:
    static constexpr size_t BLOCK_SIZE = 8;
    static constexpr size_t KEY_SIZE = 8;
    static constexpr size_t NUM_ROUNDS = 16;
    
    ByteArray key_;
    uint64_t roundKeys_[NUM_ROUNDS];
    
    void generateRoundKeys(const Byte* key);
    uint32_t feistelFunction(uint32_t right, uint64_t roundKey);
    
    static uint64_t permute(const uint8_t* table, size_t tableSize, 
                           uint64_t input, size_t inputBits);
    static uint32_t sBoxSubstitution(uint64_t input);
    
public:
    DES();
    
    std::string name() const override { return "DES"; }
    size_t blockSize() const override { return BLOCK_SIZE; }
    size_t keySize() const override { return KEY_SIZE; }
    
    void setKey(const Key& key) override;
    bool isValidKey(const Key& key) const override {
        return key.size() == KEY_SIZE;
    }
    
    void encryptBlock(const Byte* input, Byte* output) override;
    void decryptBlock(const Byte* input, Byte* output) override;
    
    const uint64_t* getRoundKeys() const { return roundKeys_; }
};

}