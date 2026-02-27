#pragma once
#include "../../ciphers/block_cipher.hpp"
#include "../des/des.hpp"
#include <array>
#include <vector>

namespace crypto {

class DEAL : public IBlockCipher {
private:
    static constexpr size_t BLOCK_SIZE = 16;
    static constexpr size_t NUM_ROUNDS = 6;
    
    size_t keySize_;
    std::vector<DES> roundCiphers_;
    std::vector<ByteArray> roundKeys_;
    std::array<Block64, NUM_ROUNDS + 1> subkeys_;
    
    void keySchedule(const Byte* key, size_t keyLength);
    void generateSubkeys(const Byte* key, size_t keyLength);
    Block128 feistelNetwork(const Block128& block, bool encrypt);
    
public:
    DEAL(size_t keySize = 16);
    
    std::string name() const override { 
        return "DEAL-" + std::to_string(keySize_ * 8);
    }
    size_t blockSize() const override { return BLOCK_SIZE; }
    size_t keySize() const override { return keySize_; }
    
    void setKey(const Key& key) override;
    bool isValidKey(const Key& key) const override {
        size_t len = key.size();
        return len == 16 || len == 24 || len == 32;
    }
    
    void encryptBlock(const Byte* input, Byte* output) override;
    void decryptBlock(const Byte* input, Byte* output) override;
};

}