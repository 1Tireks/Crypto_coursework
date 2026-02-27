#pragma once
#include "../../ciphers/block_cipher.hpp"
#include "des.hpp"

namespace crypto {

enum class TripleDESMode {
    EDE,
    EEE
};

class TripleDES : public IBlockCipher {
private:
    static constexpr size_t BLOCK_SIZE = 8;
    
    TripleDESMode mode_;
    DES des1_, des2_, des3_;
    bool useTwoKeys_;
    
public:
    TripleDES(TripleDESMode mode = TripleDESMode::EDE);
    
    std::string name() const override { 
        return "TripleDES" + std::string(mode_ == TripleDESMode::EDE ? "-EDE" : "-EEE");
    }
    size_t blockSize() const override { return BLOCK_SIZE; }
    size_t keySize() const override { 
        return useTwoKeys_ ? 16 : 24;
    }

    void setKey(const Key& key) override;
    bool isValidKey(const Key& key) const override {
        return key.size() == 16 || key.size() == 24;
    }
    
    void encryptBlock(const Byte* input, Byte* output) override;
    void decryptBlock(const Byte* input, Byte* output) override;
    
private:
    void setupKeys(const Byte* key, size_t keyLength);
};

}