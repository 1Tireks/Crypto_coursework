#pragma once
#include "mode.hpp"

namespace crypto {

class ECBMode : public IBlockCipherMode {
private:
    std::shared_ptr<IBlockCipher> cipher_;
    std::unique_ptr<IPadding> padding_;
    bool usePadding_;
    size_t blockSize_;
    
public:
    ECBMode(std::shared_ptr<IBlockCipher> cipher, 
            std::unique_ptr<IPadding> padding = nullptr);
    
    CipherMode mode() const override { return CipherMode::ECB; }
    std::string name() const override { return "ECB"; }
    
    void setCipher(std::shared_ptr<IBlockCipher> cipher) override;
    void setPadding(std::unique_ptr<IPadding> padding) override;
    bool usesPadding() const override { return usePadding_; }
    
    void setIV(const ByteArray&) override {}
    ByteArray getIV() const override { return ByteArray(); }
    void generateRandomIV() override {}
    
    ByteArray encrypt(const ByteArray& plaintext) override;
    ByteArray decrypt(const ByteArray& ciphertext) override;
    
    void encrypt(const Byte* input, Byte* output, size_t length) override;
    void decrypt(const Byte* input, Byte* output, size_t length) override;
    
    void reset() override {}
};

}