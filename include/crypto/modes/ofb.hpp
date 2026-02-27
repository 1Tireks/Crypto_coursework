#pragma once
#include "mode.hpp"

namespace crypto {

class OFBMode : public IBlockCipherMode {
private:
    std::shared_ptr<IBlockCipher> cipher_;
    std::unique_ptr<IPadding> padding_;
    ByteArray iv_;
    ByteArray keystream_;
    size_t keystreamPos_;
    bool usePadding_;
    size_t blockSize_;
    
public:
    OFBMode(std::shared_ptr<IBlockCipher> cipher, 
            std::unique_ptr<IPadding> padding = nullptr);
    
    CipherMode mode() const override { return CipherMode::OFB; }
    std::string name() const override { return "OFB"; }
    
    void setCipher(std::shared_ptr<IBlockCipher> cipher) override;
    void setPadding(std::unique_ptr<IPadding> padding) override;
    bool usesPadding() const override { return false; }
    
    void setIV(const ByteArray& iv) override;
    ByteArray getIV() const override;
    void generateRandomIV() override;
    
    ByteArray encrypt(const ByteArray& plaintext) override;
    ByteArray decrypt(const ByteArray& ciphertext) override;
    
    void encrypt(const Byte* input, Byte* output, size_t length) override;
    void decrypt(const Byte* input, Byte* output, size_t length) override;
    
    void reset() override;
    
private:
    void generateKeystream();
    void generateMoreKeystream();
};

}