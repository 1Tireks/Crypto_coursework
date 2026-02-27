#pragma once
#include "mode.hpp"

namespace crypto {

class CFBMode : public IBlockCipherMode {
private:
    std::shared_ptr<IBlockCipher> cipher_;
    std::unique_ptr<IPadding> padding_;
    ByteArray iv_;
    ByteArray feedback_;
    bool usePadding_;
    size_t blockSize_;
    size_t segmentSize_;
    
public:
    CFBMode(std::shared_ptr<IBlockCipher> cipher, 
            std::unique_ptr<IPadding> padding = nullptr,
            size_t segmentSizeBits = 0);
    
    CipherMode mode() const override { return CipherMode::CFB; }
    std::string name() const override { 
        return "CFB-" + std::to_string(segmentSize_ * 8);
    }
    
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
};

}