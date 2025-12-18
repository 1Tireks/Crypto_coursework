// include/crypto/modes/random_delta.hpp

#pragma once
#include "mode.hpp"

namespace crypto {

class RandomDeltaMode : public IBlockCipherMode {
private:
    std::shared_ptr<IBlockCipher> cipher_;
    std::unique_ptr<IPadding> padding_;
    ByteArray iv_;
    ByteArray delta_;
    bool usePadding_;
    size_t blockSize_;
    
public:
    RandomDeltaMode(std::shared_ptr<IBlockCipher> cipher, 
                    std::unique_ptr<IPadding> padding = nullptr);
    
    CipherMode mode() const override { return CipherMode::RANDOM_DELTA; }
    std::string name() const override { return "RandomDelta"; }
    
    void setCipher(std::shared_ptr<IBlockCipher> cipher) override;
    void setPadding(std::unique_ptr<IPadding> padding) override;
    bool usesPadding() const override { return usePadding_; }
    
    void setIV(const ByteArray& iv) override;
    ByteArray getIV() const override;
    void generateRandomIV() override;
    
    ByteArray encrypt(const ByteArray& plaintext) override;
    ByteArray decrypt(const ByteArray& ciphertext) override;
    
    void encrypt(const Byte* input, Byte* output, size_t length) override;
    void decrypt(const Byte* input, Byte* output, size_t length) override;
    
    void reset() override;
    
private:
    void generateDelta(size_t blockIndex);
};

}