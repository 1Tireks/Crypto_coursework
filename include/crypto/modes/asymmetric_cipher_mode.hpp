#pragma once
#include "mode.hpp"
#include "../ciphers/asymmetric_cipher.hpp"
#include <memory>

namespace crypto {

class AsymmetricCipherMode : public IBlockCipherMode {
private:
    std::shared_ptr<IAsymmetricCipher> cipher_;
    
public:
    explicit AsymmetricCipherMode(std::shared_ptr<IAsymmetricCipher> cipher);
    
    CipherMode mode() const override { return CipherMode::ECB; }
    std::string name() const override;
    
    void setCipher(std::shared_ptr<IBlockCipher> cipher) override;
    void setPadding(std::unique_ptr<IPadding> padding) override;
    bool usesPadding() const override { return false; }
    
    void setIV(const ByteArray& iv) override;
    ByteArray getIV() const override { return ByteArray(); }
    void generateRandomIV() override;
    
    ByteArray encrypt(const ByteArray& plaintext) override;
    ByteArray decrypt(const ByteArray& ciphertext) override;
    
    void encrypt(const Byte* input, Byte* output, size_t length) override;
    void decrypt(const Byte* input, Byte* output, size_t length) override;
    
    void reset() override;
    
    std::shared_ptr<IAsymmetricCipher> getAsymmetricCipher() const { return cipher_; }
};

}

