// include/crypto/modes/asymmetric_cipher_mode.hpp
#pragma once
#include "mode.hpp"
#include "../ciphers/asymmetric_cipher.hpp"
#include <memory>

namespace crypto {

/**
 * Адаптер для использования асимметричных шифров (IAsymmetricCipher) 
 * с системой режимов шифрования (IBlockCipherMode)
 * 
 * Асимметричные шифры работают с блоками фиксированного размера,
 * определяемым размером ключа. Паддинг обычно встроен в алгоритм (OAEP, PKCS#1).
 */
class AsymmetricCipherMode : public IBlockCipherMode {
private:
    std::shared_ptr<IAsymmetricCipher> cipher_;
    
public:
    explicit AsymmetricCipherMode(std::shared_ptr<IAsymmetricCipher> cipher);
    
    CipherMode mode() const override { return CipherMode::ECB; } // Асимметричные шифры работают как ECB
    std::string name() const override;
    
    void setCipher(std::shared_ptr<IBlockCipher> cipher) override;
    void setPadding(std::unique_ptr<IPadding> padding) override;
    bool usesPadding() const override { return false; } // Паддинг встроен в алгоритм
    
    void setIV(const ByteArray& iv) override; // Игнорируется для асимметричных шифров
    ByteArray getIV() const override { return ByteArray(); } // Асимметричные шифры не используют IV
    void generateRandomIV() override; // Игнорируется для асимметричных шифров
    
    ByteArray encrypt(const ByteArray& plaintext) override;
    ByteArray decrypt(const ByteArray& ciphertext) override;
    
    void encrypt(const Byte* input, Byte* output, size_t length) override;
    void decrypt(const Byte* input, Byte* output, size_t length) override;
    
    void reset() override;
    
    // Получить асимметричный шифр
    std::shared_ptr<IAsymmetricCipher> getAsymmetricCipher() const { return cipher_; }
};

} // namespace crypto

