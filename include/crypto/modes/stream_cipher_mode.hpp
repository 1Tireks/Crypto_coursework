// include/crypto/modes/stream_cipher_mode.hpp
#pragma once
#include "mode.hpp"
#include "../ciphers/stream_cipher.hpp"
#include <memory>

namespace crypto {

/**
 * Адаптер для использования потоковых шифров (IStreamCipher) 
 * с системой режимов шифрования (IBlockCipherMode)
 * 
 * Потоковые шифры не требуют паддинга и IV, так как они работают
 * с данными произвольного размера побайтово.
 */
class StreamCipherMode : public IBlockCipherMode {
private:
    std::shared_ptr<IStreamCipher> cipher_;
    
public:
    explicit StreamCipherMode(std::shared_ptr<IStreamCipher> cipher);
    
    CipherMode mode() const override { return CipherMode::ECB; } // Потоковые шифры работают как ECB
    std::string name() const override;
    
    void setCipher(std::shared_ptr<IBlockCipher> cipher) override;
    void setPadding(std::unique_ptr<IPadding> padding) override;
    bool usesPadding() const override { return false; } // Потоковые шифры не используют паддинг
    
    void setIV(const ByteArray& iv) override; // Игнорируется для потоковых шифров
    ByteArray getIV() const override { return ByteArray(); } // Потоковые шифры не используют IV
    void generateRandomIV() override; // Игнорируется для потоковых шифров
    
    ByteArray encrypt(const ByteArray& plaintext) override;
    ByteArray decrypt(const ByteArray& ciphertext) override;
    
    void encrypt(const Byte* input, Byte* output, size_t length) override;
    void decrypt(const Byte* input, Byte* output, size_t length) override;
    
    void reset() override;
    
    // Получить потоковый шифр
    std::shared_ptr<IStreamCipher> getStreamCipher() const { return cipher_; }
};

} // namespace crypto

