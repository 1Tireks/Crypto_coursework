// include/crypto/modes/mode.hpp

#pragma once
#include "../ciphers/block_cipher.hpp"
#include "../padding/padding.hpp"
#include <memory>

namespace crypto {

enum class CipherMode {
    ECB,            // Electronic Codebook
    CBC,            // Cipher Block Chaining
    PCBC,           // Propagating Cipher Block Chaining
    CFB,            // Cipher Feedback
    OFB,            // Output Feedback
    CTR,            // Counter
    RANDOM_DELTA    // Random Delta
};

class IBlockCipherMode {
public:
    virtual ~IBlockCipherMode() = default;
    
    // Возвращает тип режима
    virtual CipherMode mode() const = 0;
    
    // Возвращает имя режима
    virtual std::string name() const = 0;
    
    // Устанавливает блочный шифр
    virtual void setCipher(std::shared_ptr<IBlockCipher> cipher) = 0;
    
    // Устанавливает схему дополнения
    virtual void setPadding(std::unique_ptr<IPadding> padding) = 0;
    
    // Проверяет, используется ли паддинг
    virtual bool usesPadding() const = 0;
    
    // Устанавливает вектор инициализации (IV)
    virtual void setIV(const ByteArray& iv) = 0;
    
    // Возвращает текущий IV
    virtual ByteArray getIV() const = 0;
    
    // Генерирует случайный IV
    virtual void generateRandomIV() = 0;
    
    // Шифрует данные
    virtual ByteArray encrypt(const ByteArray& plaintext) = 0;
    
    // Дешифрует данные
    virtual ByteArray decrypt(const ByteArray& ciphertext) = 0;
    
    // Шифрует данные (низкоуровневый интерфейс)
    virtual void encrypt(const Byte* input, Byte* output, size_t length) = 0;
    
    // Дешифрует данные (низкоуровневый интерфейс)
    virtual void decrypt(const Byte* input, Byte* output, size_t length) = 0;
    
    // Сбрасывает внутреннее состояние (для потоковых режимов)
    virtual void reset() = 0;
    
    // Фабричный метод для создания режимов
    static std::unique_ptr<IBlockCipherMode> create(
        CipherMode mode,
        std::shared_ptr<IBlockCipher> cipher,
        std::unique_ptr<IPadding> padding = nullptr,
        const ByteArray& iv = ByteArray()
    );
};

}