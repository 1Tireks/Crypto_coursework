#pragma once
#include "../ciphers/block_cipher.hpp"
#include "../padding/padding.hpp"
#include <memory>

namespace crypto {

enum class CipherMode {
    ECB,
    CBC,
    PCBC,
    CFB,
    OFB,
    CTR,
    RANDOM_DELTA
};

class IBlockCipherMode {
public:
    virtual ~IBlockCipherMode() = default;
    
    virtual CipherMode mode() const = 0;
    
    virtual std::string name() const = 0;
    
    virtual void setCipher(std::shared_ptr<IBlockCipher> cipher) = 0;
    
    virtual void setPadding(std::unique_ptr<IPadding> padding) = 0;

    virtual bool usesPadding() const = 0;

    virtual void setIV(const ByteArray& iv) = 0;
    
    virtual ByteArray getIV() const = 0;
    
    virtual void generateRandomIV() = 0;
    
    virtual ByteArray encrypt(const ByteArray& plaintext) = 0;
    
    virtual ByteArray decrypt(const ByteArray& ciphertext) = 0;
    
    virtual void encrypt(const Byte* input, Byte* output, size_t length) = 0;
    
    virtual void decrypt(const Byte* input, Byte* output, size_t length) = 0;
    
    virtual void reset() = 0;
    
    static std::unique_ptr<IBlockCipherMode> create(
        CipherMode mode,
        std::shared_ptr<IBlockCipher> cipher,
        std::unique_ptr<IPadding> padding = nullptr,
        const ByteArray& iv = ByteArray()
    );
};

}