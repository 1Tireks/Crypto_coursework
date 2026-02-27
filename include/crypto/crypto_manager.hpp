#pragma once

#include "core/types.hpp"
#include "modes/mode.hpp"
#include "ciphers/block_cipher.hpp"
#include "padding/padding.hpp"
#include <memory>
#include <string>

namespace crypto {


class CryptoManager {
public:
    CryptoManager() = default;
    ~CryptoManager() = default;

    CryptoManager(const CryptoManager&) = delete;
    CryptoManager& operator=(const CryptoManager&) = delete;

    std::unique_ptr<IBlockCipherMode> createEncryptor(
        const std::string& algorithmName,
        const std::string& modeName,
        const std::string& paddingName,
        const Key& key,
        const ByteArray& iv = ByteArray());

    std::unique_ptr<IBlockCipherMode> createEncryptor(
        const std::string& algorithmName,
        CipherMode mode,
        PaddingType padding,
        const Key& key,
        const ByteArray& iv = ByteArray());

    Key generateKey(const std::string& algorithmName);

    Key generateKey(size_t keySize);

    ByteArray encryptString(
        const std::string& plaintext,
        const std::string& algorithmName,
        const std::string& modeName,
        const std::string& paddingName,
        const Key& key,
        const ByteArray& iv = ByteArray());

    std::string decryptString(
        const ByteArray& ciphertext,
        const std::string& algorithmName,
        const std::string& modeName,
        const std::string& paddingName,
        const Key& key,
        const ByteArray& iv = ByteArray());

    ByteArray encrypt(
        const ByteArray& plaintext,
        const std::string& algorithmName,
        const std::string& modeName,
        const std::string& paddingName,
        const Key& key,
        const ByteArray& iv = ByteArray());

    ByteArray decrypt(
        const ByteArray& ciphertext,
        const std::string& algorithmName,
        const std::string& modeName,
        const std::string& paddingName,
        const Key& key,
        const ByteArray& iv = ByteArray());

    bool isValidConfiguration(
        const std::string& algorithmName,
        const std::string& modeName,
        const std::string& paddingName) const;

    size_t getKeySize(const std::string& algorithmName) const;

    size_t getBlockSize(const std::string& algorithmName) const;

private:
    std::shared_ptr<IBlockCipher> createCipher(
        const std::string& algorithmName,
        const Key& key);

    CipherMode parseMode(const std::string& modeName) const;

    PaddingType parsePadding(const std::string& paddingName) const;
};

}

