// include/crypto/crypto_manager.hpp

#pragma once

#include "core/types.hpp"
#include "modes/mode.hpp"
#include "ciphers/block_cipher.hpp"
#include "padding/padding.hpp"
#include <memory>
#include <string>

namespace crypto {

/**
 * CryptoManager - высокоуровневый менеджер для работы с криптографической библиотекой
 * 
 * Упрощает создание и использование шифров, режимов и паддингов
 */
class CryptoManager {
public:
    CryptoManager() = default;
    ~CryptoManager() = default;

    CryptoManager(const CryptoManager&) = delete;
    CryptoManager& operator=(const CryptoManager&) = delete;

    /**
     * Создает готовый к использованию шифр с указанными параметрами
     * 
     * @param algorithmName Имя алгоритма: "DES", "TripleDES", "DEAL"
     * @param modeName Имя режима: "ECB", "CBC", "PCBC", "CFB", "OFB", "CTR", "RandomDelta"
     * @param paddingName Имя паддинга: "PKCS7", "Zeros", "ANSI_X923", "ISO_10126" или "None"
     * @param key Ключ для шифрования
     * @param iv Вектор инициализации (опционально, для режимов, которые его требуют)
     * @return Готовый объект режима шифрования
     */
    std::unique_ptr<IBlockCipherMode> createEncryptor(
        const std::string& algorithmName,
        const std::string& modeName,
        const std::string& paddingName,
        const Key& key,
        const ByteArray& iv = ByteArray());

    // Создает шифр из enum значений
    std::unique_ptr<IBlockCipherMode> createEncryptor(
        const std::string& algorithmName,
        CipherMode mode,
        PaddingType padding,
        const Key& key,
        const ByteArray& iv = ByteArray());

    /**
     * Генерирует ключ для указанного алгоритма
     * 
     * @param algorithmName Имя алгоритма
     * @return Сгенерированный ключ
     */
    Key generateKey(const std::string& algorithmName);

    // Генерирует ключ указанного размера
    Key generateKey(size_t keySize);

    // Шифрует строку
    ByteArray encryptString(
        const std::string& plaintext,
        const std::string& algorithmName,
        const std::string& modeName,
        const std::string& paddingName,
        const Key& key,
        const ByteArray& iv = ByteArray());

    // Расшифровывает в строку
    std::string decryptString(
        const ByteArray& ciphertext,
        const std::string& algorithmName,
        const std::string& modeName,
        const std::string& paddingName,
        const Key& key,
        const ByteArray& iv = ByteArray());

    // Шифрует байтовый массив
    ByteArray encrypt(
        const ByteArray& plaintext,
        const std::string& algorithmName,
        const std::string& modeName,
        const std::string& paddingName,
        const Key& key,
        const ByteArray& iv = ByteArray());

    // Расшифровывает байтовый массив
    ByteArray decrypt(
        const ByteArray& ciphertext,
        const std::string& algorithmName,
        const std::string& modeName,
        const std::string& paddingName,
        const Key& key,
        const ByteArray& iv = ByteArray());

    // Проверяет совместимость алгоритма, режима и паддинга
    bool isValidConfiguration(
        const std::string& algorithmName,
        const std::string& modeName,
        const std::string& paddingName) const;

    // Возвращает рекомендуемый размер ключа для алгоритма
    size_t getKeySize(const std::string& algorithmName) const;

    // Возвращает размер блока для алгоритма
    size_t getBlockSize(const std::string& algorithmName) const;

private:
    // Создает блочный шифр по имени
    std::shared_ptr<IBlockCipher> createCipher(
        const std::string& algorithmName,
        const Key& key);

    // Преобразует строку в enum режима шифрования
    CipherMode parseMode(const std::string& modeName) const;

    // Преобразует строку в enum паддинга
    PaddingType parsePadding(const std::string& paddingName) const;
};

}

