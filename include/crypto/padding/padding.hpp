// include/crypto/padding/padding.hpp

#pragma once
#include "../core/types.hpp"
#include <memory>
#include <string>

namespace crypto {

enum class PaddingType {
    ZEROS,
    PKCS7,
    ANSI_X923,
    ISO_10126
};

class IPadding {
public:
    virtual ~IPadding() = default;
    
    virtual PaddingType type() const = 0;
    virtual std::string name() const = 0;
    
    virtual ByteArray pad(const ByteArray& data, size_t blockSize) = 0;
    virtual ByteArray unpad(const ByteArray& paddedData) const = 0;
    virtual bool validate(const ByteArray& paddedData) const = 0;
    
    static std::unique_ptr<IPadding> create(PaddingType type);
    static std::unique_ptr<IPadding> create(const std::string& name);
};

class ZeroPadding : public IPadding {
public:
    PaddingType type() const override { return PaddingType::ZEROS; }
    std::string name() const override { return "ZeroPadding"; }
    
    ByteArray pad(const ByteArray& data, size_t blockSize) override;
    ByteArray unpad(const ByteArray& paddedData) const override;
    bool validate(const ByteArray& paddedData) const override;
};

class PKCS7Padding : public IPadding {
public:
    PaddingType type() const override { return PaddingType::PKCS7; }
    std::string name() const override { return "PKCS7"; }
    
    ByteArray pad(const ByteArray& data, size_t blockSize) override;
    ByteArray unpad(const ByteArray& paddedData) const override;
    bool validate(const ByteArray& paddedData) const override;
};

class ANSIX923Padding : public IPadding {
public:
    PaddingType type() const override { return PaddingType::ANSI_X923; }
    std::string name() const override { return "ANSI X9.23"; }
    
    ByteArray pad(const ByteArray& data, size_t blockSize) override;
    ByteArray unpad(const ByteArray& paddedData) const override;
    bool validate(const ByteArray& paddedData) const override;
};

class ISO10126Padding : public IPadding {
public:
    PaddingType type() const override { return PaddingType::ISO_10126; }
    std::string name() const override { return "ISO 10126"; }
    
    ByteArray pad(const ByteArray& data, size_t blockSize) override;
    ByteArray unpad(const ByteArray& paddedData) const override;
    bool validate(const ByteArray& paddedData) const override;
};

inline std::unique_ptr<IPadding> IPadding::create(PaddingType type) {
    switch (type) {
        case PaddingType::ZEROS:
            return std::make_unique<ZeroPadding>();
        case PaddingType::PKCS7:
            return std::make_unique<PKCS7Padding>();
        case PaddingType::ANSI_X923:
            return std::make_unique<ANSIX923Padding>();
        case PaddingType::ISO_10126:
            return std::make_unique<ISO10126Padding>();
        default:
            throw PaddingException("Unknown padding type");
    }
}

inline std::unique_ptr<IPadding> IPadding::create(const std::string& name) {
    if (name == "ZeroPadding" || name == "ZEROS" || name == "zeros") {
        return std::make_unique<ZeroPadding>();
    }
    if (name == "PKCS7" || name == "pkcs7") {
        return std::make_unique<PKCS7Padding>();
    }
    if (name == "ANSI_X923" || name == "ANSI X9.23") {
        return std::make_unique<ANSIX923Padding>();
    }
    if (name == "ISO_10126" || name == "ISO 10126") {
        return std::make_unique<ISO10126Padding>();
    }
    throw PaddingException("Unknown padding name: " + name);
}

}