#pragma once
#include "../core/types.hpp"

namespace crypto {

class ICipher {
public:
    virtual ~ICipher() = default;
    
    virtual std::string name() const = 0;
    
    virtual size_t blockSize() const = 0;
    
    virtual size_t keySize() const = 0;
    
    virtual void setKey(const Key& key) = 0;
    
    virtual bool isValidKey(const Key& key) const = 0;
};

}