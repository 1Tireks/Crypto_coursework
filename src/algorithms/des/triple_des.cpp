#include "../../../include/crypto/algorithms/des/triple_des.hpp"
#include "../../../include/crypto/core/utils.hpp"

namespace crypto {

TripleDES::TripleDES(TripleDESMode mode) : mode_(mode), useTwoKeys_(false) {}

void TripleDES::setKey(const Key& key) {
    if (!isValidKey(key)) {
        throw InvalidKeyException("TripleDES requires 16-byte (2-key) or 24-byte (3-key) key");
    }
    
    useTwoKeys_ = (key.size() == 16);
    setupKeys(key.bytes(), key.size());
}

void TripleDES::setupKeys(const Byte* key, size_t keyLength) {
    Key key1, key2, key3;
    
    if (useTwoKeys_) {
        key1 = Key(ByteArray(key, key + 8));
        key2 = Key(ByteArray(key + 8, key + 16));
        key3 = key1;
    } else {
        key1 = Key(ByteArray(key, key + 8));
        key2 = Key(ByteArray(key + 8, key + 16));
        key3 = Key(ByteArray(key + 16, key + 24));
    }
    
    des1_.setKey(key1);
    des2_.setKey(key2);
    des3_.setKey(key3);
}

void TripleDES::encryptBlock(const Byte* input, Byte* output) {
    Byte intermediate[8];
    
    switch (mode_) {
        case TripleDESMode::EDE:
            
            des1_.encryptBlock(input, intermediate);
            
            des2_.decryptBlock(intermediate, intermediate);
            
            des3_.encryptBlock(intermediate, output);
            break;
            
        case TripleDESMode::EEE:
            des1_.encryptBlock(input, intermediate);
            des2_.encryptBlock(intermediate, intermediate);
            des3_.encryptBlock(intermediate, output);
            break;
    }
}

void TripleDES::decryptBlock(const Byte* input, Byte* output) {
    Byte intermediate[8];
    
    switch (mode_) {
        case TripleDESMode::EDE:
            
            des3_.decryptBlock(input, intermediate);
            
            des2_.encryptBlock(intermediate, intermediate);
            
            des1_.decryptBlock(intermediate, output);
            break;
            
        case TripleDESMode::EEE:
            des3_.decryptBlock(input, intermediate);
            des2_.decryptBlock(intermediate, intermediate);
            des1_.decryptBlock(intermediate, output);
            break;
    }
}

}