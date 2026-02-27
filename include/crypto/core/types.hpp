#pragma once
#include <vector>
#include <array>
#include <cstdint>
#include <memory>
#include <string>
#include "exceptions.hpp"

namespace crypto {

using Byte = uint8_t;
using ByteArray = std::vector<Byte>;

template<size_t N>
using Block = std::array<Byte, N>;

using Block128 = Block<16>; 
using Block64 = Block<8>;   
using Block32 = Block<4>;    

struct Key {
    ByteArray data;

    Key() = default;
    explicit Key(const ByteArray& d) : data(d) {}
    explicit Key(const std::string& hex);

    size_t size() const { return data.size(); }
    bool empty() const { return data.empty(); }

    const Byte* bytes() const { return data.data(); }
    Byte* bytes() { return data.data(); }

    std::string toHex() const;
    static Key fromHex(const std::string& hex);

};


constexpr size_t DES_BLOCK_SIZE = 8;            
constexpr size_t DES_KEY_SIZE = 8;              
constexpr size_t TRIPLE_DES_KEY_SIZE_2KEY = 16;  
constexpr size_t TRIPLE_DES_KEY_SIZE_3KEY = 24;  
constexpr size_t DEAL_BLOCK_SIZE = 16;           
constexpr size_t DEAL_KEY_SIZE = 16;             

}

