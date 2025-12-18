// src/math/continued_fraction.cpp
#include "../../include/crypto/math/continued_fraction.hpp"
#include <algorithm>

namespace crypto {
namespace math {

std::vector<uint64_t> continuedFraction(uint64_t a, uint64_t b) {
    std::vector<uint64_t> result;
    
    if (b == 0) {
        return result;
    }
    
    while (b != 0) {
        uint64_t q = a / b;
        result.push_back(q);
        
        uint64_t temp = b;
        b = a % b;
        a = temp;
    }
    
    return result;
}

std::vector<std::pair<uint64_t, uint64_t>> convergents(const std::vector<uint64_t>& cf) {
    std::vector<std::pair<uint64_t, uint64_t>> result;
    
    if (cf.empty()) {
        return result;
    }
    
    // Первая подходящая дробь
    uint64_t h0 = 1, h1 = cf[0];
    uint64_t k0 = 0, k1 = 1;
    
    result.push_back({h1, k1});
    
    // Вычисляем остальные подходящие дроби
    for (size_t i = 1; i < cf.size(); ++i) {
        uint64_t h2 = cf[i] * h1 + h0;
        uint64_t k2 = cf[i] * k1 + k0;
        
        result.push_back({h2, k2});
        
        h0 = h1;
        h1 = h2;
        k0 = k1;
        k1 = k2;
    }
    
    return result;
}

std::vector<std::pair<uint64_t, uint64_t>> convergentsFromFraction(uint64_t a, uint64_t b) {
    std::vector<uint64_t> cf = continuedFraction(a, b);
    return convergents(cf);
}

} // namespace math
} // namespace crypto

