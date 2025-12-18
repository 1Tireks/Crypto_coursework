// include/crypto/math/continued_fraction.hpp
#pragma once
#include <vector>
#include <cstdint>

namespace crypto {
namespace math {

// Вычисление цепной дроби для a/b
std::vector<uint64_t> continuedFraction(uint64_t a, uint64_t b);

// Вычисление подходящих дробей для цепной дроби
// Возвращает пары (p, q) где p/q - подходящие дроби
std::vector<std::pair<uint64_t, uint64_t>> convergents(const std::vector<uint64_t>& cf);

// Вычисление подходящих дробей напрямую из a/b
std::vector<std::pair<uint64_t, uint64_t>> convergentsFromFraction(uint64_t a, uint64_t b);

} // namespace math
} // namespace crypto

