// include/crypto/math/modinv.hpp
#pragma once
#include <cstdint>

namespace crypto {
namespace math {

// Модульная инверсия: находит x такой, что (a * x) mod m = 1
// Использует расширенный алгоритм Евклида
uint64_t modinv(uint64_t a, uint64_t m);

// Для больших чисел (для BigInteger)
// Предполагаем, что BigInteger будет определен позже
// template<typename BigInt>
// BigInt modinv(const BigInt& a, const BigInt& m);

} // namespace math
} // namespace crypto

