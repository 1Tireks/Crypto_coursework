// include/crypto/math/prime.hpp
#pragma once
#include <cstdint>
#include <vector>

namespace crypto {
namespace math {

// Простая проверка на простоту (тест Ферма для малых чисел)
bool isPrime(uint64_t n);

// Более надежная проверка (тест Миллера-Рабина)
bool isPrimeMillerRabin(uint64_t n, int k = 10);

// Генерация случайного простого числа заданной битовой длины
uint64_t generatePrime(uint64_t minBits = 16);

// Генерация простого числа в диапазоне
uint64_t generatePrimeInRange(uint64_t min, uint64_t max);

// Решето Эратосфена для малых чисел
std::vector<uint64_t> sieveOfEratosthenes(uint64_t limit);

} // namespace math
} // namespace crypto

