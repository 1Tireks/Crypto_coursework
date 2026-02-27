#pragma once
#include <cstdint>
#include <vector>

namespace crypto {
namespace math {

bool isPrime(uint64_t n);

bool isPrimeMillerRabin(uint64_t n, int k = 10);

uint64_t generatePrime(uint64_t minBits = 16);

uint64_t generatePrimeInRange(uint64_t min, uint64_t max);

std::vector<uint64_t> sieveOfEratosthenes(uint64_t limit);

}
}

