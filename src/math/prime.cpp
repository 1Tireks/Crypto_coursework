
#include "../../include/crypto/math/prime.hpp"
#include "../../include/crypto/core/utils.hpp"
#include <random>
#include <cmath>
#include <algorithm>
#include <cassert>

namespace crypto {
namespace math {

bool isPrime(uint64_t n) {
    if (n < 2) return false;
    if (n == 2 || n == 3) return true;
    if (n % 2 == 0 || n % 3 == 0) return false;
    
    for (uint64_t i = 5; i * i <= n; i += 6) {
        if (n % i == 0 || n % (i + 2) == 0) {
            return false;
        }
    }
    return true;
}

static uint64_t modPow(uint64_t base, uint64_t exp, uint64_t mod) {
    uint64_t result = 1;
    base = base % mod;
    while (exp > 0) {
        if (exp % 2 == 1) {
            result = (result * base) % mod;
        }
        exp = exp >> 1;
        base = (base * base) % mod;
    }
    return result;
}

bool isPrimeMillerRabin(uint64_t n, int k) {
    if (n < 2) return false;
    if (n == 2 || n == 3) return true;
    if (n % 2 == 0) return false;
    
    uint64_t d = n - 1;
    int r = 0;
    while (d % 2 == 0) {
        d /= 2;
        r++;
    }
    
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint64_t> dis(2, n - 2);
    
    for (int i = 0; i < k; ++i) {
        uint64_t a = dis(gen);
        uint64_t x = modPow(a, d, n);
        
        if (x == 1 || x == n - 1) {
            continue;
        }
        
        bool composite = true;
        for (int j = 0; j < r - 1; ++j) {
            x = (x * x) % n;
            if (x == n - 1) {
                composite = false;
                break;
            }
        }
        
        if (composite) {
            return false;
        }
    }
    
    return true;
}

uint64_t generatePrime(uint64_t minBits) {
    if (minBits > 32) {
        minBits = 32;
    }
    
    uint64_t min = 1ULL << (minBits - 1);
    uint64_t max = (minBits == 64) ? UINT64_MAX : ((1ULL << minBits) - 1);
    
    return generatePrimeInRange(min, max);
}

uint64_t generatePrimeInRange(uint64_t min, uint64_t max) {
    if (min > max) {
        std::swap(min, max);
    }
    
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint64_t> dis(min, max);
    
    if (min % 2 == 0) min++;
    
    for (int attempts = 0; attempts < 10000; ++attempts) {
        uint64_t candidate = dis(gen);
        if (candidate % 2 == 0) {
            candidate++;
        }
        
        if (candidate > max) {
            candidate = min + (candidate % (max - min + 1));
            if (candidate % 2 == 0) candidate++;
        }
        
        if (isPrimeMillerRabin(candidate)) {
            return candidate;
        }
    }
    
    for (uint64_t n = min; n <= max; n += 2) {
        if (isPrimeMillerRabin(n)) {
            return n;
        }
    }
    
    throw CryptoException("Could not generate prime in range");
}

std::vector<uint64_t> sieveOfEratosthenes(uint64_t limit) {
    if (limit < 2) return {};
    
    std::vector<bool> isPrime(limit + 1, true);
    isPrime[0] = isPrime[1] = false;
    
    for (uint64_t i = 2; i * i <= limit; ++i) {
        if (isPrime[i]) {
            for (uint64_t j = i * i; j <= limit; j += i) {
                isPrime[j] = false;
            }
        }
    }
    
    std::vector<uint64_t> primes;
    for (uint64_t i = 2; i <= limit; ++i) {
        if (isPrime[i]) {
            primes.push_back(i);
        }
    }
    
    return primes;
}

}
}

