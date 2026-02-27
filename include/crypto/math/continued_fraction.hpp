#pragma once
#include <vector>
#include <cstdint>

namespace crypto {
namespace math {

std::vector<uint64_t> continuedFraction(uint64_t a, uint64_t b);

std::vector<std::pair<uint64_t, uint64_t>> convergents(const std::vector<uint64_t>& cf);

std::vector<std::pair<uint64_t, uint64_t>> convergentsFromFraction(uint64_t a, uint64_t b);

}
}

