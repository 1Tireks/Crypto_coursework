
#include "../../include/crypto/math/random.hpp"
#include <random>

namespace crypto {
namespace math {

ByteArray randomBytes(size_t count) {
    ByteArray result(count);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    
    for (size_t i = 0; i < count; ++i) {
        result[i] = static_cast<Byte>(dis(gen));
    }
    
    return result;
}

Key randomKey(size_t size) {
    return Key(randomBytes(size));
}

}
}

