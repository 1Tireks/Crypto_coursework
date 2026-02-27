#pragma once
#include "../core/types.hpp"
#include <cstddef>

namespace crypto {
namespace math {

ByteArray randomBytes(size_t count);

Key randomKey(size_t size);

}
}

