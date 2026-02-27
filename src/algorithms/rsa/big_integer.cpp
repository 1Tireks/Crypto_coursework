#include "../../../include/crypto/algorithms/rsa/big_integer.hpp"
#include "../../../include/crypto/core/exceptions.hpp"
#include <algorithm>
#include <climits>
#include <cstring>
#include <random>

namespace crypto {
namespace rsa {

BigInteger::BigInteger() : negative_(false) {
    digits_.push_back(0);
}

BigInteger::BigInteger(int64_t value) : negative_(value < 0) {
    uint64_t absValue = static_cast<uint64_t>(value < 0 ? -value : value);
    if (absValue == 0) {
        digits_.push_back(0);
    } else {
        while (absValue > 0) {
            digits_.push_back(static_cast<uint32_t>(absValue & 0xFFFFFFFF));
            absValue >>= 32;
        }
    }
}

BigInteger::BigInteger(const BigInteger& other) 
    : digits_(other.digits_), negative_(other.negative_) {
}

BigInteger& BigInteger::operator=(const BigInteger& other) {
    if (this != &other) {
        digits_ = other.digits_;
        negative_ = other.negative_;
    }
    return *this;
}

void BigInteger::normalize() {
    removeLeadingZeros();
    if (digits_.size() == 1 && digits_[0] == 0) {
        negative_ = false;
    }
}

void BigInteger::removeLeadingZeros() {
    while (digits_.size() > 1 && digits_.back() == 0) {
        digits_.pop_back();
    }
}

bool BigInteger::isZero() const {
    return digits_.size() == 1 && digits_[0] == 0;
}

bool BigInteger::isOne() const {
    return !negative_ && digits_.size() == 1 && digits_[0] == 1;
}

bool BigInteger::isEven() const {
    return digits_.empty() || (digits_[0] & 1) == 0;
}

int BigInteger::sign() const {
    if (isZero()) return 0;
    return negative_ ? -1 : 1;
}

size_t BigInteger::bitLength() const {
    if (isZero()) return 0;
    
    size_t result = (digits_.size() - 1) * 32;
    uint32_t top = digits_.back();
    
    while (top > 0) {
        result++;
        top >>= 1;
    }
    
    return result;
}

bool BigInteger::operator==(const BigInteger& other) const {
    return negative_ == other.negative_ && digits_ == other.digits_;
}

bool BigInteger::operator!=(const BigInteger& other) const {
    return !(*this == other);
}

int BigInteger::compareAbsolute(const BigInteger& other) const {
    if (digits_.size() < other.digits_.size()) return -1;
    if (digits_.size() > other.digits_.size()) return 1;
    
    for (int i = static_cast<int>(digits_.size()) - 1; i >= 0; --i) {
        if (digits_[i] < other.digits_[i]) return -1;
        if (digits_[i] > other.digits_[i]) return 1;
    }
    
    return 0;
}

bool BigInteger::operator<(const BigInteger& other) const {
    if (negative_ != other.negative_) {
        return negative_;
    }
    
    int cmp = compareAbsolute(other);
    return negative_ ? cmp > 0 : cmp < 0;
}

bool BigInteger::operator<=(const BigInteger& other) const {
    return *this < other || *this == other;
}

bool BigInteger::operator>(const BigInteger& other) const {
    return !(*this <= other);
}

bool BigInteger::operator>=(const BigInteger& other) const {
    return !(*this < other);
}

BigInteger BigInteger::operator+(const BigInteger& other) const {
    BigInteger result = *this;
    result += other;
    return result;
}

BigInteger& BigInteger::operator+=(const BigInteger& other) {
    if (negative_ == other.negative_) {
        size_t maxSize = std::max(digits_.size(), other.digits_.size());
        digits_.resize(maxSize, 0);
        
        uint64_t carry = 0;
        for (size_t i = 0; i < maxSize; ++i) {
            uint64_t sum = static_cast<uint64_t>(digits_[i]) + 
                          (i < other.digits_.size() ? other.digits_[i] : 0) + carry;
            digits_[i] = static_cast<uint32_t>(sum & 0xFFFFFFFF);
            carry = sum >> 32;
        }
        
        if (carry > 0) {
            digits_.push_back(static_cast<uint32_t>(carry));
        }
    } else {
        BigInteger temp = other;
        temp.negative_ = !temp.negative_;
        *this -= temp;
    }
    
    normalize();
    return *this;
}

BigInteger BigInteger::operator-(const BigInteger& other) const {
    BigInteger result = *this;
    result -= other;
    return result;
}

BigInteger& BigInteger::operator-=(const BigInteger& other) {
    if (negative_ != other.negative_) {
        BigInteger temp = other;
        temp.negative_ = !temp.negative_;
        *this += temp;
    } else {
        int cmp = compareAbsolute(other);
        if (cmp == 0) {
            *this = BigInteger(0);
            return *this;
        }
        
        bool resultNegative = (cmp < 0) ? !negative_ : negative_;
        const BigInteger& larger = (cmp < 0) ? other : *this;
        const BigInteger& smaller = (cmp < 0) ? *this : other;
        
        digits_.clear();
        uint32_t borrow = 0;
        for (size_t i = 0; i < larger.digits_.size(); ++i) {
            uint64_t diff = static_cast<uint64_t>(larger.digits_[i]) -
                           (i < smaller.digits_.size() ? smaller.digits_[i] : 0) -
                           borrow;
            borrow = (diff >> 32) ? 1 : 0;
            digits_.push_back(static_cast<uint32_t>(diff & 0xFFFFFFFF));
        }
        
        negative_ = resultNegative;
        normalize();
    }
    
    return *this;
}

BigInteger BigInteger::operator*(const BigInteger& other) const {
    BigInteger result(0);
    
    for (size_t i = 0; i < digits_.size(); ++i) {
        BigInteger temp(0);
        temp.digits_.resize(i + other.digits_.size(), 0);
        
        uint64_t carry = 0;
        for (size_t j = 0; j < other.digits_.size(); ++j) {
            uint64_t product = static_cast<uint64_t>(digits_[i]) * other.digits_[j] + carry;
            temp.digits_[i + j] = static_cast<uint32_t>(product & 0xFFFFFFFF);
            carry = product >> 32;
        }
        
        if (carry > 0) {
            temp.digits_.push_back(static_cast<uint32_t>(carry));
        }
        
        temp.negative_ = false;
        temp.normalize();
        result += temp;
    }
    
    result.negative_ = negative_ != other.negative_;
    result.normalize();
    return result;
}

BigInteger BigInteger::operator/(const BigInteger& other) const {
    auto [quotient, remainder] = divideWithRemainder(*this, other);
    return quotient;
}

BigInteger BigInteger::operator%(const BigInteger& other) const {
    auto [quotient, remainder] = divideWithRemainder(*this, other);
    return remainder;
}

std::pair<BigInteger, BigInteger> BigInteger::divideWithRemainder(
    const BigInteger& dividend, const BigInteger& divisor) {
    
    if (divisor.isZero()) {
        throw CryptoException("Division by zero");
    }
    
    BigInteger quotient(0);
    BigInteger remainder = dividend;
    remainder.negative_ = false;
    BigInteger div = divisor;
    div.negative_ = false;
    
    while (remainder >= div) {
        BigInteger temp = div;
        BigInteger multiplier(1);
        
        while ((temp << 1) <= remainder) {
            temp = temp << 1;
            multiplier = multiplier << 1;
        }
        
        remainder -= temp;
        quotient += multiplier;
    }
    
    quotient.negative_ = dividend.negative_ != divisor.negative_;
    remainder.negative_ = dividend.negative_;
    
    quotient.normalize();
    remainder.normalize();
    
    return {quotient, remainder};
}

BigInteger BigInteger::operator<<(size_t shift) const {
    BigInteger result = *this;
    
    size_t digitShift = shift / 32;
    size_t bitShift = shift % 32;
    
    result.digits_.insert(result.digits_.begin(), digitShift, 0);
    
    if (bitShift > 0) {
        uint32_t carry = 0;
        for (size_t i = 0; i < result.digits_.size(); ++i) {
            uint64_t value = (static_cast<uint64_t>(result.digits_[i]) << bitShift) | carry;
            result.digits_[i] = static_cast<uint32_t>(value & 0xFFFFFFFF);
            carry = static_cast<uint32_t>(value >> 32);
        }
        if (carry > 0) {
            result.digits_.push_back(carry);
        }
    }
    
    result.normalize();
    return result;
}

BigInteger BigInteger::operator>>(size_t shift) const {
    BigInteger result = *this;
    
    size_t digitShift = shift / 32;
    size_t bitShift = shift % 32;
    
    if (digitShift >= result.digits_.size()) {
        return BigInteger(0);
    }
    
    result.digits_.erase(result.digits_.begin(), result.digits_.begin() + digitShift);
    
    if (bitShift > 0 && !result.digits_.empty()) {
        uint32_t carry = 0;
        for (int i = static_cast<int>(result.digits_.size()) - 1; i >= 0; --i) {
            uint64_t value = (static_cast<uint64_t>(result.digits_[i]) >> bitShift) | 
                            (static_cast<uint64_t>(carry) << (32 - bitShift));
            carry = static_cast<uint32_t>(result.digits_[i] & ((1ULL << bitShift) - 1));
            result.digits_[i] = static_cast<uint32_t>(value);
        }
    }
    
    result.normalize();
    return result;
}

BigInteger BigInteger::modPow(const BigInteger& base, const BigInteger& exp, const BigInteger& mod) {
    if (mod.isZero()) {
        throw CryptoException("Modulus cannot be zero");
    }
    
    BigInteger result(1);
    BigInteger tempBase = base % mod;
    BigInteger tempExp = exp;
    
    while (!tempExp.isZero()) {
        if (!tempExp.isEven()) {
            result = (result * tempBase) % mod;
        }
        tempExp = tempExp >> 1;
        tempBase = (tempBase * tempBase) % mod;
    }
    
    return result;
}

BigInteger BigInteger::gcd(const BigInteger& a, const BigInteger& b) {
    BigInteger x = a;
    BigInteger y = b;
    x.negative_ = false;
    y.negative_ = false;
    
    while (!y.isZero()) {
        BigInteger temp = y;
        y = x % y;
        x = temp;
    }
    
    return x;
}

BigInteger BigInteger::modInv(const BigInteger& a, const BigInteger& m) {
    BigInteger x0(0), x1(1);
    BigInteger a_copy = a;
    BigInteger m_copy = m;
    a_copy.negative_ = false;
    m_copy.negative_ = false;
    
    if (m_copy.isOne()) {
        return BigInteger(0);
    }
    
    while (a_copy > BigInteger(1)) {
        BigInteger q = a_copy / m_copy;
        BigInteger t = m_copy;
        
        m_copy = a_copy % m_copy;
        a_copy = t;
        
        t = x0;
        x0 = x1 - q * x0;
        x1 = t;
    }
    
    if (x1.negative_) {
        x1 += m;
    }
    
    return x1;
}

std::string BigInteger::toString() const {
    if (isZero()) return "0";
    
    std::string result;
    BigInteger temp = *this;
    temp.negative_ = false;
    
    BigInteger ten(10);
    while (!temp.isZero()) {
        auto [quotient, remainder] = divideWithRemainder(temp, ten);
        result += static_cast<char>('0' + remainder.digits_[0]);
        temp = quotient;
    }
    
    if (negative_) {
        result += '-';
    }
    
    std::reverse(result.begin(), result.end());
    return result;
}

std::string BigInteger::toHex() const {
    if (isZero()) return "0";
    
    std::string result;
    for (int i = static_cast<int>(digits_.size()) - 1; i >= 0; --i) {
        char buf[9];
        snprintf(buf, sizeof(buf), "%08x", digits_[i]);
        result += buf;
    }
    
    size_t start = 0;
    while (start < result.size() - 1 && result[start] == '0') {
        start++;
    }
    
    return (negative_ ? "-" : "") + result.substr(start);
}

BigInteger BigInteger::fromHex(const std::string& hex) {
    BigInteger result(0);
    bool neg = false;
    size_t start = 0;
    
    if (!hex.empty() && hex[0] == '-') {
        neg = true;
        start = 1;
    }
    
    for (size_t i = start; i < hex.size(); ++i) {
        char c = hex[i];
        uint32_t digit = 0;
        if (c >= '0' && c <= '9') {
            digit = c - '0';
        } else if (c >= 'a' && c <= 'f') {
            digit = c - 'a' + 10;
        } else if (c >= 'A' && c <= 'F') {
            digit = c - 'A' + 10;
        } else {
            continue;
        }
        
        result = result * BigInteger(16) + BigInteger(static_cast<int64_t>(digit));
    }
    
    result.negative_ = neg;
    result.normalize();
    return result;
}

BigInteger BigInteger::random(size_t bits) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint32_t> dis;
    
    BigInteger result(0);
    size_t fullDigits = bits / 32;
    size_t remainingBits = bits % 32;
    
    result.digits_.resize(fullDigits + (remainingBits > 0 ? 1 : 0));
    
    for (size_t i = 0; i < fullDigits; ++i) {
        result.digits_[i] = dis(gen);
    }
    
    if (remainingBits > 0) {
        uint32_t mask = (1ULL << remainingBits) - 1;
        result.digits_[fullDigits] = dis(gen) & mask;
        if (result.digits_[fullDigits] == 0 && bits > 0) {
            result.digits_[fullDigits] = 1;
        }
    }
    
    if (!result.digits_.empty() && remainingBits > 0) {
        result.digits_.back() |= (1ULL << (remainingBits - 1));
    }
    
    result.negative_ = false;
    result.normalize();
    return result;
}

BigInteger BigInteger::randomInRange(const BigInteger& min, const BigInteger& max) {
    BigInteger range = max - min;
    size_t bits = range.bitLength();
    
    BigInteger result;
    do {
        result = random(bits);
        result = result % range;
        result += min;
    } while (result < min || result > max);
    
    return result;
}

BigInteger BigInteger::fromBytes(const std::vector<uint8_t>& bytes) {
    BigInteger result(0);
    
    for (size_t i = 0; i < bytes.size(); ++i) {
        result = result * BigInteger(256) + BigInteger(static_cast<int64_t>(bytes[i]));
    }
    
    return result;
}

std::vector<uint8_t> BigInteger::toBytes() const {
    std::vector<uint8_t> result;
    BigInteger temp = *this;
    temp.negative_ = false;
    
    BigInteger two56(256);
    while (!temp.isZero()) {
        auto [quotient, remainder] = divideWithRemainder(temp, two56);
        result.push_back(static_cast<uint8_t>(remainder.digits_[0]));
        temp = quotient;
    }
    
    std::reverse(result.begin(), result.end());
    return result;
}

}
}

