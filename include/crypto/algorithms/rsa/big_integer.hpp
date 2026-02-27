#pragma once
#include <vector>
#include <string>
#include <cstdint>

namespace crypto {
namespace rsa {

class BigInteger {
public:
    BigInteger();
    explicit BigInteger(int64_t value);
    explicit BigInteger(const std::string& hex);
    BigInteger(const BigInteger& other);
    BigInteger& operator=(const BigInteger& other);
    
    
    std::string toString() const;
    std::string toHex() const;
    static BigInteger fromHex(const std::string& hex);
    static BigInteger fromBytes(const std::vector<uint8_t>& bytes);
    std::vector<uint8_t> toBytes() const;
    
    
    BigInteger operator+(const BigInteger& other) const;
    BigInteger operator-(const BigInteger& other) const;
    BigInteger operator*(const BigInteger& other) const;
    BigInteger operator/(const BigInteger& other) const;
    BigInteger operator%(const BigInteger& other) const;
    
    BigInteger& operator+=(const BigInteger& other);
    BigInteger& operator-=(const BigInteger& other);
    BigInteger& operator*=(const BigInteger& other);
    
    
    bool operator==(const BigInteger& other) const;
    bool operator!=(const BigInteger& other) const;
    bool operator<(const BigInteger& other) const;
    bool operator<=(const BigInteger& other) const;
    bool operator>(const BigInteger& other) const;
    bool operator>=(const BigInteger& other) const;
    
    
    BigInteger operator<<(size_t shift) const;
    BigInteger operator>>(size_t shift) const;
    
    
    static BigInteger modPow(const BigInteger& base, const BigInteger& exp, const BigInteger& mod);
    static BigInteger modInv(const BigInteger& a, const BigInteger& m);
    static BigInteger gcd(const BigInteger& a, const BigInteger& b);
    
    
    bool isZero() const;
    bool isOne() const;
    bool isEven() const;
    size_t bitLength() const;
    int sign() const; 
    
    
    static BigInteger random(size_t bits);
    static BigInteger randomInRange(const BigInteger& min, const BigInteger& max);
    
private:
    std::vector<uint32_t> digits_; 
    bool negative_;
    
    void normalize();
    void removeLeadingZeros();
    int compareAbsolute(const BigInteger& other) const;
    
    
    void addDigits(const std::vector<uint32_t>& other);
    void subtractDigits(const std::vector<uint32_t>& other);
    static std::vector<uint32_t> multiplyDigits(const std::vector<uint32_t>& a, const std::vector<uint32_t>& b);
    static std::pair<BigInteger, BigInteger> divideWithRemainder(const BigInteger& dividend, const BigInteger& divisor);
};

}
}

