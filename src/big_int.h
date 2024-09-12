
#pragma once

#include "span.h"
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

struct bignum_st;
namespace avm {
class bigint {
public:
    bigint();
    explicit bigint(int);
    explicit bigint(int64_t);
    explicit bigint(std::size_t);
    explicit bigint(const std::string &);

    ~bigint() = default;
    bigint(const bigint &);
    bigint &operator=(const bigint &);
    bigint(bigint &&) noexcept = default;
    bigint &operator=(bigint &&) noexcept = default;
    void swap(bigint &) noexcept;
    friend bool operator<(const bigint &, const bigint &);
    friend bool operator==(const bigint &, const bigint &);
    bigint &operator+=(const bigint &);
    bigint &operator-=(const bigint &);
    bigint &operator*=(const bigint &);
    bigint &operator/=(const bigint &);
    bigint &operator%=(const bigint &);
    bigint operator-() const;
    bigint &operator+=(int64_t other) { return *this += bigint(other); }
    bigint &operator-=(int64_t other) { return *this -= bigint(other); }
    bigint &operator&=(int64_t other) { return *this &= bigint(other); }
    bigint &operator>>=(int n);
    bigint &operator<<=(int n);
    bigint &operator&=(const bigint &);
    bigint &operator|=(const bigint &);
    uint8_t lsb() const;
    int byteSize() const;
    friend std::ostream &operator<<(std::ostream &, const bigint &);
    friend bool is_negative(const bigint &);
    friend long to_long(const bigint &);
    friend std::size_t getSizeType(const bigint &);
    std::vector<uint8_t> serialize() const;
    static bigint deserialize(Span<const uint8_t>);

private:
    int spaceship_operator(const bigint &) const;
    void negate();
    int size_bits() const;
    bool empty() const { return byteSize() == 0; }
    using buffer_type = std::vector<unsigned char>;
    buffer_type to_bin() const;
    void mask_bits(int n);
    struct NullBigNumberDeleter {
        void operator()(bignum_st *) const;
    };
    using unique_bn_ptr = std::unique_ptr<bignum_st, NullBigNumberDeleter>;
    static_assert(sizeof(unique_bn_ptr) == sizeof(bignum_st *));
    unique_bn_ptr value_;
};
inline void swap(bigint &a, bigint &b) {
    a.swap(b);
}
bool operator==(const bigint &, const bigint &);
bool operator<(const bigint &, const bigint &);
inline bool operator>(const bigint &a, const bigint &b) {
    return b < a;
}
inline bool operator>=(const bigint &a, const bigint &b) {
    return !(a < b);
}
inline bool operator!=(const bigint &a, const bigint &b) {
    return !(a == b);
}
inline bool operator<=(const bigint &a, const bigint &b) {
    return !(b < a);
}
inline bigint operator+(bigint a, const bigint &b) {
    a += b;
    return a;
}
inline bigint operator-(bigint a, const bigint &b) {
    a -= b;
    return a;
}
inline bigint operator*(bigint a, const bigint &b) {
    a *= b;
    return a;
}
inline bigint operator/(bigint a, const bigint &b) {
    a /= b;
    return a;
}
inline bigint operator%(bigint a, const bigint &b) {
    a %= b;
    return a;
}
inline bigint operator&(bigint a, const bigint &b) {
    a &= b;
    return a;
}
std::ostream &operator<<(std::ostream &os, const bigint &);
inline bool operator!=(const bigint &a, const int64_t b) {
    return a != bigint(b);
}
inline bool operator==(const bigint &a, const int64_t b) {
    return a == bigint{b};
}
inline bool operator==(const int64_t a, const bigint &b) {
    return bigint{a} == b;
}
inline bool operator<(const bigint &a, int64_t b) {
    return a < bigint(b);
}
inline bool operator>=(const bigint &a, int64_t b) {
    return a >= bigint(b);
}
inline bool operator<(int64_t a, const bigint &b) {
    return bigint(a) < b;
}
inline bool operator<=(const bigint &a, int64_t b) {
    return a <= bigint(b);
}
inline bool operator>(const bigint &a, int64_t b) {
    return a > bigint(b);
}
inline bigint operator-(bigint a, const int64_t b) {
    return a - bigint(b);
}
inline bigint operator%(bigint a, const int64_t b) {
    return a % bigint(b);
}
inline bigint operator*(bigint a, const int64_t b) {
    return a * bigint(b);
}
inline bigint operator/(bigint a, const int64_t b) {
    return a / bigint(b);
}
inline bigint operator+(bigint a, const int64_t b) {
    return a + bigint(b);
}
inline bool operator==(const bigint &a, const size_t b) {
    return a == bigint{b};
}
inline bool operator!=(const bigint &a, const size_t b) {
    return a != bigint(b);
}
inline bool operator==(const size_t a, const bigint &b) {
    return bigint{a} == b;
}
inline bool operator==(const bigint &a, const int b) {
    return a == bigint{b};
}
inline bool operator==(const int a, const bigint &b) {
    return bigint{a} == b;
}
inline bool operator!=(const bigint &a, const int b) {
    return a != bigint(b);
}
inline uint8_t operator&(const bigint &a, const uint8_t b) {
    return a.lsb() & b;
}

bool is_negative(const bigint &);
bigint abs(const bigint &);
std::string to_string(const bigint &);
std::size_t getSizeType(const bigint &);
long to_long(const bigint &);

template <typename O>
inline void serialize(const bigint &n, O o) {
    const std::vector<uint8_t> v{n.serialize()};
    std::copy(begin(v), end(v), o);
}

template <typename I>
bigint deserialize(I first, I last) {
    std::vector<uint8_t> v(first, last);
    return bigint::deserialize(v);
}
class BigIntException : std::runtime_error {
public:
    BigIntException() : std::runtime_error(""){};
};
} // namespace avm

namespace std {
template <>
inline void swap<avm::bigint>(avm::bigint &a, avm::bigint &b) noexcept {
    a.swap(b);
}
} // namespace std
