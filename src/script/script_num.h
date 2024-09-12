// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
#pragma once

#include "big_int.h"
#include <cassert>
#include <iosfwd>
#include <stdexcept>
#include <variant>
#include <vector>

class ScriptnumMinimalEncodingException : public std::runtime_error {
public:
    explicit ScriptnumMinimalEncodingException(const std::string &s) : std::runtime_error(s) {}
};

class ScriptnumOverflowException : public std::overflow_error {
public:
    explicit ScriptnumOverflowException(const std::string &s) : std::overflow_error(s) {}
};

class CScriptNum {
public:
    static const size_t MAXIMUM_ITEM_SIZE = 100000ULL;
    CScriptNum() : m_value(0) {}
    explicit CScriptNum(const avm::bigint &n) : m_value(n) {}
    explicit CScriptNum(Span<const uint8_t>, const size_t nMaxNumSize = MAXIMUM_ITEM_SIZE);
    explicit CScriptNum(const int64_t &n) : m_value(n) {}

    friend bool operator<(const CScriptNum &, int64_t);
    friend bool operator<(int64_t, const CScriptNum &);
    friend bool operator<(const CScriptNum &, const CScriptNum &);
    friend bool operator==(const CScriptNum &, const CScriptNum &);

    CScriptNum &operator%=(const CScriptNum &);
    CScriptNum &operator-=(const CScriptNum &);
    CScriptNum &operator/=(const CScriptNum &);
    CScriptNum &operator*=(const CScriptNum &);
    CScriptNum &operator+=(const CScriptNum &);
    CScriptNum &operator&=(int64_t);
    CScriptNum &operator&=(const CScriptNum &);

    CScriptNum &operator=(int64_t rhs) {
        m_value = rhs;
        return *this;
    }

    CScriptNum operator-() const;
    friend std::ostream &operator<<(std::ostream &, const CScriptNum &);
    int getint() const;
    std::vector<uint8_t> getvch() const;

    size_t getSizeType() const;

private:
    bool checkIndex(const CScriptNum &) const;
    using value_type = std::variant<int64_t, avm::bigint>;
    value_type m_value;
};

bool operator==(const CScriptNum &, const CScriptNum &);
inline bool operator!=(const CScriptNum &a, const CScriptNum &b) {
    return !(a == b);
}

bool operator<(const CScriptNum &, const CScriptNum &);
inline bool operator<(const CScriptNum &a, int64_t b) {
    return std::visit([b](const auto &a) { return a < b; }, a.m_value);
}

inline bool operator<(int64_t a, const CScriptNum &b) {
    return std::visit([a](const auto &b) { return a < b; }, b.m_value);
}
inline bool operator>=(const CScriptNum &a, const CScriptNum &b) {
    return !(a < b);
}
inline bool operator>(const CScriptNum &a, const CScriptNum &b) {
    return b < a;
}
inline bool operator<=(const CScriptNum &a, const CScriptNum &b) {
    return !(b < a);
}
inline bool operator>(int64_t a, const CScriptNum &b) {
    return b < a;
}
inline bool operator<=(int64_t a, const CScriptNum &b) {
    return !(b < a);
}
inline bool operator>=(const CScriptNum &a, int64_t b) {
    return !(a < b);
}
inline bool operator>(const CScriptNum &a, int64_t b) {
    return b < a;
}
inline bool operator<=(const CScriptNum &a, int64_t b) {
    return !(b < a);
}
inline bool operator>=(int64_t a, const CScriptNum &b) {
    return !(a < b);
}
std::ostream &operator<<(std::ostream &, const CScriptNum &);
inline CScriptNum operator+(CScriptNum a, const CScriptNum &b) {
    a += b;
    return a;
}
inline CScriptNum operator&(CScriptNum a, const CScriptNum &b) {
    a &= b;
    return a;
}
inline CScriptNum operator&(CScriptNum a, int64_t b) {
    a &= b;
    return a;
}
inline CScriptNum operator/(CScriptNum a, const CScriptNum &b) {
    a /= b;
    return a;
}
inline CScriptNum operator%(CScriptNum a, const CScriptNum &b) {
    a %= b;
    return a;
}
inline CScriptNum operator*(CScriptNum a, const CScriptNum &b) {
    a *= b;
    return a;
}
inline CScriptNum operator-(CScriptNum a, const CScriptNum &b) {
    a -= b;
    return a;
}
