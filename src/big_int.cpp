#include "big_int.h"

#include <algorithm>
#include <cassert>
#include <iostream>
#include <limits>
#include <openssl/asn1.h>
#include <openssl/bn.h>
#include <sstream>
using namespace std;

void avm::bigint::NullBigNumberDeleter::operator()(bignum_st *p) const {
    ::BN_free(p);
}

avm::bigint::bigint() : value_{nullptr} {}

avm::bigint::bigint(const int i) : value_(BN_new(), NullBigNumberDeleter()) {
    if (!value_) {
        throw BigIntException();
    }
    if (i >= 0) {
        const auto s{BN_set_word(value_.get(), i)};
        if (!s) {
            throw BigIntException();
        }
    } else if (i > INT_MIN) {
        const auto s{BN_set_word(value_.get(), -i)};
        if (!s) throw BigIntException();
        BN_set_negative(value_.get(), 1);
    } else {
        const int ii{i + 1};
        auto s{BN_set_word(value_.get(), -ii)};
        if (!s) {
            throw BigIntException();
        }
        BN_set_negative(value_.get(), 1);
        s = BN_sub(value_.get(), value_.get(), BN_value_one());
        if (!s) {
            throw BigIntException();
        }
    }
}

avm::bigint::bigint(const int64_t i) : value_(BN_new(), NullBigNumberDeleter()) {
    if (!value_) {
        throw BigIntException();
    }
    if (i >= 0) {
        const auto s{BN_set_word(value_.get(), i)};
        if (!s) {
            throw BigIntException();
        }
    } else if (i > INT64_MIN) {
        const auto s{BN_set_word(value_.get(), -i)};
        if (!s) {
            throw BigIntException();
        }
        BN_set_negative(value_.get(), 1);
    } else {
        const int64_t ii{i + 1};
        auto s{BN_set_word(value_.get(), -ii)};
        if (!s) {
            throw BigIntException();
        }
        BN_set_negative(value_.get(), 1);
        s = BN_sub(value_.get(), value_.get(), BN_value_one());
        if (!s) {
            throw BigIntException();
        }
    }
}

avm::bigint::bigint(const size_t i) : value_(BN_new(), NullBigNumberDeleter()) {
    assert(value_);
    if (!value_) {
        throw BigIntException();
    }
    const auto s{BN_set_word(value_.get(), i)};
    if (!s) {
        throw BigIntException();
    }
}

avm::bigint::bigint(const std::string &n) : value_(BN_new(), NullBigNumberDeleter()) {
    if (!value_) {
        throw BigIntException();
    }
    auto p{value_.get()};
    const auto s = BN_dec2bn(&p, n.c_str());
    if (!s) {
        throw BigIntException();
    }
}

avm::bigint::bigint(const bigint &other) : value_(BN_new(), NullBigNumberDeleter()) {
    if (!value_) {
        throw BigIntException();
    }
    const auto s = BN_copy(value_.get(), other.value_.get());
    if (!s) {
        throw BigIntException();
    }
}

avm::bigint &avm::bigint::operator=(const bigint &other) {
    bigint temp{other};
    swap(temp);
    return *this;
}

void avm::bigint::swap(bigint &other) noexcept {
    using std::swap;
    swap(value_, other.value_);
}

bool avm::operator<(const bigint &a, const bigint &b) {
    return a.spaceship_operator(b) < 0;
}

bool avm::operator==(const bigint &a, const bigint &b) {
    return a.spaceship_operator(b) == 0;
}

avm::bigint &avm::bigint::operator+=(const bigint &other) {
    const auto s = BN_add(value_.get(), value_.get(), other.value_.get());
    if (!s) {
        throw BigIntException();
    }
    return *this;
}

avm::bigint &avm::bigint::operator-=(const bigint &other) {
    const auto s = BN_sub(value_.get(), value_.get(), other.value_.get());
    if (!s) {
        throw BigIntException();
    }
    return *this;
}

namespace {
struct NullCtxDeleter {
    void operator()(BN_CTX *p) const { ::BN_CTX_free(p); }
};
using UniqueCtxPtr = std::unique_ptr<BN_CTX, NullCtxDeleter>;
static_assert(sizeof(UniqueCtxPtr) == sizeof(BN_CTX *));
UniqueCtxPtr MakeUniqueCtxPtr() {
    return UniqueCtxPtr{BN_CTX_new(), NullCtxDeleter()};
}
} // namespace

avm::bigint &avm::bigint::operator*=(const bigint &other) {
    UniqueCtxPtr ctx{MakeUniqueCtxPtr()};
    const auto s{BN_mul(value_.get(), value_.get(), other.value_.get(), ctx.get())};
    if (!s) throw BigIntException();
    return *this;
}

avm::bigint &avm::bigint::operator/=(const bigint &other) {
    bigint rem;
    UniqueCtxPtr ctx{MakeUniqueCtxPtr()};
    const auto s{BN_div(value_.get(), rem.value_.get(), value_.get(), other.value_.get(), ctx.get())};
    if (!s) throw BigIntException();
    return *this;
}

avm::bigint &avm::bigint::operator%=(const bigint &other) {
    bigint rem;
    UniqueCtxPtr ctx{MakeUniqueCtxPtr()};
    const auto s{BN_mod(value_.get(), value_.get(), other.value_.get(), ctx.get())};
    if (!s) {
        throw BigIntException();
    }
    return *this;
}

avm::bigint &avm::bigint::operator&=(const bigint &other) {
    if (this == &other) {
        return *this;
    }

    if (other.empty()) {
        *this = bigint{0};
        return *this;
    }

    bool negate{};
    if ((is_negative(*this)) && is_negative(other)) {
        negate = true;
    }

    auto bytes_other{other.to_bin()};
    auto bytes_this{to_bin()};

    if (bytes_other.size() <= bytes_this.size()) {
        transform(rbegin(bytes_other), rend(bytes_other), rbegin(bytes_this), rbegin(bytes_other),
                  [](auto byte_other, auto byte_this) { return byte_other & byte_this; });
        BN_bin2bn(bytes_other.data(), bytes_other.size(), value_.get());
    } else {
        transform(rbegin(bytes_this), rend(bytes_this), rbegin(bytes_other), rbegin(bytes_this),
                  [](auto byte_this, auto byte_other) { return byte_this & byte_other; });
        BN_bin2bn(bytes_this.data(), bytes_this.size(), value_.get());
    }
    if (negate) {
        this->negate();
    }
    return *this;
}

avm::bigint &avm::bigint::operator|=(const bigint &other) {
    if (this == &other) {
        return *this;
    }
    if (other.empty()) {
        return *this;
    }

    bool negate{};
    if ((is_negative(other) && !is_negative(*this)) || (is_negative(*this) && !is_negative(other))) {
        negate = true;
    }

    auto bytes_other{other.to_bin()};
    auto bytes_this{to_bin()};

    if (bytes_other.size() <= bytes_this.size()) {
        transform(rbegin(bytes_other), rend(bytes_other), rbegin(bytes_this), rbegin(bytes_this),
                  [](auto byte_other, auto byte_this) { return byte_other | byte_this; });
        BN_bin2bn(bytes_this.data(), bytes_this.size(), value_.get());
    } else {
        transform(rbegin(bytes_this), rend(bytes_this), rbegin(bytes_other), rbegin(bytes_other),
                  [](auto byte_this, auto byte_other) { return byte_this | byte_other; });
        BN_bin2bn(bytes_other.data(), bytes_other.size(), value_.get());
    }
    if (negate) {
        this->negate();
    }
    return *this;
}

avm::bigint &avm::bigint::operator<<=(const int n) {
    if (n <= 0) {
        return *this;
    }
    const auto s{BN_lshift(value_.get(), value_.get(), n)};
    if (!s) {
        throw BigIntException();
    }
    return *this;
}

avm::bigint &avm::bigint::operator>>=(const int n) {
    if (n <= 0) {
        return *this;
    }
    const auto s{BN_rshift(value_.get(), value_.get(), n)};
    if (!s) {
        throw BigIntException();
    }
    return *this;
}

avm::bigint avm::bigint::operator-() const {
    bigint rv{*this};
    rv.negate();
    return rv;
}

uint8_t avm::bigint::lsb() const {
    const auto buffer{to_bin()};
    if (buffer.empty()) {
        return 0;
    }
    return buffer[buffer.size() - 1];
}

int avm::bigint::spaceship_operator(const bigint &other) const {
    return BN_cmp(value_.get(), other.value_.get());
}

void avm::bigint::negate() {
    const bool neg = is_negative(*this);
    if (neg) {
        BN_set_negative(value_.get(), 0);
    } else {
        BN_set_negative(value_.get(), 1);
    }
}

void avm::bigint::mask_bits(const int n) {
    const auto s{BN_mask_bits(value_.get(), n)};
    if (!s) {
        throw BigIntException();
    }
}

int avm::bigint::size_bits() const {
    return BN_num_bits(value_.get());
}

int avm::bigint::byteSize() const {
    return BN_num_bytes(value_.get());
}

avm::bigint::buffer_type avm::bigint::to_bin() const {
    buffer_type buffer(byteSize());
    BN_bn2bin(value_.get(), buffer.data());
    return buffer;
}

namespace {
struct NullStringDeleter {
    void operator()(const char *p) const { ::OPENSSL_free((void *)p); }
};
using UniqueStringPtr = std::unique_ptr<const char[], NullStringDeleter>;
static_assert(sizeof(UniqueStringPtr) == sizeof(const char *));
UniqueStringPtr to_str(bignum_st *bn) {
    return UniqueStringPtr{BN_bn2dec(bn)};
}
} // namespace

std::ostream &avm::operator<<(std::ostream &os, const bigint &n) {
    if (n.value_ == nullptr) {
        return os;
    }
    const auto s{to_str(n.value_.get())};
    os << s.get();
    return os;
}

bool avm::is_negative(const bigint &n) {
    const auto s{BN_is_negative(n.value_.get())};
    return s == 1;
}

avm::bigint avm::abs(const bigint &n) {
    return is_negative(n) ? -n : n;
}

std::string avm::to_string(const bigint &n) {
    std::ostringstream oss;
    oss << n;
    return oss.str();
}

namespace {
struct NullAssn1Deleter {
    void operator()(ASN1_INTEGER *p) const { ::ASN1_INTEGER_free(p); }
};
using UniqueAssn1Ptr = std::unique_ptr<ASN1_INTEGER, NullAssn1Deleter>;
static_assert(sizeof(UniqueAssn1Ptr) == sizeof(ASN1_INTEGER *));

UniqueAssn1Ptr to_asn1(bignum_st *bn) {
    return UniqueAssn1Ptr{BN_to_ASN1_INTEGER(bn, nullptr)};
}
} // namespace

long avm::to_long(const bigint &n) {
    const auto asn1{to_asn1(n.value_.get())};
    if (!asn1) {
        throw BigIntException();
    }
    return ASN1_INTEGER_get(asn1.get());
}

std::size_t avm::getSizeType(const bigint &n) {
    const int64_t i64 = to_long(n);
    return static_cast<size_t>(i64);
}

namespace {
constexpr auto length_in_bytes{4};
}

std::vector<uint8_t> avm::bigint::serialize() const {
    const auto len{BN_bn2mpi(value_.get(), nullptr)};
    vector<unsigned char> result(len);
    BN_bn2mpi(value_.get(), result.data());
    result.erase(begin(result), begin(result) + length_in_bytes);
    reverse(begin(result), end(result));
    return result;
}

avm::bigint avm::bigint::deserialize(Span<const uint8_t> s) {
    const auto size{s.size()};
    vector<uint8_t> tmp(size + length_in_bytes);
    tmp[0] = (size >> 24) & 0xff;
    tmp[1] = (size >> 16) & 0xff;
    tmp[2] = (size >> 8) & 0xff;
    tmp[3] = (size >> 0) & 0xff;
    reverse_copy(begin(s), end(s), begin(tmp) + length_in_bytes);
    auto p{BN_mpi2bn(tmp.data(), tmp.size(), nullptr)};
    bigint b;
    b.value_.reset(p);
    return b;
}
