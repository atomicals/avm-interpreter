// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
#include "script_num.h"

#include "serialize_number.h"
#include <iostream>
#include <iterator>
#include <limits>
#include <span.h>

using avm::bigint;
using namespace std;

CScriptNum::CScriptNum(Span<const uint8_t> span, const size_t nMaxNumSize) {
    assert(m_value.index() == 0);
    assert(get<0>(m_value) == 0);

    if (span.size() > nMaxNumSize) {
        throw ScriptnumOverflowException("script number overflow");
    }
    if (!avm::IsMinimallyEncoded(span, nMaxNumSize)) {
        throw ScriptnumMinimalEncodingException("non-minimally encoded script number");
    }
    if (span.empty()) {
        m_value = bigint{0};
        assert(m_value.index() == 1);
    } else if (span.size() <= nMaxNumSize) {
        m_value = avm::bigint::deserialize(span);
    }
    assert(m_value.index() == 1);
}

CScriptNum &CScriptNum::operator&=(const CScriptNum &other) {
    static_assert(variant_size_v<CScriptNum::value_type> == 2);
    assert(checkIndex(other));
    if (m_value.index() == 0) {
        get<0>(m_value) &= get<0>(other.m_value);
    } else {
        get<1>(m_value) &= get<1>(other.m_value);
    }
    assert(checkIndex(other));
    return *this;
}

CScriptNum &CScriptNum::operator&=(int64_t other) {
    std::visit([&other](auto &n) { n &= other; }, m_value);
    return *this;
}

bool CScriptNum::checkIndex(const CScriptNum &other) const {
    return m_value.index() == other.m_value.index();
}

bool operator==(const CScriptNum &a, const CScriptNum &b) {
    static_assert(std::variant_size_v<CScriptNum::value_type> == 2);

    // clang-format off
    if(a.checkIndex(b)) {
        return a.m_value == b.m_value;
    } else  {
        return visit([&b](const auto& a) {
            return visit([&a](const auto& b)
            {
                return a == b;
            }, b.m_value);
        }, a.m_value);
    }
    // clang-format on
}

bool operator<(const CScriptNum &a, const CScriptNum &b) {
    static_assert(variant_size_v<CScriptNum::value_type> == 2);
    // clang-format off
    if(a.checkIndex(b)) {
        return a.m_value < b.m_value;
    } else {
        return visit([&b](const auto& a) {
                        return visit([&a](const auto& b) {
                            return a < b;
                        }, b.m_value);
                    }, 
                    a.m_value);
    }
    // clang-format on
}

CScriptNum &CScriptNum::operator+=(const CScriptNum &other) {
    static_assert(variant_size_v<CScriptNum::value_type> == 2);
    assert(checkIndex(other));

    if (m_value.index() == 0) {
        assert(get<0>(other.m_value) == 0 ||
               (get<0>(other.m_value) > 0 &&
                get<0>(m_value) <= std::numeric_limits<int64_t>::max() - get<0>(other.m_value)) ||
               (get<0>(other.m_value) < 0 &&
                get<0>(m_value) >= std::numeric_limits<int64_t>::min() - get<0>(other.m_value)));
        get<0>(m_value) += get<0>(other.m_value);
    } else {
        get<1>(m_value) += get<1>(other.m_value);
    }
    assert(checkIndex(other));
    return *this;
}

CScriptNum &CScriptNum::operator-=(const CScriptNum &other) {
    static_assert(variant_size_v<CScriptNum::value_type> == 2);
    assert(checkIndex(other));

    if (m_value.index() == 0) {
        assert(get<0>(other.m_value) == 0 ||
               (get<0>(other.m_value) > 0 &&
                get<0>(m_value) >= std::numeric_limits<int64_t>::min() + get<0>(other.m_value)) ||
               (get<0>(other.m_value) < 0 &&
                get<0>(m_value) <= std::numeric_limits<int64_t>::max() + get<0>(other.m_value)));
        get<0>(m_value) -= get<0>(other.m_value);
    } else {
        get<1>(m_value) -= get<1>(other.m_value);
    }
    assert(checkIndex(other));
    return *this;
}

CScriptNum &CScriptNum::operator*=(const CScriptNum &other) {
    static_assert(variant_size_v<CScriptNum::value_type> == 2);
    assert(checkIndex(other));

    if (m_value.index() == 0) {
        get<0>(m_value) *= get<0>(other.m_value);
    } else {
        get<1>(m_value) *= get<1>(other.m_value);
    }
    assert(checkIndex(other));
    return *this;
}

CScriptNum &CScriptNum::operator/=(const CScriptNum &other) {
    static_assert(variant_size_v<CScriptNum::value_type> == 2);
    assert(checkIndex(other));
    if (m_value.index() == 0) {
        get<0>(m_value) /= get<0>(other.m_value);
    } else {
        get<1>(m_value) /= get<1>(other.m_value);
    }
    assert(checkIndex(other));
    return *this;
}

CScriptNum &CScriptNum::operator%=(const CScriptNum &other) {
    static_assert(variant_size_v<CScriptNum::value_type> == 2);
    assert(checkIndex(other));
    if (m_value.index() == 0) {
        get<0>(m_value) %= get<0>(other.m_value);
    } else {
        get<1>(m_value) %= get<1>(other.m_value);
    }
    assert(checkIndex(other));
    return *this;
}

CScriptNum CScriptNum::operator-() const {
    return std::visit([](auto &n) -> CScriptNum { return CScriptNum{-n}; }, m_value);
}

std::ostream &operator<<(std::ostream &os, const CScriptNum &n) {
    visit([&os](const auto &n) { os << n; }, n.m_value);
    return os;
}

namespace {
template <typename... Ts>
struct overload : Ts... {
    using Ts::operator()...;
};
template <typename... Ts>
overload(Ts...) -> overload<Ts...>;
} // namespace

int CScriptNum::getint() const {
    static_assert(variant_size_v<CScriptNum::value_type> == 2);
    return std::visit(overload{[](const avm::bigint &n) -> int {
                                   static const bigint bn_int_min{std::numeric_limits<int>::min()};
                                   static const bigint bn_int_max{std::numeric_limits<int>::max()};
                                   if (n > bn_int_max) {
                                       return std::numeric_limits<int>::max();
                                   } else if (n < bn_int_min) {
                                       return std::numeric_limits<int>::min();
                                   } else {
                                       return avm::to_long(n);
                                   }
                               },
                               [](const int64_t n) {
                                   if (n > std::numeric_limits<int>::max()) {
                                       return std::numeric_limits<int>::max();
                                   } else if (n < std::numeric_limits<int>::min()) {
                                       return std::numeric_limits<int>::min();
                                   } else {
                                       return static_cast<int>(n);
                                   }
                               }},
                      m_value);
}

size_t CScriptNum::getSizeType() const {
    static_assert(variant_size_v<CScriptNum::value_type> == 2);
    return std::visit(overload{[](const avm::bigint &n) {
                                   assert(n >= 0 && n <= std::numeric_limits<int32_t>::max());
                                   return avm::getSizeType(n);
                               },
                               [](const int64_t n) {
                                   assert(n >= 0 && n <= std::numeric_limits<int32_t>::max());
                                   return size_t(n);
                               }},
                      m_value);
}

vector<uint8_t> CScriptNum::getvch() const {
    static_assert(variant_size_v<CScriptNum::value_type> == 2);
    // clang-format off
    return std::visit(overload{[](const avm::bigint& n) {
                          return n.serialize();
                      },
                      [](const auto& n) {
                          vector<uint8_t> v;
                          v.reserve(sizeof(n));
                          avm::serialize(n, back_inserter(v));
                          return v;
                      }},
                      m_value);
    // clang-format on
}
