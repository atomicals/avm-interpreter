// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <compressor.h>

#include <hash.h>
#include <pubkey.h>
#include <script/standard.h>

#include <cstring>

/*
 * These check for scripts for which a special case with a shorter encoding is
 * defined. They are implemented separately from the CScript test, as these test
 * for exact byte sequence correspondences, and are more strict. For example,
 * IsToPubKey also verifies whether the public key is valid (as invalid ones
 * cannot be represented in compressed form).
 */

static bool IsToScriptID(const CScript &script, CScriptID &hash) {
    if (script.IsPayToScriptHash()) {
        static_assert(CScriptID::size() == 20);
        std::memcpy(&*hash.begin(), &script[2], 20);
        return true;
    }
    return false;
}
 
bool CompressScript(const CScript &script, std::vector<uint8_t> &out) {
    CKeyID keyID;
    CScriptID scriptID;
    if (IsToScriptID(script, scriptID)) {
        out.resize(21);
        out[0] = 0x01;
        std::memcpy(&out[1], &*scriptID.begin(), 20);
        return true;
    }
    return false;
}

unsigned int GetSpecialScriptSize(unsigned int nSize) {
    if (nSize == 0 || nSize == 1) {
        return 20;
    }
    if (nSize == 2 || nSize == 3 || nSize == 4 || nSize == 5) {
        return 32;
    }
    return 0;
}

bool DecompressScript(CScript &script, unsigned int nSize,
                      const std::vector<uint8_t> &in) {
    switch (nSize) {
        case 0x01:
            script.resize(23);
            script[0] = OP_HASH160;
            script[1] = 20;
            std::memcpy(&script[2], in.data(), 20);
            script[22] = OP_EQUAL;
            return true;
    }
    return false;
}

// Amount compression:
// * If the amount is 0, output 0
// * first, divide the amount (in base units) by the largest power of 10
// possible; call the exponent e (e is max 9)
// * if e<9, the last digit of the resulting number cannot be 0; store it as d,
// and drop it (divide by 10)
//   * call the result n
//   * output 1 + 10*(9*n + d - 1) + e
// * if e==9, we only know the resulting number is not zero, so output 1 + 10*(n
// - 1) + 9
// (this is decodable, as d is in [1-9] and e is in [0-9])
uint64_t CompressAmount(Amount amt) {
    uint64_t n = amt / SATOSHI;
    if (n == 0) {
        return 0;
    }
    int e = 0;
    while (((n % 10) == 0) && e < 9) {
        n /= 10;
        e++;
    }
    if (e < 9) {
        int d = (n % 10);
        assert(d >= 1 && d <= 9);
        n /= 10;
        return 1 + (n * 9 + d - 1) * 10 + e;
    } else {
        return 1 + (n - 1) * 10 + 9;
    }
}

Amount DecompressAmount(uint64_t x) {
    // x = 0  OR  x = 1+10*(9*n + d - 1) + e  OR  x = 1+10*(n - 1) + 9
    if (x == 0) {
        return Amount::zero();
    }
    x--;
    // x = 10*(9*n + d - 1) + e
    int e = x % 10;
    x /= 10;
    uint64_t n = 0;
    if (e < 9) {
        // x = 9*n + d - 1
        int d = (x % 9) + 1;
        x /= 9;
        // x = n
        n = x * 10 + d;
    } else {
        n = x + 1;
    }
    while (e) {
        n *= 10;
        e--;
    }
    return int64_t(n) * SATOSHI;
}
