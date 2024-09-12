// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <crypto/common.h>
#include <prevector.h>
#include <serialize.h>

#include <cassert>
#include <climits>
#include <cstdint>
#include <cstring>
#include <limits>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>
#include <uint256.h>
#include <script/script_num.h>
#include "serialize_number.h"
#include "big_int.h"
#include <iostream>

// Maximum number of bytes pushable to the stack
static constexpr unsigned int MAX_SCRIPT_ELEMENT_SIZE = 4000;

// Maximum number of non-push operations per script
static const int MAX_OPS_PER_SCRIPT = 1000000;

// Maximum script length in bytes
static const int MAX_SCRIPT_SIZE = 1000000;

// Maximum number of values on script interpreter stack
static const int MAX_STACK_SIZE = 1000;

// Threshold for nLockTime: below this value it is interpreted as block number,
// otherwise as UNIX timestamp. Thresold is Tue Nov 5 00:53:20 1985 UTC
static const unsigned int LOCKTIME_THRESHOLD = 500000000;

template <typename T> std::vector<uint8_t> ToByteVector(const T &in) {
    return std::vector<uint8_t>(in.begin(), in.end());
}

/** Script opcodes */
enum opcodetype {
    // push value
    OP_0 = 0x00,
    OP_FALSE = OP_0,
    OP_PUSHDATA1 = 0x4c,
    OP_PUSHDATA2 = 0x4d,
    OP_PUSHDATA4 = 0x4e,
    OP_1NEGATE = 0x4f,
    OP_RESERVED = 0x50,
    OP_1 = 0x51,
    OP_TRUE = OP_1,
    OP_2 = 0x52,
    OP_3 = 0x53,
    OP_4 = 0x54,
    OP_5 = 0x55,
    OP_6 = 0x56,
    OP_7 = 0x57,
    OP_8 = 0x58,
    OP_9 = 0x59,
    OP_10 = 0x5a,
    OP_11 = 0x5b,
    OP_12 = 0x5c,
    OP_13 = 0x5d,
    OP_14 = 0x5e,
    OP_15 = 0x5f,
    OP_16 = 0x60,

    // control
    OP_NOP = 0x61,
    OP_VER = 0x62,
    OP_IF = 0x63,
    OP_NOTIF = 0x64,
    OP_VERIF = 0x65,
    OP_VERNOTIF = 0x66,
    OP_ELSE = 0x67,
    OP_ENDIF = 0x68,
    OP_VERIFY = 0x69,
    OP_RETURN = 0x6a,

    // stack ops
    OP_TOALTSTACK = 0x6b,
    OP_FROMALTSTACK = 0x6c,
    OP_2DROP = 0x6d,
    OP_2DUP = 0x6e,
    OP_3DUP = 0x6f,
    OP_2OVER = 0x70,
    OP_2ROT = 0x71,
    OP_2SWAP = 0x72,
    OP_IFDUP = 0x73,
    OP_DEPTH = 0x74,
    OP_DROP = 0x75,
    OP_DUP = 0x76,
    OP_NIP = 0x77,
    OP_OVER = 0x78,
    OP_PICK = 0x79,
    OP_ROLL = 0x7a,
    OP_ROT = 0x7b,
    OP_SWAP = 0x7c,
    OP_TUCK = 0x7d,

    // splice ops
    OP_CAT = 0x7e,
    OP_SPLIT = 0x7f, 
    OP_NUM2BIN = 0x80, 
    OP_BIN2NUM = 0x81, 
    OP_SIZE = 0x82,

    // bit logic
    OP_INVERT = 0x83,
    OP_AND = 0x84,
    OP_OR = 0x85,
    OP_XOR = 0x86,
    OP_EQUAL = 0x87,
    OP_EQUALVERIFY = 0x88,
    OP_RESERVED1 = 0x89,
    OP_RESERVED2 = 0x8a,

    // numeric
    OP_1ADD = 0x8b,
    OP_1SUB = 0x8c,
    OP_2MUL = 0x8d,
    OP_2DIV = 0x8e,
    OP_NEGATE = 0x8f,
    OP_ABS = 0x90,
    OP_NOT = 0x91,
    OP_0NOTEQUAL = 0x92,

    OP_ADD = 0x93,
    OP_SUB = 0x94,
    OP_MUL = 0x95,
    OP_DIV = 0x96,
    OP_MOD = 0x97,
    OP_LSHIFT = 0x98,
    OP_RSHIFT = 0x99,

    OP_BOOLAND = 0x9a,
    OP_BOOLOR = 0x9b,
    OP_NUMEQUAL = 0x9c,
    OP_NUMEQUALVERIFY = 0x9d,
    OP_NUMNOTEQUAL = 0x9e,
    OP_LESSTHAN = 0x9f,
    OP_GREATERTHAN = 0xa0,
    OP_LESSTHANOREQUAL = 0xa1,
    OP_GREATERTHANOREQUAL = 0xa2,
    OP_MIN = 0xa3,
    OP_MAX = 0xa4,

    OP_WITHIN = 0xa5,

    // crypto
    OP_RIPEMD160 = 0xa6,
    OP_SHA1 = 0xa7,
    OP_SHA256 = 0xa8,
    OP_HASH160 = 0xa9,
    OP_HASH256 = 0xaa,

    OP_CODESEPARATOR = 0xab,         // Not used in AVM
    OP_CHECKSIG = 0xac,              // Not used in AVM
    OP_CHECKSIGVERIFY = 0xad,        // Not used in AVM
    OP_CHECKMULTISIG = 0xae,         // Not used in AVM
    OP_CHECKMULTISIGVERIFY = 0xaf,   // Not used in AVM

    // expansion
    OP_NOP1 = 0xb0,
    OP_CHECKLOCKTIMEVERIFY = 0xb1,
    OP_NOP2 = OP_CHECKLOCKTIMEVERIFY,
    OP_CHECKSEQUENCEVERIFY = 0xb2,
    OP_NOP3 = OP_CHECKSEQUENCEVERIFY,
    OP_NOP4 = 0xb3,
    OP_NOP5 = 0xb4,
    OP_NOP6 = 0xb5,
    OP_NOP7 = 0xb6,
    OP_NOP8 = 0xb7,
    OP_NOP9 = 0xb8,
    OP_NOP10 = 0xb9,

    // More crypto
    OP_CHECKDATASIG = 0xba,
    OP_CHECKDATASIGVERIFY = 0xbb,

    // additional byte string operations
    OP_REVERSEBYTES = 0xbc,

    OP_CHECKAUTHSIG = 0xc0,          // TESTED.
    OP_CHECKAUTHSIGVERIFY = 0xc1,    // TESTED.

    // Native Introspection opcodes
    OP_TXVERSION = 0xc2,
    OP_TXINPUTCOUNT = 0xc3,
    OP_TXOUTPUTCOUNT = 0xc4,
    OP_TXLOCKTIME = 0xc5,
    OP_OUTPOINTTXHASH = 0xc8,
    OP_OUTPOINTINDEX = 0xc9,
    OP_INPUTBYTECODE = 0xca,            // TESTED.
    OP_INPUTSEQUENCENUMBER = 0xcb,      // TESTED.
    OP_INPUTWITNESSBYTECODE = 0xcc,     // NOT WORKING. NOT USED
    OP_OUTPUTVALUE = 0xcd,
    OP_OUTPUTBYTECODE = 0xce,
 
    OP_NFT_PUT = 0xd1,                  // TESTED. Add NFT to internal token table storage
    OP_FT_BALANCE_ADD = 0xd3,           // TESTED. Add to FT balance internal token table storage
 
    OP_KV_EXISTS = 0xed,                // TESTED. Check if KV exists.
    OP_KV_GET = 0xef,                   // TESTED. Get KV. 
    OP_KV_PUT = 0xf0,                   // TESTED. Put KV.
    OP_KV_DELETE = 0xf1,                // TESTED. Delete KV.

    OP_FT_WITHDRAW = 0xf2,              // TESTED. Mark an output for withdraw FT
    OP_NFT_WITHDRAW = 0xf3,             // TESTED. Mark an output for withdraw NFT
    
    OP_FT_BALANCE= 0xf4,                // TESTED. Get balance of FT held in contract
    OP_FT_COUNT = 0xf6,                 // TESTED. Get count of different unique FTs
    OP_FT_ITEM = 0xf7,                  // TESTED. Get a specific FT atomical id in sorted order
     
    OP_NFT_EXISTS = 0xf8,               // TESTED. Get specific NFT that exists
    OP_NFT_COUNT = 0xf9,                // TESTED. Get count of different unique NFTs
    OP_NFT_ITEM = 0xfa,                 // TESTED. Get a specfic NFT atomical id in sorted order
     
    OP_GETBLOCKINFO = 0xfb,             // TESTED. Get block info for height.
    OP_DECODEBLOCKINFO = 0xfc,          // TESTED. Decode a block header into the parts

    OP_HASH_FN = 0xfd,                  // TESTED. Various hash functions
   
    // The first op_code value after all defined opcodes
    FIRST_UNDEFINED_OP_VALUE,

    INVALIDOPCODE = 0xff,   ///< Not a real OPCODE!
};

// Maximum value that an opcode can be
static const unsigned int MAX_OPCODE = FIRST_UNDEFINED_OP_VALUE - 1;

const char *GetOpName(opcodetype opcode);

/**
 * Check whether the given stack element data would be minimally pushed using
 * the given opcode.
 */
bool CheckMinimalPush(const std::vector<uint8_t> &data, opcodetype opcode);

struct scriptnum_error : std::runtime_error {
    explicit
    scriptnum_error(const std::string &str)
        : std::runtime_error(str)
    {}
};

/**
 * Base template class for CScriptNum and ScriptInt. This class implements
 * some of the functionality common to both subclasses, and also captures
 * some enforcement of the consensus rules related to:
 *
 *  - valid 64 bit range (INT64_MIN is forbidden)
 *  - trapping for arithmetic operations that overflow or that produce a
 *    result equal to INT64_MIN
 */
template <typename Derived>
struct ScriptIntBase {
public:
    /**
     * Factory method to safely construct an instance from a raw int64_t.
     *
     * Note the unusual enforcement of the rules regarding valid 64-bit
     * ranges. We enforce a strict range of [INT64_MIN+1, INT64_MAX].
     */
    static constexpr
    std::optional<Derived> fromInt(int64_t x) noexcept {
        if ( ! valid64BitRange(x)) {
            return std::nullopt;
        }
        return Derived(x);
    }

    /// Performance/convenience optimization: Construct an instance from a raw
    /// int64_t where the caller already knows that the supplied value is in range.
    static constexpr
    Derived fromIntUnchecked(int64_t x) noexcept {
        return Derived(x);
    }

    constexpr
    bool operator==(int64_t x) const noexcept { return value_ == x; }

    constexpr
    bool operator!=(int64_t x) const noexcept { return value_ != x; }

    constexpr
    bool operator<=(int64_t x) const noexcept { return value_ <= x; }

    constexpr
    bool operator<(int64_t x) const noexcept { return value_ < x; }

    constexpr
    bool operator>=(int64_t x) const noexcept { return value_ >= x; }

    constexpr
    bool operator>(int64_t x) const noexcept { return value_ > x; }

    constexpr
    bool operator==(Derived const& x) const noexcept {
        return operator==(x.value_);
    }

    constexpr
    bool operator!=(Derived const& x) const noexcept {
        return operator!=(x.value_);
    }

    constexpr
    bool operator<=(Derived const& x) const noexcept {
        return operator<=(x.value_);
    }

    constexpr
    bool operator<(Derived const& x) const noexcept {
        return operator<(x.value_);
    }

    constexpr
    bool operator>=(Derived const& x) const noexcept {
        return operator>=(x.value_);
    }

    constexpr
    bool operator>(Derived const& x) const noexcept {
        return operator>(x.value_);
    }

    // Arithmetic operations
    std::optional<Derived> safeAdd(int64_t x) const noexcept {
        bool const res = __builtin_add_overflow(value_, x, &x);
        if (res) {
            return std::nullopt;
        }
        if ( ! valid64BitRange(x)) {
            return std::nullopt;
        }
        return Derived(x);
    }

    std::optional<Derived> safeAdd(Derived const& x) const noexcept {
        return safeAdd(x.value_);
    }

    std::optional<Derived> safeSub(int64_t x) const noexcept {
        bool const res = __builtin_sub_overflow(value_, x, &x);
        if (res) {
            return std::nullopt;
        }
        if ( ! valid64BitRange(x)) {
            return std::nullopt;
        }
        return Derived(x);
    }

    std::optional<Derived> safeSub(Derived const& x) const noexcept {
        return safeSub(x.value_);
    }

    std::optional<Derived> safeMul(int64_t x) const noexcept {
        bool const res = __builtin_mul_overflow(value_, x, &x);
        if (res) {
            return std::nullopt;
        }
        if ( ! valid64BitRange(x)) {
            return std::nullopt;
        }
        return Derived(x);
    }

    std::optional<Derived> safeMul(Derived const& x) const noexcept {
        return safeMul(x.value_);
    }

    constexpr
    Derived operator/(int64_t x) const noexcept {
        if (x == -1 && ! valid64BitRange(value_)) {
            // Guard against overflow, which can't normally happen unless class is misused
            // by the fromIntUnchecked() factory method (may happen in tests).
            // This will return INT64_MIN which is what ARM & x86 does anyway for INT64_MIN / -1.
            return Derived(value_);
        }
        return Derived(value_ / x);
    }

    constexpr
    Derived operator/(Derived const& x) const noexcept {
        return operator/(x.value_);
    }

    constexpr
    Derived operator%(int64_t x) const noexcept {
        if (x == -1 && ! valid64BitRange(value_)) {
            // INT64_MIN % -1 is UB in C++, but mathematically it would yield 0
            return Derived(0);
        }
        return Derived(value_ % x);
    }

    constexpr
    Derived operator%(Derived const& x) const noexcept {
        return operator%(x.value_);
    }

    // Bitwise operations
    std::optional<Derived> safeBitwiseAnd(int64_t x) const noexcept {
        x = value_ & x;
        if ( ! valid64BitRange(x)) {
            return std::nullopt;
        }
        return Derived(x);
    }

    std::optional<Derived> safeBitwiseAnd(Derived const& x) const noexcept {
        return safeBitwiseAnd(x.value_);
    }

    constexpr
    Derived operator-() const noexcept {
        // Defensive programming: -INT64_MIN is UB
        return Derived(valid64BitRange(value_) ? -value_ : value_);
    }

    constexpr
    int64_t getint64() const noexcept {
        return value_;
    }

protected:
    static constexpr
    bool valid64BitRange(int64_t x) {
        return x != std::numeric_limits<int64_t>::min();
    }

    explicit constexpr
    ScriptIntBase(int64_t x)
        : value_(x)
    {}

    int64_t value_;
};

/**
 * A ScriptInt is a "write-only" class designed to be used with
 * CScript in order to tell the CScript serialization engine to
 * represent small numbers in a more compact way.  It is
 * interchangeable with CScriptNum for serialization purposes,
 * except that for small numbers in the range [-1, 16] ScriptInt
 * ends up serializing slightly smaller, saving one byte.
 *
 * This is because the CScript class serializes ScriptInt differently
 * than it does CScriptNum for integers in the range [-1, 16].
 *
 * Whereas CScriptNum is always pushed as an encapsulated byte blob,
 * ScriptInt instances in the range [-1, 16] are pushed as raw bytes
 * directly (with some offsetting around OP_16 as the anchor).
 *
 * For numbers outside the [-1, 16] range, ScriptInt serializes
 * identically to CScriptNum.
 *
 * When the resulting script is interpreted by the script interpreter,
 * any values that are serialized in this more compact way are internally
 * transformed and normalized into CScriptNum instances on the stack
 * (see interpreter.cpp).  So the purpose of this class is simply as
 * a "type tag" to tell CScript to serialize in the more compact form,
 * if possible.
 *
 * In short, these two serialize differently:
 *
 *   CScript() << CScriptNum::fromIntUnchecked(10); // [PUSH(1) 0x0a] (2 bytes)
 *   CScript() << ScriptInt::fromIntUnchecked(10);  // [0x5a] (1 byte)
 *
 * However, for integers outside the range [-1, 16], the serialization
 * is identical:
 *
 *   CScript() << CScriptNum::fromIntUnchecked(42); // [PUSH(1) 0x2a] (2 bytes)
 *   CScript() << ScriptInt::fromIntUnchecked(42);  // Same as above
 *
 * Note that due to quirks in how CScriptNum serializes 0, these two
 * also serialize identically:
 *
 *   CScript() << CScriptNum::fromIntUnchecked(0);  // [PUSH(0)] == [0x00] (1 byte)
 *   CScript() << ScriptInt::fromIntUnchecked(0);   // [0x00] (1 byte)
 */
struct ScriptInt : ScriptIntBase<ScriptInt> {
    friend ScriptIntBase;

private:
    explicit constexpr
    ScriptInt(int64_t x) noexcept
        : ScriptIntBase(x)
    {}
};
 

/**
 * We use a prevector for the script to reduce the considerable memory overhead
 * of vectors in cases where they normally contain a small number of small
 * elements. Tests in October 2015 showed use of this reduced dbcache memory
 * usage by 23% and made an initial sync 13% faster.
 */
typedef prevector<28, uint8_t> CScriptBase;

bool GetScriptOp(CScriptBase::const_iterator &pc,
                 CScriptBase::const_iterator end, opcodetype &opcodeRet,
                 std::vector<uint8_t> *pvchRet);

/** Serialized script, used inside transaction inputs and outputs */
class CScript : public CScriptBase {
protected:
    CScript &push_int64(int64_t n) {
        if (n == -1 || (n >= 1 && n <= 16)) {
            push_back(n + (OP_1 - 1));
        } else if (n == 0) {
            push_back(OP_0);
        } else {
            std::vector<uint8_t> v;
            v.reserve(sizeof(n));
            avm::serialize(n, back_inserter(v));
            *this << v;
            //*this << CScriptNum::serialize(n);
        }
        return *this;
    }

public:
    CScript() {}
    CScript(const_iterator pbegin, const_iterator pend)
        : CScriptBase(pbegin, pend) {}
    CScript(std::vector<uint8_t>::const_iterator pbegin,
            std::vector<uint8_t>::const_iterator pend)
        : CScriptBase(pbegin, pend) {}
    CScript(const uint8_t *pbegin, const uint8_t *pend)
        : CScriptBase(pbegin, pend) {}

    SERIALIZE_METHODS(CScript, obj) { READWRITEAS(CScriptBase, obj); }

    CScript &operator+=(const CScript &b) {
        reserve(size() + b.size());
        insert(end(), b.begin(), b.end());
        return *this;
    }

    friend CScript operator+(const CScript &a, const CScript &b) {
        CScript ret = a;
        ret += b;
        return ret;
    }

    explicit CScript(opcodetype b) {
        operator<<(b);
    }
    explicit CScript(const CScriptNum &b) {
        operator<<(b);
    }
    explicit CScript(const std::vector<uint8_t> &b) { operator<<(b); }

    CScript &operator<<(opcodetype opcode) {
        if (opcode < 0 || opcode > 0xff) {
            throw std::runtime_error("CScript::operator<<(): invalid opcode");
        }
        insert(end(), uint8_t(opcode));
        return *this;
    }

    CScript &operator<<(const CScriptNum &b) {
        *this << b.getvch();
        return *this;
    }

    CScript& operator<<(ScriptInt const& x) {
        return push_int64(x.getint64());
    }

    CScript &operator<<(const std::vector<uint8_t> &b) {
        if (b.size() < OP_PUSHDATA1) {
            insert(end(), uint8_t(b.size()));
        } else if (b.size() <= 0xff) {
            insert(end(), OP_PUSHDATA1);
            insert(end(), uint8_t(b.size()));
        } else if (b.size() <= 0xffff) {
            insert(end(), OP_PUSHDATA2);
            uint8_t _data[2];
            WriteLE16(_data, b.size());
            insert(end(), _data, _data + sizeof(_data));
        } else {
            insert(end(), OP_PUSHDATA4);
            uint8_t _data[4];
            WriteLE32(_data, b.size());
            insert(end(), _data, _data + sizeof(_data));
        }
        insert(end(), b.begin(), b.end());
        return *this;
    }

    CScript &operator<<(const CScript &b) {
        // I'm not sure if this should push the script or concatenate scripts.
        // If there's ever a use for pushing a script onto a script, delete this
        // member fn.
        assert(!"Warning: Pushing a CScript onto a CScript with << is probably "
                "not intended, use + to concatenate!");
        return *this;
    }

    bool GetOp(const_iterator &pc, opcodetype &opcodeRet,
               std::vector<uint8_t> &vchRet) const {
        return GetScriptOp(pc, end(), opcodeRet, &vchRet);
    }

    bool GetOp(const_iterator &pc, opcodetype &opcodeRet) const {
        return GetScriptOp(pc, end(), opcodeRet, nullptr);
    }

    /** Encode/decode small integers: */
    static int DecodeOP_N(opcodetype opcode) {
        if (opcode == OP_0) {
            return 0;
        }

        assert(opcode >= OP_1 && opcode <= OP_16);
        return int(opcode) - int(OP_1 - 1);
    }
    static opcodetype EncodeOP_N(int n) {
        assert(n >= 0 && n <= 16);
        if (n == 0) {
            return OP_0;
        }

        return (opcodetype)(OP_1 + n - 1);
    }

    bool IsPayToScriptHash() const;
    bool IsCommitment(const std::vector<uint8_t> &data) const;
    bool IsWitnessProgram(int &version, std::vector<uint8_t> &program) const;
    bool IsWitnessProgram() const;

    /**
     * Called by IsStandardTx and P2SH/BIP62 VerifyScript (which makes it
     * consensus-critical).
     */
    bool IsPushOnly(const_iterator pc) const;
    bool IsPushOnly() const;

    /** Check if the script contains valid OP_CODES */
    bool HasValidOps() const;

    /**
     * Returns whether the script is guaranteed to fail at execution, regardless
     * of the initial stack. This allows outputs to be pruned instantly when
     * entering the UTXO set.
     */
    bool IsUnspendable() const {
        // We currently only detect OP_RETURN as provably unspendable.
        return (size() > 0 && *begin() == OP_RETURN);
    }

    bool IsSigOpReturn(std::vector<uint8_t>& sig) const {
        if (!IsUnspendable()) {
            return false;
        }
        bool hasSigMarker = *(begin() + 1) == 0x03 && *(begin() + 2) == 0x73 && *(begin() + 3) == 0x69 && *(begin() + 4) == 0x67;
        if (!hasSigMarker) {
            return false;
        }
        // Get the next push data
        opcodetype opcode;
        std::vector<uint8_t> item;
        // Get the op at the 6th position
        CScript::const_iterator it = begin() + 5;
        if (GetOp(it, opcode, item)) {
            // It was not a push data therefore it could not be a sig data
            if (opcode > OP_PUSHDATA4) {
                return false;
            }
            // It could be a signature type. Unknown length, but it could be 
            sig = item;
            return true;
        }
        return false;
    }

    void clear() {
        // The default prevector::clear() does not release memory
        CScriptBase::clear();
        shrink_to_fit();
    }
};

class CReserveScript {
public:
    CScript reserveScript;
    virtual void KeepScript() {}
    CReserveScript() {}
    virtual ~CReserveScript() {}
};

struct CScriptWitness
{
    // Note that this encodes the data elements being pushed, rather than
    // encoding them as a CScript that pushes them.
    CScript stack;

    // Some compilers complain without a default constructor
    CScriptWitness() { }

    bool IsNull() const { return stack.empty(); }

    void SetNull() { stack.clear(); stack.shrink_to_fit(); }

    std::string ToString() const;
};
