// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2017-2019 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <amount.h>
#include <feerate.h>
#include <primitives/txid.h>
#include <script/script.h>
#include <serialize.h>
#include "hash.h"
#include <iostream>

static const int SERIALIZE_TRANSACTION = 0x00;
 
/** An outpoint - a combination of a transaction hash and an index n into its vout */
class COutPoint
{
public:
    TxId hash;
    uint32_t n;

    static constexpr uint32_t NULL_INDEX = std::numeric_limits<uint32_t>::max();

    COutPoint(): n(NULL_INDEX) { }
    COutPoint(const TxId& hashIn, uint32_t nIn): hash(hashIn), n(nIn) { }

    SERIALIZE_METHODS(COutPoint, obj) { READWRITE(obj.hash, obj.n); }

    void SetNull() { hash.SetNull(); n = NULL_INDEX; }
    bool IsNull() const { return (hash.IsNull() && n == NULL_INDEX); }

    const TxId &GetTxId() const { return hash; }
    uint32_t GetN() const { return n; }

    friend bool operator<(const COutPoint& a, const COutPoint& b)
    {
        return std::tie(a.hash, a.n) < std::tie(b.hash, b.n);
    }

    friend bool operator==(const COutPoint& a, const COutPoint& b)
    {
        return (a.hash == b.hash && a.n == b.n);
    }

    friend bool operator!=(const COutPoint& a, const COutPoint& b)
    {
        return !(a == b);
    }

    std::string ToString() const;
};

/** An input of a transaction.  It contains the location of the previous
 * transaction's output that it claims and a signature that matches the
 * output's public key.
 */
class CTxIn
{
public:
    COutPoint prevout;
    CScript scriptSig;
    uint32_t nSequence;
    CScriptWitness scriptWitness; //!< Only serialized through CTransaction

    /**
     * Setting nSequence to this value for every input in a transaction
     * disables nLockTime/IsFinalTx().
     * It fails OP_CHECKLOCKTIMEVERIFY/CheckLockTime() for any input that has
     * it set (BIP 65).
     * It has SEQUENCE_LOCKTIME_DISABLE_FLAG set (BIP 68/112).
     */
    static const uint32_t SEQUENCE_FINAL = 0xffffffff;
    /**
     * This is the maximum sequence number that enables both nLockTime and
     * OP_CHECKLOCKTIMEVERIFY (BIP 65).
     * It has SEQUENCE_LOCKTIME_DISABLE_FLAG set (BIP 68/112).
     */
    static const uint32_t MAX_SEQUENCE_NONFINAL{SEQUENCE_FINAL - 1};

    // Below flags apply in the context of BIP 68. BIP 68 requires the tx
    // version to be set to 2, or higher.
    /**
     * If this flag is set, CTxIn::nSequence is NOT interpreted as a
     * relative lock-time.
     * It skips SequenceLocks() for any input that has it set (BIP 68).
     * It fails OP_CHECKSEQUENCEVERIFY/CheckSequence() for any input that has
     * it set (BIP 112).
     */
    static const uint32_t SEQUENCE_LOCKTIME_DISABLE_FLAG = (1U << 31);

    /**
     * If CTxIn::nSequence encodes a relative lock-time and this flag
     * is set, the relative lock-time has units of 512 seconds,
     * otherwise it specifies blocks with a granularity of 1. */
    static const uint32_t SEQUENCE_LOCKTIME_TYPE_FLAG = (1 << 22);

    /**
     * If CTxIn::nSequence encodes a relative lock-time, this mask is
     * applied to extract that lock-time from the sequence field. */
    static const uint32_t SEQUENCE_LOCKTIME_MASK = 0x0000ffff;

    /**
     * In order to use the same number of bits to encode roughly the
     * same wall-clock duration, and because blocks are naturally
     * limited to occur every 600s on average, the minimum granularity
     * for time-based relative lock-time is fixed at 512 seconds.
     * Converting from CTxIn::nSequence to seconds is performed by
     * multiplying by 512 = 2^9, or equivalently shifting up by
     * 9 bits. */
    static const int SEQUENCE_LOCKTIME_GRANULARITY = 9;

    CTxIn()
    {
        nSequence = SEQUENCE_FINAL;
    }

    explicit CTxIn(COutPoint prevoutIn, CScript scriptSigIn=CScript(), uint32_t nSequenceIn=SEQUENCE_FINAL);
    CTxIn(TxId hashPrevTx, uint32_t nOut, CScript scriptSigIn=CScript(), uint32_t nSequenceIn=SEQUENCE_FINAL);

    SERIALIZE_METHODS(CTxIn, obj) { READWRITE(obj.prevout, obj.scriptSig, obj.nSequence); }

    friend bool operator==(const CTxIn& a, const CTxIn& b)
    {
        return (a.prevout   == b.prevout &&
                a.scriptSig == b.scriptSig &&
                a.nSequence == b.nSequence);
    }

    friend bool operator!=(const CTxIn& a, const CTxIn& b)
    {
        return !(a == b);
    }

    std::string ToString() const;
};

/** An output of a transaction.  It contains the public key that the next input
 * must be able to sign with to claim it.
 */
class CTxOut
{
public:
    Amount nValue;
    CScript scriptPubKey;

    CTxOut()
    {
        SetNull();
    }

    CTxOut(const Amount& nValueIn, CScript scriptPubKeyIn);

    SERIALIZE_METHODS(CTxOut, obj) { READWRITE(obj.nValue, obj.scriptPubKey); }

    void SetNull()
    {
        nValue = -SATOSHI;
        scriptPubKey.clear();
    }

    bool IsNull() const
    {
        return (nValue == -SATOSHI);
    }

    friend bool operator==(const CTxOut& a, const CTxOut& b)
    {
        return (a.nValue       == b.nValue &&
                a.scriptPubKey == b.scriptPubKey);
    }

    friend bool operator!=(const CTxOut& a, const CTxOut& b)
    {
        return !(a == b);
    }

    std::string ToString() const;
};

class CMutableTransaction;
  
/**
 * Basic transaction serialization format:
 * - int32_t nVersion
 * - std::vector<CTxIn> vin
 * - std::vector<CTxOut> vout
 * - uint32_t nLockTime
 *
 * Extended transaction serialization format:
 * - int32_t nVersion
 * - unsigned char dummy = 0x00
 * - unsigned char flags (!= 0)
 * - std::vector<CTxIn> vin
 * - std::vector<CTxOut> vout
 * - if (flags & 1):
 *   - CScriptWitness scriptWitness; (deserialized into CTxIn)
 * - uint32_t nLockTime
 */
template<typename Stream, typename TxType>
void UnserializeTransaction(TxType& tx, Stream& s)
{
    const bool fAllowWitness = true;

    s >> tx.nVersion;
    unsigned char flags = 0;
    tx.vin.clear();
    tx.vout.clear();
    /* Try to read the vin. In case the dummy is there, this will be read as an empty vector. */
    s >> tx.vin;
    if (tx.vin.size() == 0 && fAllowWitness) {
        /* We read a dummy or an empty vin. */
        s >> flags;
        if (flags != 0) {
            s >> tx.vin;
            s >> tx.vout;
        }
    } else {
        /* We read a non-empty vin. Assume a normal vout follows. */
        s >> tx.vout;
    }
    if ((flags & 1) && fAllowWitness) {
        /* The witness flag is present, and we support witnesses. */
        flags ^= 1;
        for (size_t i = 0; i < tx.vin.size(); i++) {
            s >> tx.vin[i].scriptWitness.stack;
        }
        if (!tx.HasWitness()) {
            /* It's illegal to encode witnesses when all witness stacks are empty. */
            throw std::ios_base::failure("Superfluous witness record");
        }
    }
    if (flags) {
        /* Unknown flag in the serialization */
        throw std::ios_base::failure("Unknown transaction optional data");
    }
    s >> tx.nLockTime;
}

template<typename Stream, typename TxType>
void SerializeTransaction(const TxType& tx, Stream& s)
{
    const bool fAllowWitness = true;
    s << tx.nVersion;
    unsigned char flags = 0;
    // Consistency check
    if (fAllowWitness) {
        /* Check whether witnesses need to be serialized. */
        if (tx.HasWitness()) {
            flags |= 1;
        }
    }
    if (flags) {
        /* Use extended format in case witnesses are to be serialized. */
        std::vector<CTxIn> vinDummy;
        s << vinDummy;
        s << flags;
    }
    s << tx.vin;
    s << tx.vout;
    if (flags & 1) {
        for (size_t i = 0; i < tx.vin.size(); i++) {
            s << tx.vin[i].scriptWitness.stack;
        }
    }
    s << tx.nLockTime;
}

class CTransaction;
using CTransactionRef = std::shared_ptr<const CTransaction>;

/**
 * The basic transaction that is broadcasted on the network and contained in
 * blocks. A transaction can contain multiple inputs and outputs.
 */
class CTransaction final {
public:
    // Default transaction version.
    static const int32_t CURRENT_VERSION = 2;

    // Changing the default transaction version requires a two step process:
    // first adapting relay policy by bumping MAX_STANDARD_VERSION, and then
    // later date bumping the default CURRENT_VERSION at which point both
    // CURRENT_VERSION and MAX_STANDARD_VERSION will be equal.
    static const int32_t MAX_STANDARD_VERSION = 2;

    // The local variables are made const to prevent unintended modification
    // without updating the cached hash value. However, CTransaction is not
    // actually immutable; deserialization and assignment are implemented,
    // and bypass the constness. This is safe, as they update the entire
    // structure, including the hash.
    const std::vector<CTxIn> vin;
    const std::vector<CTxOut> vout;
    const int32_t nVersion;
    const uint32_t nLockTime;

private:
    /** Memory only. */
    const uint256 hash;

    uint256 ComputeHash() const;

    /** Construct a CTransaction that qualifies as IsNull() */
    CTransaction();


    /** Memory only. */
    const bool m_has_witness;
    // const Txid hash;
    const uint256 m_witness_hash;

    //Txid ComputeHash() const;
    uint256 ComputeWitnessHash() const;

    bool ComputeHasWitness() const;

public:
    /** Default-constructed CTransaction that qualifies as IsNull() */
    static const CTransaction null;
    //! Points to null (with a no-op deleter)
    static const CTransactionRef sharedNull;

    /** Convert a CMutableTransaction into a CTransaction. */
    explicit CTransaction(const CMutableTransaction &tx);
    explicit CTransaction(CMutableTransaction &&tx);

    /**
     * We prevent copy assignment & construction to enforce use of
     * CTransactionRef, as well as prevent new code from inadvertently copying
     * around these potentially very heavy objects.
     */
    CTransaction(const CTransaction &) = delete;
    CTransaction &operator=(const CTransaction &) = delete;

    template <typename Stream> inline void Serialize(Stream &s) const {
        SerializeTransaction(*this, s);
    }

    /**
     * This deserializing constructor is provided instead of an Unserialize
     * method. Unserialize is not possible, since it would require overwriting
     * const fields.
     */
    template <typename Stream>
    CTransaction(deserialize_type, Stream &s)
        : CTransaction(CMutableTransaction(deserialize, s)) {}

    bool IsNull() const { return vin.empty() && vout.empty(); }

    const TxId GetId() const { return TxId(hash); }
    const TxHash GetHash() const { return TxHash(hash); }
    const TxHash& GetWitnessHash() const { return TxHash(m_witness_hash); };
    // Return sum of txouts.
    Amount GetValueOut() const;
    // GetValueIn() is a method on CCoinsViewCache, because
    // inputs must be known to compute value in.

    /**
     * Get the total transaction size in bytes.
     * @return Total transaction size in bytes
     */
    unsigned int GetTotalSize() const;

    bool IsCoinBase() const {
        return (vin.size() == 1 && vin[0].prevout.IsNull());
    }

    friend bool operator==(const CTransaction &a, const CTransaction &b) {
        return a.GetHash() == b.GetHash();
    }

    friend bool operator!=(const CTransaction &a, const CTransaction &b) {
        return !(a == b);
    }

    std::string ToString() const;

    bool HasWitness() const { return m_has_witness; }
};

/**
 * A mutable version of CTransaction.
 */
class CMutableTransaction {
public:
    std::vector<CTxIn> vin;
    std::vector<CTxOut> vout;
    int32_t nVersion;
    uint32_t nLockTime;

    CMutableTransaction();
    explicit CMutableTransaction(const CTransaction &tx);

    template <typename Stream> inline void Serialize(Stream &s) const {
        SerializeTransaction(*this, s);
    }

    template <typename Stream> inline void Unserialize(Stream &s) {
        UnserializeTransaction(*this, s);
    }

    template <typename Stream>
    CMutableTransaction(deserialize_type, Stream &s) {
        Unserialize(s);
    }

    /**
     * Compute the id and hash of this CMutableTransaction. This is computed on
     * the fly, as opposed to GetId() and GetHash() in CTransaction, which uses
     * a cached result.
     */
    TxId GetId() const;
    TxHash GetHash() const;
    bool HasWitness() const
    {
        for (size_t i = 0; i < vin.size(); i++) {
            if (!vin[i].scriptWitness.IsNull()) {
                return true;
            }
        }
        return false;
    }
    friend bool operator==(const CMutableTransaction &a,
                           const CMutableTransaction &b) {
        return a.GetHash() == b.GetHash();
    }
};
 

#if defined(__x86_64__)
static_assert(sizeof(CMutableTransaction) == 56,
              "sizeof CMutableTransaction is expected to be 56 bytes");
#endif

static inline CTransactionRef MakeTransactionRef() { return CTransaction::sharedNull; }

template <typename Tx>
static inline CTransactionRef MakeTransactionRef(Tx &&txIn) {
    return std::make_shared<const CTransaction>(std::forward<Tx>(txIn));
}

/** Precompute sighash midstate to avoid quadratic hashing */
struct PrecomputedTransactionData {
    uint256 hashPrevouts, hashSequence, hashOutputs;

    PrecomputedTransactionData() = default;

    template <class T> explicit PrecomputedTransactionData(const T &tx);
};

/// A class that wraps a pointer to either a CTransaction or a
/// CMutableTransaction and presents a uniform view of the minimal
/// intersection of both classes' exposed data.
///
/// This is used by the native introspection code to make it possible for
/// mutable txs as well constant txs to be treated uniformly for the purposes
/// of the native introspection opcodes.
///
/// Contract is: The wrapped tx or mtx pointer must have a lifetime at least
///              as long as an instance of this class.
class CTransactionView {
    const CTransaction *tx{};
    const CMutableTransaction *mtx{};
public:
    CTransactionView(const CTransaction &txIn) noexcept : tx(&txIn) {}
    CTransactionView(const CMutableTransaction &mtxIn) noexcept : mtx(&mtxIn) {}

    bool isMutableTx() const noexcept { return mtx; }

    const std::vector<CTxIn> &vin() const noexcept { return mtx ? mtx->vin : tx->vin; }
    const std::vector<CTxOut> &vout() const noexcept { return mtx ? mtx->vout : tx->vout; }
    const int32_t &nVersion() const noexcept { return mtx ? mtx->nVersion : tx->nVersion; }
    const uint32_t &nLockTime() const noexcept { return mtx ? mtx->nLockTime : tx->nLockTime; }

    TxId GetId() const { return mtx ? mtx->GetId() : tx->GetId(); }
    TxHash GetHash() const { return mtx ? mtx->GetHash() : tx->GetHash(); }

    bool operator==(const CTransactionView &o) const noexcept {
        return isMutableTx() == o.isMutableTx() && (mtx ? *mtx == *o.mtx : *tx == *o.tx);
    }
    bool operator!=(const CTransactionView &o) const noexcept { return !operator==(o); }

    /// Get a pointer to the underlying constant transaction, if such a thing exists.
    /// This is used by the validation engine which is always passed a CTransaction.
    /// Returned pointer will be nullptr if this->isMutableTx()
    const CTransaction *constantTx() const { return tx; }
};
 