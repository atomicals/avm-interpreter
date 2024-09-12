// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <hash.h>
#include <pubkey.h>
#include <script/interpreter.h>
#include <script/sighashtype.h>
#include <streams.h>

class CKey;
class CKeyID;
class CMutableTransaction;
class CScript;
class CScriptID;
class CTransaction;

struct KeyOriginInfo {
    uint8_t fingerprint[4];
    std::vector<uint32_t> path;
};

/** An interface to be implemented by keystores that support signing. */
class SigningProvider {
public:
    virtual ~SigningProvider() {}
    virtual bool GetCScript(const CScriptID &scriptid, CScript &script) const {
        return false;
    }
    virtual bool HaveCScript(const CScriptID &scriptid) const { return false; }
    virtual bool GetPubKey(const CKeyID &address, CPubKey &pubkey) const {
        return false;
    }
    virtual bool GetKey(const CKeyID &address, CKey &key) const {
        return false;
    }
    virtual bool HaveKey(const CKeyID &address) const { return false; }
    virtual bool GetKeyOrigin(const CKeyID &keyid, KeyOriginInfo &info) const {
        return false;
    }
};
 
class HidingSigningProvider : public SigningProvider {
private:
    const bool m_hide_secret;
    const bool m_hide_origin;
    const SigningProvider *m_provider;

public:
    HidingSigningProvider(const SigningProvider *provider, bool hide_secret,
                          bool hide_origin)
        : m_hide_secret(hide_secret), m_hide_origin(hide_origin),
          m_provider(provider) {}
    bool GetCScript(const CScriptID &scriptid, CScript &script) const override;
    bool GetPubKey(const CKeyID &keyid, CPubKey &pubkey) const override;
    bool GetKey(const CKeyID &keyid, CKey &key) const override;
    bool GetKeyOrigin(const CKeyID &keyid, KeyOriginInfo &info) const override;
};

struct FlatSigningProvider final : public SigningProvider {
    std::map<CScriptID, CScript> scripts;
    std::map<CKeyID, CPubKey> pubkeys;
    std::map<CKeyID, KeyOriginInfo> origins;
    std::map<CKeyID, CKey> keys;

    bool GetCScript(const CScriptID &scriptid, CScript &script) const override;
    bool GetPubKey(const CKeyID &keyid, CPubKey &pubkey) const override;
    bool GetKeyOrigin(const CKeyID &keyid, KeyOriginInfo &info) const override;
    bool GetKey(const CKeyID &keyid, CKey &key) const override;
};

FlatSigningProvider Merge(const FlatSigningProvider &a,
                          const FlatSigningProvider &b);

/** Interface for signature creators. */
class BaseSignatureCreator {
public:
    virtual ~BaseSignatureCreator() {}
    virtual const BaseSignatureChecker &Checker() const = 0;

    /** Create a singular (non-script) signature. */
    virtual bool CreateSig(const SigningProvider &provider,
                           std::vector<uint8_t> &vchSig, const CKeyID &keyid,
                           const CScript &scriptCode) const = 0;
};

/** A signature creator for transactions. */
class MutableTransactionSignatureCreator : public BaseSignatureCreator {
    const CMutableTransaction *txTo;
    unsigned int nIn;
    Amount amount;
    SigHashType sigHashType;
    const MutableTransactionSignatureChecker checker;

public:
    MutableTransactionSignatureCreator(
        const CMutableTransaction *txToIn, unsigned int nInIn,
        const Amount &amountIn, SigHashType sigHashTypeIn = SigHashType());
    const BaseSignatureChecker &Checker() const override { return checker; }
    bool CreateSig(const SigningProvider &provider,
                   std::vector<uint8_t> &vchSig, const CKeyID &keyid,
                   const CScript &scriptCode) const override;
};

typedef std::pair<CPubKey, std::vector<uint8_t>> SigPair;

// This struct contains information from a transaction input and also contains
// signatures for that input. The information contained here can be used to
// create a signature and is also filled by ProduceSignature in order to
// construct final scriptSigs.
struct SignatureData {
    /// Stores whether the scriptSig are complete.
    bool complete = false;
    /// The scriptSig of an input. Contains complete signatures or the
    /// traditional partial signatures format.
    CScript scriptSig;
    /// The redeemScript (if any) for the input.
    CScript redeem_script;
    /// BIP 174 style partial signatures for the input. May contain all
    /// signatures necessary for producing a final scriptSig.
    std::map<CKeyID, SigPair> signatures;
    std::map<CKeyID, std::pair<CPubKey, KeyOriginInfo>> misc_pubkeys;

    SignatureData() {}
    explicit SignatureData(const CScript &script) : scriptSig(script) {}
    void MergeSignatureData(SignatureData sigdata);
};

// Takes a stream and multiple arguments and serializes them as if first
// serialized into a vector and then into the stream. The resulting output into
// the stream has the total serialized length of all of the objects followed by
// all objects concatenated with each other.
template <typename Stream, typename... X>
void SerializeToVector(Stream &s, const X &... args) {
    WriteCompactSize(s, GetSerializeSizeMany(s.GetVersion(), args...));
    SerializeMany(s, args...);
}

// Takes a stream and multiple arguments and unserializes them first as a vector
// then each object individually in the order provided in the arguments.
template <typename Stream, typename... X>
void UnserializeFromVector(Stream &s, X &... args) {
    size_t expected_size = ReadCompactSize(s);
    size_t remaining_before = s.size();
    UnserializeMany(s, args...);
    size_t remaining_after = s.size();
    if (remaining_after + expected_size != remaining_before) {
        throw std::ios_base::failure("Size of value was not the stated size");
    }
}

// Deserialize HD keypaths into a map
template <typename Stream>
void DeserializeHDKeypaths(Stream &s, const std::vector<uint8_t> &key,
                           std::map<CPubKey, KeyOriginInfo> &hd_keypaths) {
    // Make sure that the key is the size of pubkey + 1
    if (key.size() != CPubKey::PUBLIC_KEY_SIZE + 1 &&
        key.size() != CPubKey::COMPRESSED_PUBLIC_KEY_SIZE + 1) {
        throw std::ios_base::failure(
            "Size of key was not the expected size for the type BIP32 keypath");
    }
    // Read in the pubkey from key
    CPubKey pubkey(key.begin() + 1, key.end());
    if (!pubkey.IsFullyValid()) {
        throw std::ios_base::failure("Invalid pubkey");
    }
    if (hd_keypaths.count(pubkey) > 0) {
        throw std::ios_base::failure(
            "Duplicate Key, pubkey derivation path already provided");
    }

    // Read in key path
    uint64_t value_len = ReadCompactSize(s);
    if (value_len % 4 || value_len == 0) {
        throw std::ios_base::failure("Invalid length for HD key path");
    }

    KeyOriginInfo keypath;
    s >> keypath.fingerprint;
    for (unsigned int i = 4; i < value_len; i += sizeof(uint32_t)) {
        uint32_t index;
        s >> index;
        keypath.path.push_back(index);
    }

    // Add to map
    hd_keypaths.emplace(pubkey, std::move(keypath));
}

// Serialize HD keypaths to a stream from a map
template <typename Stream>
void SerializeHDKeypaths(Stream &s,
                         const std::map<CPubKey, KeyOriginInfo> &hd_keypaths,
                         uint8_t type) {
    for (auto keypath_pair : hd_keypaths) {
        SerializeToVector(s, type, MakeSpan(keypath_pair.first));
        WriteCompactSize(s, (keypath_pair.second.path.size() + 1) *
                                sizeof(uint32_t));
        s << keypath_pair.second.fingerprint;
        for (const auto &path : keypath_pair.second.path) {
            s << path;
        }
    }
}

void UpdateInput(CTxIn &input, const SignatureData &data);
