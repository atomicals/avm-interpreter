// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2020 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <script/sign.h>

#include <key.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <script/standard.h>
#include <uint256.h>

typedef std::vector<uint8_t> valtype;

MutableTransactionSignatureCreator::MutableTransactionSignatureCreator(
    const CMutableTransaction *txToIn, unsigned int nInIn,
    const Amount &amountIn, SigHashType sigHashTypeIn)
    : txTo(txToIn), nIn(nInIn), amount(amountIn), sigHashType(sigHashTypeIn),
      checker(txTo, nIn, amountIn) {}

bool MutableTransactionSignatureCreator::CreateSig(
    const SigningProvider &provider, std::vector<uint8_t> &vchSig,
    const CKeyID &address, const CScript &scriptCode) const {
    CKey key;
    if (!provider.GetKey(address, key)) {
        return false;
    }

    uint256 hash = SignatureHash(scriptCode, *txTo, nIn, sigHashType, amount);
    if (!key.SignECDSA(hash, vchSig)) {
        return false;
    }

    vchSig.push_back(uint8_t(sigHashType.getRawSigHashType()));
    return true;
}

static bool GetCScript(const SigningProvider &provider,
                       const SignatureData &sigdata, const CScriptID &scriptid,
                       CScript &script) {
    if (provider.GetCScript(scriptid, script)) {
        return true;
    }
    // Look for scripts in SignatureData
    if (CScriptID(sigdata.redeem_script) == scriptid) {
        script = sigdata.redeem_script;
        return true;
    }
    return false;
}
 
class SignatureExtractorChecker final : public BaseSignatureChecker {
private:
    SignatureData &sigdata;
    BaseSignatureChecker &checker;

public:
    SignatureExtractorChecker(SignatureData &sigdata_,
                              BaseSignatureChecker &checker_)
        : sigdata(sigdata_), checker(checker_) {}
    bool CheckSig(const std::vector<uint8_t> &scriptSig,
                  const std::vector<uint8_t> &vchPubKey,
                  const CScript &scriptCode, uint32_t flags) const override;
};

bool SignatureExtractorChecker::CheckSig(const std::vector<uint8_t> &scriptSig,
                                         const std::vector<uint8_t> &vchPubKey,
                                         const CScript &scriptCode,
                                         uint32_t flags) const {
    if (checker.CheckSig(scriptSig, vchPubKey, scriptCode, flags)) {
        CPubKey pubkey(vchPubKey);
        sigdata.signatures.emplace(std::piecewise_construct,
                                   std::forward_as_tuple(pubkey.GetID()),
                                   std::forward_as_tuple(pubkey, scriptSig));
        return true;
    }
    return false;
}

namespace {
struct Stacks {
    std::vector<valtype> script;

    Stacks() = delete;
    Stacks(const Stacks &) = delete;

    Stacks(const SignatureData &data, ScriptExecutionContextOpt const& context) {
        if (data.scriptSig.IsPushOnly()) {
            EvalScript(script, data.scriptSig, SCRIPT_VERIFY_NONE, BaseSignatureChecker(), context);
        }
    }
};
} // namespace
 

void UpdateInput(CTxIn &input, const SignatureData &data) {
    input.scriptSig = data.scriptSig;
}

void SignatureData::MergeSignatureData(SignatureData sigdata) {
    if (complete) {
        return;
    }
    if (sigdata.complete) {
        *this = std::move(sigdata);
        return;
    }
    if (redeem_script.empty() && !sigdata.redeem_script.empty()) {
        redeem_script = sigdata.redeem_script;
    }
    signatures.insert(std::make_move_iterator(sigdata.signatures.begin()),
                      std::make_move_iterator(sigdata.signatures.end()));
}
 
/** Dummy signature checker which accepts all signatures. */
class DummySignatureChecker final : public BaseSignatureChecker {
public:
    DummySignatureChecker() {}
    bool CheckSig(const std::vector<uint8_t> &scriptSig,
                  const std::vector<uint8_t> &vchPubKey,
                  const CScript &scriptCode, uint32_t flags) const override {
        return true;
    }
};
const DummySignatureChecker DUMMY_CHECKER;

class DummySignatureCreator final : public BaseSignatureCreator {
private:
    char m_r_len = 32;
    char m_s_len = 32;

public:
    DummySignatureCreator(char r_len, char s_len)
        : m_r_len(r_len), m_s_len(s_len) {}
    const BaseSignatureChecker &Checker() const override {
        return DUMMY_CHECKER;
    }
    bool CreateSig(const SigningProvider &provider,
                   std::vector<uint8_t> &vchSig, const CKeyID &keyid,
                   const CScript &scriptCode) const override {
        // Create a dummy signature that is a valid DER-encoding
        vchSig.assign(m_r_len + m_s_len + 7, '\000');
        vchSig[0] = 0x30;
        vchSig[1] = m_r_len + m_s_len + 4;
        vchSig[2] = 0x02;
        vchSig[3] = m_r_len;
        vchSig[4] = 0x01;
        vchSig[4 + m_r_len] = 0x02;
        vchSig[5 + m_r_len] = m_s_len;
        vchSig[6 + m_r_len] = 0x01;
        vchSig[6 + m_r_len + m_s_len] = SIGHASH_ALL | SIGHASH_FORKID;
        return true;
    }
};

template <typename M, typename K, typename V>
bool LookupHelper(const M &map, const K &key, V &value) {
    auto it = map.find(key);
    if (it != map.end()) {
        value = it->second;
        return true;
    }
    return false;
}
 
bool HidingSigningProvider::GetCScript(const CScriptID &scriptid, CScript &script) const {
    return m_provider->GetCScript(scriptid, script);
}

bool HidingSigningProvider::GetPubKey(const CKeyID &keyid,
                                      CPubKey &pubkey) const {
    return m_provider->GetPubKey(keyid, pubkey);
}

bool HidingSigningProvider::GetKey(const CKeyID &keyid, CKey &key) const {
    if (m_hide_secret) {
        return false;
    }
    return m_provider->GetKey(keyid, key);
}

bool HidingSigningProvider::GetKeyOrigin(const CKeyID &keyid,
                                         KeyOriginInfo &info) const {
    if (m_hide_origin) {
        return false;
    }
    return m_provider->GetKeyOrigin(keyid, info);
}

bool FlatSigningProvider::GetCScript(const CScriptID &scriptid, CScript &script) const {
    return LookupHelper(scripts, scriptid, script);
}
bool FlatSigningProvider::GetPubKey(const CKeyID &keyid, CPubKey &pubkey) const {
    return LookupHelper(pubkeys, keyid, pubkey);
}
bool FlatSigningProvider::GetKeyOrigin(const CKeyID &keyid, KeyOriginInfo &info) const {
    return LookupHelper(origins, keyid, info);
}
bool FlatSigningProvider::GetKey(const CKeyID &keyid, CKey &key) const {
    return LookupHelper(keys, keyid, key);
}

FlatSigningProvider Merge(const FlatSigningProvider &a, const FlatSigningProvider &b) {
    FlatSigningProvider ret;
    ret.scripts = a.scripts;
    ret.scripts.insert(b.scripts.begin(), b.scripts.end());
    ret.pubkeys = a.pubkeys;
    ret.pubkeys.insert(b.pubkeys.begin(), b.pubkeys.end());
    ret.keys = a.keys;
    ret.keys.insert(b.keys.begin(), b.keys.end());
    return ret;
}
 