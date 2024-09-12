// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2017-2020 The Bitcoin developers
// Copyright (c) 2024 The Atomicals Developers and Supporters
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <primitives/transaction.h>
#include <script/script_error.h>
#include <script/script_execution_context.h>
#include <script/script_flags.h>
#include <script/script_metrics.h>
#include <script/sighashtype.h>
#include <script/script_num.h>

#include <cstdint>
#include <string>
#include <vector>

class CPubKey;
class CScript;
class CTransaction;
class uint256;

using StackT = std::vector<std::vector<uint8_t>>;

template <class T>
uint256 SignatureHash(const CScript &scriptCode, const T &txTo, unsigned int nIn, SigHashType sigHashType,
                      const Amount amount, const PrecomputedTransactionData *cache = nullptr, uint32_t flags = 0);

class BaseSignatureChecker {
public:
    virtual bool VerifySignature(const std::vector<uint8_t> &vchSig, const CPubKey &vchPubKey,
                                 const uint256 &sighash) const;

    virtual bool CheckSig(const std::vector<uint8_t> &vchSigIn, const std::vector<uint8_t> &vchPubKey,
                          const CScript &scriptCode, uint32_t flags) const {
        return false;
    }

    virtual bool CheckLockTime(const CScriptNum &nLockTime) const { return false; }

    virtual bool CheckSequence(const CScriptNum &nSequence) const { return false; }

    virtual ~BaseSignatureChecker() {}
};

template <class T>
class GenericTransactionSignatureChecker : public BaseSignatureChecker {
private:
    const T *txTo;
    unsigned int nIn;
    const Amount amount;
    const PrecomputedTransactionData *txdata;

public:
    GenericTransactionSignatureChecker(const T *txToIn, unsigned int nInIn, const Amount &amountIn)
        : txTo(txToIn), nIn(nInIn), amount(amountIn), txdata(nullptr) {}
    GenericTransactionSignatureChecker(const T *txToIn, unsigned int nInIn, const Amount &amountIn,
                                       const PrecomputedTransactionData &txdataIn)
        : txTo(txToIn), nIn(nInIn), amount(amountIn), txdata(&txdataIn) {}

    // The overridden functions are now final.
    bool CheckSig(const std::vector<uint8_t> &vchSigIn, const std::vector<uint8_t> &vchPubKey,
                  const CScript &scriptCode, uint32_t flags) const final override;
    bool CheckLockTime(const CScriptNum &nLockTime) const final override;
    bool CheckSequence(const CScriptNum &nSequence) const final override;
};

using TransactionSignatureChecker = GenericTransactionSignatureChecker<CTransaction>;
using MutableTransactionSignatureChecker = GenericTransactionSignatureChecker<CMutableTransaction>;

bool EvalScript(StackT &stack, const CScript &script, uint32_t flags, const BaseSignatureChecker &checker,
                ScriptExecutionMetrics &metrics, ScriptExecutionContextOpt const &context,
                ScriptStateContext &stateContext, ScriptError *serror = nullptr, unsigned int *serror_op_num = nullptr);

bool EvalScript(StackT &stack, const CScript &script, uint32_t flags, const BaseSignatureChecker &checker,
                ScriptExecutionMetrics &metrics, ScriptExecutionContextOpt const &context,
                ScriptError *serror = nullptr, unsigned int *serror_op_num = nullptr);

static inline bool EvalScript(StackT &stack, const CScript &script, uint32_t flags, const BaseSignatureChecker &checker,
                              ScriptExecutionContextOpt const &context, ScriptError *serror = nullptr,
                              unsigned int *serror_op_num = nullptr) {
    ScriptExecutionMetrics dummymetrics;
    return EvalScript(stack, script, flags, checker, dummymetrics, context, serror, serror_op_num);
}

int FindAndDelete(CScript &script, const CScript &b);

/**
 * Added for Atomicals AVM
 * Execute an unlocking and locking script together.
 *
 * Upon success, metrics will hold the accumulated script metrics.
 * (upon failure, the results should not be relied on)
 */
bool VerifyScriptAvm(const CScript &scriptSig, const CScript &scriptPubKey, uint32_t flags,
                     const BaseSignatureChecker &checker, ScriptExecutionMetrics &metricsOut,
                     ScriptExecutionContextOpt const &context, ScriptStateContext &state, ScriptError *serror = nullptr,
                     unsigned int *serror_op_num = nullptr);

static inline bool VerifyScriptAvm(const CScript &scriptSig, const CScript &scriptPubKey,
                                   const BaseSignatureChecker &checker, ScriptExecutionContextOpt const &context,
                                   ScriptStateContext &state, ScriptError *serror = nullptr,
                                   unsigned int *serror_op_num = nullptr) {
    ScriptExecutionMetrics dummymetrics;
    uint32_t flags(0);

    flags |= SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY;
    return VerifyScriptAvm(scriptSig, scriptPubKey, flags, checker, dummymetrics, context, state, serror,
                           serror_op_num);
}
