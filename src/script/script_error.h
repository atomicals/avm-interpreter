// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

enum class ScriptError {
    OK = 0,
    UNKNOWN,
    EVAL_FALSE,
    OP_RETURN,

    /* Max sizes */
    SCRIPT_SIZE,
    PUSH_SIZE,
    OP_COUNT,
    STACK_SIZE,
    SIG_COUNT,
    PUBKEY_COUNT,
    INPUT_SIGCHECKS,

    /* Operands checks */
    INVALID_OPERAND_SIZE,
    INVALID_NUMBER_RANGE,
    IMPOSSIBLE_ENCODING,
    INVALID_SPLIT_RANGE,
    INVALID_BIT_COUNT,

    /* Failed verify operations */
    VERIFY,
    EQUALVERIFY,
    CHECKMULTISIGVERIFY,
    CHECKSIGVERIFY,
    CHECKDATASIGVERIFY,
    NUMEQUALVERIFY,

    /* Logical/Format/Canonical errors */
    BAD_OPCODE,
    DISABLED_OPCODE,
    INVALID_STACK_OPERATION,
    INVALID_ALTSTACK_OPERATION,
    UNBALANCED_CONDITIONAL,

    /* Divisor errors */
    DIV_BY_ZERO,
    MOD_BY_ZERO,

    /* Bitfield errors */
    INVALID_BITFIELD_SIZE,
    INVALID_BIT_RANGE,

    /* CHECKLOCKTIMEVERIFY and CHECKSEQUENCEVERIFY */
    NEGATIVE_LOCKTIME,
    UNSATISFIED_LOCKTIME,

    /* Malleability */
    SIG_HASHTYPE,
    SIG_DER,
    MINIMALDATA,
    SIG_PUSHONLY,
    SIG_HIGH_S,
    PUBKEYTYPE,
    CLEANSTACK,
    MINIMALIF,
    SIG_NULLFAIL,

    /* Schnorr */
    SIG_BADLENGTH,
    SIG_NONSCHNORR,

    /* softfork safeness */
    DISCOURAGE_UPGRADABLE_NOPS,

    /* anti replay */
    ILLEGAL_FORKID,
    MUST_USE_FORKID,

    /* Auxiliary errors (unused by interpreter) */
    SIGCHECKS_LIMIT_EXCEEDED,

    /* Operands checks Bigger Integers (64-bit) */
    INVALID_NUMBER_RANGE_64_BIT,

    /* Native Introspection */
    CONTEXT_NOT_PRESENT,
    LIMITED_CONTEXT_NO_SIBLING_INFO,
    INVALID_TX_INPUT_INDEX,
    INVALID_TX_OUTPUT_INDEX,

    /* NOP */
    INVALID_NOP1,
    INVALID_NOP2,
    INVALID_NOP3,
    INVALID_NOP4,
    INVALID_NOP5,
    INVALID_NOP6,

    // General 
    ERROR_COUNT,

    // Atomicals Virtual Machine Errors
    INVALID_ATOMICAL_REF_SIZE,                      // Used
    INVALID_AVM_STATE_KEY_NOT_FOUND,                // Used
    INVALID_AVM_WITHDRAW_FT_AMOUNT,                 // Used
    INVALID_AVM_WITHDRAW_FT,                        // Used
    INVALID_AVM_WITHDRAW_FT_OUTPUT_INDEX,           // Used
    INVALID_AVM_WITHDRAW_NFT,                       // Used
    INVALID_AVM_WITHDRAW_NFT_OUTPUT_INDEX,          // Used
    INVALID_AVM_INVALID_FT_ITEM_INDEX,              // Used
    INVALID_AVM_INVALID_NFT_ITEM_INDEX,             // Used
    INVALID_AVM_STATE_KEY_SIZE,                     // Used
    INVALID_AVM_FT_BALANCE_TYPE,                    // Used
    INVALID_AVM_NFT_EXISTS_TYPE,                    // Used
    INVALID_AVM_NFT_ITEM_TYPE,                      // Used
    INVALID_AVM_FT_ITEM_TYPE,                       // Used
    INVALID_AVM_FT_COUNT_TYPE,                      // Used
    INVALID_AVM_NFT_COUNT_TYPE,                     // Used
    INVALID_AVM_INVALID_BLOCKINFO_ITEM,             // Used
    INVALID_AVM_BLOCK_HEADER_SIZE,                  // Used
    INVALID_AVM_CHECKTXINBLOCK_ERROR,               // Used
    INVALID_AVM_TXID_SIZE,                          // Used
    INVALID_AVM_HASH_FUNC,                          // Used
    INVALID_AVM_FT_BALANCE_ADD_INVALID,             // Used
    INVALID_AVM_NFT_PUT_INVALID,                    // Used
    INVALID_AVM_AUTH_INVALID_INDEX,                 // Used
    INVALID_AVM_AUTH_INVALID_NAMESPACE,             // Used
    INVALID_AVM_CHECKAUTHSIG,                       // Used
    INVALID_AVM_CHECKAUTHSIGVERIFY,                 // Used
    INVALID_AVM_CHECKAUTHSIGNULL,                   // Used      
    // Script enhancements
    SCRIPT_ERR_BIG_INT
};

#define SCRIPT_ERR_LAST ScriptError::ERROR_COUNT

const char *ScriptErrorString(const ScriptError error);

namespace {

inline bool set_success(ScriptError *ret) {
    if (ret) {
        *ret = ScriptError::OK;
    }
    return true;
}

inline bool set_error(ScriptError *ret, const ScriptError serror) {
    if (ret) {
        *ret = serror;
    }
    return false;
}

inline bool set_error_op_num(unsigned int *ret, const unsigned int num) {
    if (ret) {
        *ret = num;
    }
    return false;
}

constexpr auto bitsPerByte{8};

} // namespace
