// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2024 The Atomicals Developers and Supporters
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstdint>
#include "constants.h"

#if defined(BUILD_AVM_INTERNAL) && defined(HAVE_CONFIG_H)
#include <config/bitcoin-config.h>
#if defined(_WIN32)
#if defined(DLL_EXPORT)
#if defined(HAVE_FUNC_ATTRIBUTE_DLLEXPORT)
#define EXPORT_SYMBOL __declspec(dllexport)
#else
#define EXPORT_SYMBOL
#endif
#endif
#elif defined(HAVE_FUNC_ATTRIBUTE_VISIBILITY)
#define EXPORT_SYMBOL __attribute__((visibility("default")))
#endif
#elif defined(MSC_VER) && !defined(STATIC_LIBATOMICALSCONSENSUS)
#define EXPORT_SYMBOL __declspec(dllimport)
#endif

#ifndef EXPORT_SYMBOL
#define EXPORT_SYMBOL
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define ATOMICALSCONSENSUS_API_VER 1
 
typedef enum atomicalsconsensus_error_t {
    atomicalsconsensus_ERR_OK = 0,
    atomicalsconsensus_ERR_TX_INDEX,                                // Used
    atomicalsconsensus_ERR_TX_SIZE_MISMATCH,                        // Used
    atomicalsconsensus_ERR_INVALID_FLAGS,                           // Used
    atomicalsconsensus_ERR_INVALID_FT_WITHDRAW,                     // Used 
    atomicalsconsensus_ERR_INVALID_NFT_WITHDRAW,                    // Used
    atomicalsconsensus_ERR_STATE_SIZE_ERROR,                        // Used
    atomicalsconsensus_ERR_STATE_UPDATES_SIZE_ERROR,                //  
    atomicalsconsensus_ERR_STATE_DELETES_SIZE_ERROR,                //  
    atomicalsconsensus_ERR_STATE_FT_BALANCES_SIZE_ERROR,            //  
    atomicalsconsensus_ERR_STATE_FT_BALANCES_UPDATES_SIZE_ERROR,    //  
    atomicalsconsensus_ERR_STATE_NFT_BALANCES_SIZE_ERROR,           //  
    atomicalsconsensus_ERR_STATE_NFT_BALANCES_UPDATES_SIZE_ERROR,   //   
} atomicalsconsensus_error;
 
 /** Script verification flags */
enum {
    atomicalsconsensus_SCRIPT_FLAGS_VERIFY_NONE = 0,
    // No flags for now, but could be in the future
    atomicalsconsensus_SCRIPT_FLAGS_VERIFY_ALL =atomicalsconsensus_SCRIPT_FLAGS_VERIFY_NONE
};

EXPORT_SYMBOL int atomicalsconsensus_verify_script_avm(
    const uint8_t *lockScript, unsigned int lockScriptLen,
    const uint8_t *unlockScript, unsigned int unlockScriptLen, 
    const uint8_t *txTo, unsigned int txToLen, 
    const uint8_t *authPubKey, unsigned int authPubKeyLen, 
    const uint8_t *ftStateCbor, unsigned int ftStateCborLen, 
    const uint8_t *ftStateIncomingCbor, unsigned int ftStateIncomingCborLen, 
    const uint8_t *nftStateCbor, unsigned int nftStateCborLen, 
    const uint8_t *nftStateIncomingCbor, unsigned int nftStateCborIncomingLen, 
    const uint8_t *contractExternalStateCbor, unsigned int contractStateExternalCborLen, 
    const uint8_t *contractStateCbor, unsigned int contractStateCborLen, 
    const uint8_t *prevStateHash, 
    atomicalsconsensus_error *err, 
    unsigned int *script_error,
    unsigned int *script_error_op_num,
    uint8_t *stateHash,
    uint8_t *stateFinal,
    unsigned int *stateFinalLen,
    uint8_t *stateUpdates,
    unsigned int *stateUpdatesLen,
    uint8_t *stateDeletes,
    unsigned int *stateDeletesLen,
    uint8_t *ftBalancesResult,
    unsigned int *ftBalancesResultLen,
    uint8_t *ftBalancesUpdatesResult,
    unsigned int *ftBalancesUpdatesResultLen,
    uint8_t *nftBalancesResult,
    unsigned int *nftBalancesResultLen,
    uint8_t *nftBalancesUpdatesResult,
    unsigned int *nftBalancesUpdatesResultLen,
    uint8_t *ftWithdraws,
    unsigned int *ftWithdrawsLen,
    uint8_t *nftWithdraws,
    unsigned int *nftWithdrawsLen,
    uint8_t *ftBalancesAdded, unsigned int *ftBalancesAddedLen,
    uint8_t *nftPuts, unsigned int *nftPutsLen);
 

EXPORT_SYMBOL unsigned int atomicalsconsensus_version();

#ifdef __cplusplus
} // extern "C"
#endif

#undef EXPORT_SYMBOL
