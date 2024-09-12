// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2024 The Atomicals Developers and Supporters
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <script/atomicalsconsensus.h>

#include "json.hpp"
#include <iostream>
#include <primitives/transaction.h>
#include <pubkey.h>
#include <script/interpreter.h>
#include <script/script_utils.h>
#include <version.h>
using json = nlohmann::json;
namespace {

/** A class that deserializes a single CTransaction one time. */
class TxInputStream {
public:
    TxInputStream(int nTypeIn, int nVersionIn, const uint8_t *txTo, size_t txToLen)
        : m_type(nTypeIn), m_version(nVersionIn), m_data(txTo), m_remaining(txToLen) {}

    void read(char *pch, size_t nSize) {
        if (nSize > m_remaining) {
            throw std::ios_base::failure(std::string(__func__) + ": end of data");
        }

        if (pch == nullptr) {
            throw std::ios_base::failure(std::string(__func__) + ": bad destination buffer");
        }

        if (m_data == nullptr) {
            throw std::ios_base::failure(std::string(__func__) + ": bad source buffer");
        }

        memcpy(pch, m_data, nSize);
        m_remaining -= nSize;
        m_data += nSize;
    }

    template <typename T>
    TxInputStream &operator>>(T &&obj) {
        ::Unserialize(*this, obj);
        return *this;
    }

    int GetVersion() const { return m_version; }
    int GetType() const { return m_type; }

private:
    const int m_type;
    const int m_version;
    const uint8_t *m_data;
    size_t m_remaining;
};

inline int set_error(atomicalsconsensus_error *ret, atomicalsconsensus_error serror) {
    if (ret) {
        *ret = serror;
    }

    return 0;
}

struct ECCryptoClosure {
    ECCVerifyHandle handle;
};

ECCryptoClosure instance_of_eccryptoclosure;
} // namespace

/** Check that all specified flags are part of the libconsensus interface. */
static bool verify_flags(unsigned int flags) {
    return (flags & ~(atomicalsconsensus_SCRIPT_FLAGS_VERIFY_ALL)) == 0;
}

static int verify_script_avm(const uint8_t *lockScript, // The locking script established in the protocol code
                             unsigned int lockScriptLen,
                             const uint8_t *unlockScript, // Unlocking script to satisfy the locking script
                             unsigned int unlockScriptLen, 
                             const json &ftState, // Snapshot of FT token state         
                             const json &ftStateIncoming, // Incoming FT tokens for the current transaction
                             const json &nftState, // Snapshot of the NFT token state
                             const json &nftStateIncoming, // Incoming NFT tokens for the current transaction
                             const json &contractState, // Snapshot of the contract state data
                             const json &contractExternalState, // External state such as blockchain info for the current transaction
                             const uint8_t *txTo,   // Transaction being executed
                             unsigned int txToLen, 
                             const uint8_t *authPubKey, // Auth pub key if provided
                             unsigned int authPubKeyLen, 
                             unsigned int flags, // Script flags for enabling features in future
                             atomicalsconsensus_error *err, // Base error
                             unsigned int *script_err, // Script execution error
                             unsigned int *script_err_op_num, // Specific op index that threw the error
                             ScriptStateContext *stateContext // Context of the execution 
                             ) {
    if (!verify_flags(flags)) {
        return atomicalsconsensus_ERR_INVALID_FLAGS;
    }
    TxInputStream stream(SER_NETWORK, PROTOCOL_VERSION, txTo, txToLen);
    CTransaction tx(deserialize, stream);
    /*  
    //
    // TODO: Figure out why the transaction does not serialize correctly
    //  following code is what does not work for correct deserialization. The input witness is truncated for some reason...
    //  if (GetSerializeSize(tx) != txToLen) {
    //      return set_error(err, atomicalsconsensus_ERR_TX_SIZE_MISMATCH);
    // }
    CTransactionView txView(tx);
    /*
    if (GetSerializeSize(tx, PROTOCOL_VERSION) != txToLen) {
        std::cout << "serailzied size: " << GetSerializeSize(tx, PROTOCOL_VERSION) << std::endl;
        std::cout << "txToLen: " << txToLen << std::endl;
        return set_error(err, atomicalsconsensus_ERR_TX_SIZE_MISMATCH);
    }
    //
    */
    // Regardless of the verification result, the tx did not error.
    set_error(err, atomicalsconsensus_ERR_OK);
    CScript const spk(lockScript, lockScript + lockScriptLen);
    CScript const unlockSig(unlockScript, unlockScript + unlockScriptLen);

    PrecomputedTransactionData txdata(tx);
    json copiedState(contractState.begin(), contractState.end());

    CCoinsView coinsDummy;
    CCoinsViewCache coinsCache(&coinsDummy);

    std::vector<uint8_t> fullScriptVec(unlockScript, unlockScript + unlockScriptLen);
    std::vector<uint8_t> lockingScriptVec(lockScript, lockScript + lockScriptLen);
    fullScriptVec.insert( fullScriptVec.end(), lockingScriptVec.begin(), lockingScriptVec.end() );
    std::vector<uint8_t> authPubKeyVec(authPubKey, authPubKey + authPubKeyLen);

    ScriptExecutionContext createdContext = ScriptExecutionContext::createForTx(tx, coinsCache, fullScriptVec, authPubKeyVec);
    ScriptExecutionContext const context = createdContext;

    json ftStateCopy(ftState.begin(), ftState.end());
    json ftStateIncomingCopy(ftStateIncoming.begin(), ftStateIncoming.end());
    json nftStateCopy(nftState.begin(), nftState.end());
    json nftStateIncomingCopy(nftStateIncoming.begin(), nftStateIncoming.end());
    json contractStateCopy(contractState.begin(), contractState.end());
    json contractExternalStateCopy(contractExternalState.begin(), contractExternalState.end());

    std::cout << "ftStateCopy" << ftStateCopy << std::endl;
    std::cout << "ftStateIncomingCopy" << ftStateIncomingCopy << std::endl;
    std::cout << "nftStateCopy" << nftStateCopy << std::endl;
    std::cout << "nftStateIncomingCopy" << nftStateIncomingCopy << std::endl;
    std::cout << "contractStateCopy" << contractStateCopy << std::endl;
    std::cout << "contractExternalStateCopy" << contractExternalStateCopy << std::endl;

    ScriptStateContext state(ftStateCopy, ftStateIncomingCopy, nftStateCopy, nftStateIncomingCopy, contractStateCopy,
                             contractExternalStateCopy);

    // Default script errors
    ScriptError tempScriptError = ScriptError::OK;
    auto error_code = VerifyScriptAvm(unlockSig, // Use the provided unlocking script sig because we are in AVM context
                                      spk, TransactionSignatureChecker(&tx, 0, Amount::zero(), txdata), context, state,
                                      &tempScriptError, script_err_op_num);
    json ftBalancesResult = state.getFtBalancesResult();
    json nftBalancesResult = state.getNftBalancesResult();
    *stateContext = state;
    *script_err = (int)tempScriptError;
    std::cout << "script_error_code: " << (int)(*script_err) << std::endl;
    std::cout << "script_err_op_num: " << (int)(*script_err_op_num) << std::endl;
    return error_code;
}

int atomicalsconsensus_verify_script_avm(
    const uint8_t *lockScript, unsigned int lockScriptLen, const uint8_t *unlockScript, unsigned int unlockScriptLen,
    const uint8_t *txTo, unsigned int txToLen, const uint8_t *authPubKey, unsigned int authPubKeyLen, 
    const uint8_t *ftStateCbor, unsigned int ftStateCborLen,
    const uint8_t *ftStateIncomingCbor, unsigned int ftStateIncomingCborLen, const uint8_t *nftStateCbor,
    unsigned int nftStateCborLen, const uint8_t *nftStateIncomingCbor, unsigned int nftStateIncomingCborLen,
    const uint8_t *contractExternalStateCbor, unsigned int contractExternalStateCborLen,
    const uint8_t *contractStateCbor, unsigned int contractStateCborLen, const uint8_t *prevStateHash,
    atomicalsconsensus_error *err, unsigned int *script_err, unsigned int *script_err_op_num, uint8_t *stateHash,
    uint8_t *stateFinal, unsigned int *stateFinalLen, uint8_t *stateUpdates,
    unsigned int *stateUpdatesLen, uint8_t *stateDeletes,
    unsigned int *stateDeletesLen, uint8_t *ftBalancesResult,
    unsigned int *ftBalancesResultLen, uint8_t *ftBalancesUpdatesResult,
    unsigned int *ftBalancesUpdatesResultLen, uint8_t *nftBalancesResult,
    unsigned int *nftBalancesResultLen, uint8_t *nftBalancesUpdatesResult,
    unsigned int *nftBalancesUpdatesResultLen, uint8_t *ftWithdraws,
    unsigned int *ftWithdrawsLen, uint8_t *nftWithdraws,
    unsigned int *nftWithdrawsLen,
    uint8_t *ftBalancesAdded, unsigned int *ftBalancesAddedLen,
    uint8_t *nftPuts, unsigned int *nftPutsLen
    ) {

    // Regardless of the verification result, the tx did not error.
    set_error(err, atomicalsconsensus_ERR_OK);

    // Copy all of the states
    std::vector<std::uint8_t> prevStateHashBytes(prevStateHash, prevStateHash + 32);
    std::vector<std::uint8_t> ftStateBytes(ftStateCbor, ftStateCbor + ftStateCborLen);
    std::vector<std::uint8_t> ftStateIncomingBytes(ftStateIncomingCbor, ftStateIncomingCbor + ftStateIncomingCborLen);
    std::vector<std::uint8_t> nftStateBytes(nftStateCbor, nftStateCbor + nftStateCborLen);
    std::vector<std::uint8_t> nftStateIncomingBytes(nftStateIncomingCbor,
                                                    nftStateIncomingCbor + nftStateIncomingCborLen);
    std::vector<std::uint8_t> contractExternalStateBytes(contractExternalStateCbor,
                                                         contractExternalStateCbor + contractExternalStateCborLen);
    std::vector<std::uint8_t> contractStateBytes(contractStateCbor, contractStateCbor + contractStateCborLen);

    auto ftState = json::from_cbor(ftStateBytes, true, true, json::cbor_tag_handler_t::error);
    auto ftStateIncoming = json::from_cbor(ftStateIncomingBytes, true, true, json::cbor_tag_handler_t::error);
    auto nftState = json::from_cbor(nftStateBytes, true, true, json::cbor_tag_handler_t::error);
    auto nftStateIncoming = json::from_cbor(nftStateIncomingBytes, true, true, json::cbor_tag_handler_t::error);
    auto contractExternalState =
        json::from_cbor(contractExternalStateBytes, true, true, json::cbor_tag_handler_t::error);
    auto contractState = json::from_cbor(contractStateBytes, true, true, json::cbor_tag_handler_t::error);

    uint32_t flags(0);
    ScriptStateContext stateContext;
    int result = ::verify_script_avm(lockScript, lockScriptLen, unlockScript, unlockScriptLen, ftState, ftStateIncoming,
                                     nftState, nftStateIncoming, contractState, contractExternalState,
                                     txTo, txToLen,authPubKey, authPubKeyLen, flags, err, script_err, script_err_op_num, &stateContext);
    if (result != 1) {
        return result;
    }

    // Remove empty keyspaces
    // After various deletes there could be empty keyspaces, ensure they are removed prior to returning
    stateContext.cleanupStateAndBalances();
    // Throws state format error, which should return a runtime error and force the program to crash since it should
    // never happen Also can throw state size limit error which should be caught and translated into a comprehensible
    // error
    try {
        stateContext.validateFinalStateRestrictions();
    } catch (StateValidationStateSizeLimitError &ex) {
        return set_error(err, atomicalsconsensus_ERR_STATE_SIZE_ERROR);
    } catch (StateValidationStateUpdateSizeLimitError &ex) {
        return set_error(err, atomicalsconsensus_ERR_STATE_UPDATES_SIZE_ERROR);
    } catch (StateValidationStateDeleteSizeLimitError &ex) {
        return set_error(err, atomicalsconsensus_ERR_STATE_DELETES_SIZE_ERROR);
    } catch (StateValidationTokenFtBalanceSizeLimitError &ex) {
        return set_error(err, atomicalsconsensus_ERR_STATE_FT_BALANCES_SIZE_ERROR);
    } catch (StateValidationTokenFtBalanceUpdateSizeLimitError &ex) {
        return set_error(err, atomicalsconsensus_ERR_STATE_FT_BALANCES_UPDATES_SIZE_ERROR);
    } catch (StateValidationTokenNftBalanceSizeLimitError &ex) {
        return set_error(err, atomicalsconsensus_ERR_STATE_NFT_BALANCES_SIZE_ERROR);
    } catch (StateValidationTokenNftBalanceUpdateSizeLimitError &ex) {
        return set_error(err, atomicalsconsensus_ERR_STATE_NFT_BALANCES_UPDATES_SIZE_ERROR);
    }

    // Copy the Final contract state
    //
    json stateFinalJson = stateContext.getContractStateFinal();
    CopyBytes(json::to_cbor(stateFinalJson), stateFinal, stateFinalLen);
    //
    // Copy the Updated State data
    //
    json stateUpdatesJson = stateContext.getContractStateUpdates();
    CopyBytes(json::to_cbor(stateUpdatesJson), stateUpdates, stateUpdatesLen);
    //
    // Copy the Deleted State data
    //
    json stateDeletesJson = stateContext.getContractStateDeletes();
    CopyBytes(json::to_cbor(stateDeletesJson), stateDeletes, stateDeletesLen);
    //
    // Copy the FT balances result
    //
    json ftBalancesJson = stateContext.getFtBalancesResult();
    CopyBytes(json::to_cbor(ftBalancesJson), ftBalancesResult, ftBalancesResultLen);
    //
    // Copy the FT balances updates result
    //
    json ftBalancesUpdatesJson = stateContext.getFtBalancesUpdatesResult();
    CopyBytes(json::to_cbor(ftBalancesUpdatesJson), ftBalancesUpdatesResult, ftBalancesUpdatesResultLen);
    //
    // Copy the NFT balances result
    //
    json nftBalancesJson = stateContext.getNftBalancesResult();
    CopyBytes(json::to_cbor(nftBalancesJson), nftBalancesResult, nftBalancesResultLen);
    //
    // Copy the NFT balances updates result
    //
    json nftBalancesUpdatesJson = stateContext.getNftBalancesUpdatesResult();
    CopyBytes(json::to_cbor(nftBalancesUpdatesJson), nftBalancesUpdatesResult, nftBalancesUpdatesResultLen);
    //
    // Copy FT withdraws
    //
    json ftWithdrawsJson = stateContext.getFtWithdrawsResult();
    CopyBytes(json::to_cbor(ftWithdrawsJson), ftWithdraws, ftWithdrawsLen);
    //
    // Copy NFT withdraws
    //
    json nftWithdrawsJson = stateContext.getNftWithdrawsResult();
    CopyBytes(json::to_cbor(nftWithdrawsJson), nftWithdraws, nftWithdrawsLen);

    //
    // Copy the FTs that were taken from incoming and added to balance
    //
    json ftIncomingBalancesAddedJson = stateContext.getFtIncomingBalancesAddedResult();
    CopyBytes(json::to_cbor(ftIncomingBalancesAddedJson), ftBalancesAdded, ftBalancesAddedLen);
    //
    // Copy NFTs that were taken from incoming and put to balance
    //
    json nftIncomingPutsJson = stateContext.getNftIncomingPutsResult();
    CopyBytes(json::to_cbor(nftIncomingPutsJson), nftPuts, nftPutsLen);

    // Convert previous state hash into vector
    std::vector<uint8_t> vchprevStateHash(prevStateHash, prevStateHash + 32);
    std::vector<uint8_t> updatedStateHash =
        CalculateStateHash(vchprevStateHash, stateFinalJson, stateUpdatesJson, stateDeletesJson, ftStateIncoming,
                           nftStateIncoming, ftBalancesJson, ftBalancesUpdatesJson, nftBalancesJson,
                           nftBalancesUpdatesJson, ftWithdrawsJson, nftWithdrawsJson);

    CopyBytesNoDestLen(updatedStateHash, stateHash);
    return result;
}

unsigned int atomicalsconsensus_version() {
    // Just use the API version for now
    return ATOMICALSCONSENSUS_API_VER;
}
