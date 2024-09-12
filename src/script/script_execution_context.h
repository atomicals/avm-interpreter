// Copyright (c) 2021 The Bitcoin developers
// Copyright (c) 2024 The Atomicals Developers and Supporters
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <coins.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <streams.h>
#include "json.hpp"
#include <boost/algorithm/hex.hpp>
#include <iostream>
#include <memory>
#include <optional>
#include <util/strencodings.h>
#include <utility>
#include <vector>
using namespace boost::algorithm;
using json = nlohmann::json;

/// An execution context for evaluating a script input. Note that this object contains some shared
/// data that is shared for all inputs to a tx. This object is given to CScriptCheck as well
/// as passed down to VerifyScriptAvm() and friends (for native introspection).
///
/// NOTE: In all cases below, the referenced transaction, `tx`, must remain valid throughout this
/// object's lifetime!
#if defined(__GNUG__) && !defined(__clang__)
// silence this warning for g++ only - known compiler bug, see https://gcc.gnu.org/bugzilla/show_bug.cgi?id=102801 and
// https://gcc.gnu.org/bugzilla/show_bug.cgi?id=80635
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
#endif // defined(__GNUG__) && !defined(__clang__)

enum GetAuthInfoResult {
    OK = 1,
    ERR_NAMESPACE = 2,
    ERR_SIGHASH = 3, 
    ERR_INVALID = 4
};
 
// External blockchain state input internal struct representation
struct ExternalBlockInfoStruct {
public:
    CBlockHeader header;
    uint32_t height;
    std::vector<uint8_t> headerHex;
};

typedef std::map<uint32_t, ExternalBlockInfoStruct> HeightToBlockInfoStruct;

// External blockchain state input internal struct representation
struct ContractStateExternalStruct {
public:
    HeightToBlockInfoStruct headers;
    uint32_t currentHeight;
};

class HeaderKeyNotFoundError : public std::exception {};

class HeightKeyNotFoundError : public std::exception {};

class CurrentHeaderKeyNotFoundError : public std::exception {};

class CurrentHeightKeyNotFoundError : public std::exception {};

class HeaderInvalidError : public std::exception {};

class HeaderDecodeError : public std::exception {};

class CurrentHeaderDecodeError : public std::exception {};

class HeightInvalidError : public std::exception {};

class InvalidBlockInfoHeight : public std::exception {};

class CriticalUnexpectedError : public std::exception {};

// Decode hex string to a block header. Returns true on success or false on any error
static bool DecodeHexBlockHeaderDup(const std::string &hex_header, CBlockHeader &header) {
    if (!IsHex(hex_header)) {
        return false;
    }
    const std::vector<uint8_t> header_data{ParseHex(hex_header)};
    CDataStream ser_header(header_data, SER_NETWORK, PROTOCOL_VERSION);
    try {
        ser_header >> header;
    } catch (const std::exception &) {
        return false;
    }
    return true;
}

static std::vector<uint8_t> writeUint64(uint64_t x) {
    std::vector<uint8_t> v;
    v.assign( reinterpret_cast<uint8_t *>( &x ), reinterpret_cast<uint8_t *>( &x ) + sizeof( x ) );
    return v;
}

static std::vector<uint8_t> writeUint32(uint32_t x) {
    std::vector<uint8_t> v;
    v.assign( reinterpret_cast<uint8_t *>( &x ), reinterpret_cast<uint8_t *>( &x ) + sizeof( x ) );
    return v;
}
 
class ScriptExecutionContext {
    /// All the inputs in a tx share this object
    struct Shared {
        /// The transaction being evaluated.
        CTransactionView tx;
        // For std::make_shared to work correctly.
        Shared(CTransactionView tx_) : tx(tx_) {}
    };

    using SharedPtr = std::shared_ptr<const Shared>;

    SharedPtr shared;
    std::vector<uint8_t> _fullScript;   // the full unlock+lock script to execute
    std::vector<uint8_t> _pubKey;       // Auth pubKey if provided

    /// Construct a specific context for this input, given a tx.
    /// Use this constructor for the first input in a tx.
    /// All of the coins for the tx will get pre-cached and a new internal Shared object will be constructed.
    ScriptExecutionContext(const CCoinsViewCache &coinsCache, CTransactionView tx, const std::vector<uint8_t>& fullScript, const std::vector<uint8_t>& pubKey);

public:
    /// Construct a specific context for this input, given another context.
    /// The two contexts will share the same Shared data.
    /// Use this constructor for all subsequent inputs to a tx (so that they may all share the same context)
    ScriptExecutionContext(const ScriptExecutionContext &sharedContext);

    /// Factory method to create a context for all inputs in a tx.
    static ScriptExecutionContext createForTx(CTransactionView tx, const CCoinsViewCache &coinsCache, const std::vector<uint8_t>& fullScript, const std::vector<uint8_t>& pubKey);

    /// The transaction associated with this script evaluation context.
    const CTransactionView &tx() const { return shared->tx; }

    /// Get the scriptSig (unlock script) for the input index
    const CScript & scriptSig(unsigned inputIdx) const {
         return tx().vin().at(inputIdx).scriptSig;
    }
 
    bool getAuthPubKey(std::vector<uint8_t>& pubKey) const {
        if (_pubKey.size()) {
            pubKey = _pubKey;
            return true;
        }
        return false;
    }

    bool getAuthSig(std::vector<uint8_t>& sig) const {
        for (unsigned int index = 0; index < tx().vout().size(); index++) {
            auto const &output = tx().vout()[index];
            auto const &outputScript = tx().vout()[index].scriptPubKey;
            std::vector<uint8_t> outputScriptVec(outputScript.begin(), outputScript.end());
            if (outputScript.IsSigOpReturn(sig)) {
               return true;
            }
        }
        return false;
    }

    // Produces the authorization vector to be signed to authorize the avm call
    std::vector<uint8_t> getAuthMessage() const {
        // Format:
        // prevTx + prevIndex + unlockscript + lockscript + Array(outputValue+outputScript) 
        // Note: The OP_RETURN for the "sig" signature is not included in the outputValue+OutputScript array, it is skipped... 
        // ... just includes all other outputs.
        // 
        //
        std::vector<uint8_t> authMessage;
        auto const &input = tx().vin()[0];
        auto const &txid = input.prevout.GetTxId();
        // prevTx
        authMessage.insert(authMessage.end(), txid.begin(), txid.end());
        // prevIndex
        std::vector<uint8_t> prevoutN = writeUint32(input.prevout.GetN());
        authMessage.insert(authMessage.end(), prevoutN.begin(), prevoutN.end());
        // unlockscript+lockscript
        authMessage.insert(authMessage.end(), _fullScript.begin(), _fullScript.end());
        // For each output, serialize but skip the op_return which contains the signature
        for (unsigned int index = 0; index < tx().vout().size(); index++) {
            auto const &output = tx().vout()[index];
            CScriptNum const bn(output.nValue / SATOSHI);
            std::vector<uint8_t> outputValVec = writeUint64(bn.getint());
            auto const &outputScript = tx().vout()[index].scriptPubKey;
            std::vector<uint8_t> outputScriptVec(outputScript.begin(), outputScript.end());
            std::vector<uint8_t> sig;
            if (!outputScript.IsSigOpReturn(sig)) {
                authMessage.insert(authMessage.end(), outputValVec.begin(), outputValVec.end());
                authMessage.insert(authMessage.end(), outputScriptVec.begin(), outputScriptVec.end());
            }
        }
        // std::cerr << "getAuthMessage: " << HexStr(authMessage) << std::endl;
        return authMessage;
    }
};

class ScriptStateContext {
    json _contractStateExternal;
    json _ftState;
    json _ftStateIncoming;
    json _nftState;
    json _nftStateIncoming;
    json _contractState;
    json _contractStateUpdates;
    json _contractStateDeletes;
    json _ftBalancesUpdates;
    json _nftBalancesUpdates;

    std::set<uint288> _ftAddsSet;
    std::set<uint288> _nftPutsSet;

    std::map<uint288, std::map<uint32_t, uint64_t>> _ftWithdrawMap;
    std::map<uint288, uint32_t> _nftWithdrawMap;
    ContractStateExternalStruct _externalStateStruct;

public:
    ScriptStateContext(json &ftState, json &ftStateIncoming, json &nftState, json &nftStateIncoming, json &contractState, json &contractStateExternal);
    ScriptStateContext() {}

    void cleanupStateAndBalances();
    void validateFinalStateRestrictions() const;
    bool isAllowedBlockInfoHeight(uint32_t height) const;
    static CBlockHeader decodeHeader(const std::vector<uint8_t> &header);
    static ContractStateExternalStruct validateContractStateExternal(const json &contractStateExternal);
    static json::const_iterator getKeyspaceNode(const json &entity, const std::string &keySpace);
    static json &ensureKeyspaceExists(json &entity, const std::string &keySpace);
    static void cleanupKeyspaces(json &entity);
    static void cleanupEmptyKeyspace(json &entity, const std::string &keySpace);
    static void cleanupEmptyFtTokenBalance(json &entity);
    static void cleanupEmptyNftTokenBalance(json &entity);

    // Contract state manipulation
    bool contractStateGet(const std::vector<uint8_t> &keySpace, const std::vector<uint8_t> &keyName,
                          std::vector<uint8_t> &value) const;
    void contractStatePut(const std::vector<uint8_t> &keySpace, const std::vector<uint8_t> &keyName,
                          const std::vector<uint8_t> &value);
    void contractStateDelete(const std::vector<uint8_t> &keySpace, const std::vector<uint8_t> &keyName);
    bool contractStateExists(const std::vector<uint8_t> &keySpace, const std::vector<uint8_t> &keyName) const;

    // Public methods to retrieve the resulting states, balances and withdraws
    json const &getContractStateFinal() const { return _contractState; }
    json const &getContractStateUpdates() const { return _contractStateUpdates; }
    json const &getContractStateDeletes() const { return _contractStateDeletes; }
    json const &getFtBalancesResult() const { return _ftState; }
    json const &getFtBalancesUpdatesResult() const { return _ftBalancesUpdates; }
    json const &getNftBalancesResult() const { return _nftState; }
    json const &getNftBalancesUpdatesResult() const { return _nftBalancesUpdates; }
    json getFtWithdrawsResult() const;
    json getNftWithdrawsResult() const;
    json getFtIncomingBalancesAddedResult() const;
    json getNftIncomingPutsResult() const;
 
    GetAuthInfoResult getAuthInfo(const std::vector<uint8_t> &keySpace, uint32_t idx, std::vector<uint8_t> &resultPubKey) const;

    // contract token enumeration and balances
    uint64_t contractFtBalance(const uint288 &ftId);
    bool contractFtBalanceAdd(const uint288& ftId);
    bool allowedFtBalanceAdd(const uint288& ftId);
    bool performFtBalanceAdd(const uint288& ftId, uint64_t amount);
    uint64_t contractFtBalanceIncoming(const uint288 &ftId);

    bool contractNftExists(const uint288 &nftId);
    bool contractNftExistsIncoming(const uint288 &nftId);
    bool contractNftPut(const uint288& nftId);
    bool allowedNftPut(const uint288& nftId);
    bool performNftPut(const uint288& nftId);

    uint32_t getFtCount() const;
    uint32_t getFtCountIncoming() const;
    uint32_t getNftCount() const;
    uint32_t getNftCountIncoming() const;
    bool getFtItem(uint32_t index, uint288 &tokenId) const;
    bool getFtItemIncoming(uint32_t index, uint288 &tokenId) const;
    bool getNftItem(uint32_t index, uint288 &tokenId) const;
    bool getNftItemIncoming(uint32_t index, uint288 &tokenId) const;

    // contract token withdrawl functions
    bool contractWithdrawFt(const uint288 &ftId, uint32_t index, uint64_t withdrawAmount);
    bool contractWithdrawNft(const uint288 &nftId, uint32_t index);
    bool encodeFtWithdrawMap(json &withdrawFt) const;
    bool encodeNftWithdrawMap(json &withdrawNft) const;
    bool encodeFtIncomingBalancesAddedMap(json &ftBalancesAdded) const; 
    bool encodeNftIncomingPutsMap(json &nftPuts) const;

    // Additional methods
    CBlockHeader getBlockInfoByHeight(uint32_t height) const;
    void getCurrentBlockInfoHeader(uint32_t height, std::vector<uint8_t> &value) const;
    uint64_t getCurrentBlockInfoHeight(uint32_t height) const;
    uint32_t getCurrentBlockInfoVersion(uint32_t height) const;
    void getCurrentBlockInfoPrevHash(uint32_t height, std::vector<uint8_t> &value) const;
    void getCurrentBlockInfoMerkleRoot(uint32_t height, std::vector<uint8_t> &value) const;
    uint32_t getCurrentBlockInfoTime(uint32_t height) const;
    uint32_t getCurrentBlockInfoBits(uint32_t height) const;
    uint32_t getCurrentBlockInfoNonce(uint32_t height) const;
    uint64_t getCurrentBlockInfoDifficulty(uint32_t height) const;

    // Decode block header
    uint32_t getBlockInfoVersion(const std::vector<uint8_t> &header) const;
    void getBlockInfoPrevHash(const std::vector<uint8_t> &header, std::vector<uint8_t> &value) const;
    void getBlockInfoMerkleRoot(const std::vector<uint8_t> &header, std::vector<uint8_t> &value) const;
    uint32_t getBlockInfoTime(const std::vector<uint8_t> &header) const;
    uint32_t getBlockInfoBits(const std::vector<uint8_t> &header) const;
    uint32_t getBlockInfoNonce(const std::vector<uint8_t> &header) const;
    uint64_t getBlockInfoDifficulty(const std::vector<uint8_t> &header) const;

    // checkTxInBlock
    bool checkTxInBlock(const std::vector<uint8_t> &header, const std::vector<uint8_t> &proof,
                        const uint256 &txid) const;
};
#if defined(__GNUG__) && !defined(__clang__)
#pragma GCC diagnostic pop
#endif // defined(__GNUG__) && !defined(__clang__)

using ScriptExecutionContextOpt = std::optional<ScriptExecutionContext>;
