// Copyright (c) 2021 The Bitcoin developers
// Copyright (c) 2024 The Atomicals Developers and Supporters
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <script/script_execution_context.h>
#include <script/script_utils.h>

#include <merkleblock.h>

#include <cassert>

#include "json.hpp"

#include <iostream>

using json = nlohmann::json;

ScriptExecutionContext::ScriptExecutionContext(const CCoinsViewCache &coinsCache, CTransactionView tx, const std::vector<uint8_t>& fullScript, const std::vector<uint8_t>& pubKey) {
    shared = std::make_shared<Shared>(tx);
    _fullScript = fullScript;
    _pubKey = pubKey;
}

ScriptExecutionContext::ScriptExecutionContext(const ScriptExecutionContext &sharedContext)
    : shared(sharedContext.shared), _fullScript(sharedContext._fullScript), _pubKey(sharedContext._pubKey) {
    assert(shared);
}
/* static */
ScriptExecutionContext ScriptExecutionContext::createForTx(CTransactionView tx, const CCoinsViewCache &coinsCache, const std::vector<uint8_t>& fullScript, const std::vector<uint8_t>& pubKey) {
    return ScriptExecutionContext(coinsCache, tx, fullScript, pubKey); // private c'tor, must use push_back
}

ScriptStateContext::ScriptStateContext(json &ftState, json &ftStateIncoming, json &nftState, json &nftStateIncoming,
                                       json &contractState, json &contractStateExternal)
    : _contractStateExternal(contractStateExternal), _ftState(ftState), _ftStateIncoming(ftStateIncoming),
      _nftState(nftState), _nftStateIncoming(nftStateIncoming), _contractState(contractState),
      _contractStateUpdates({}), _contractStateDeletes({}), _ftBalancesUpdates({}), _nftBalancesUpdates({}) {
    ContractStateExternalStruct external = ScriptStateContext::validateContractStateExternal(_contractStateExternal);
    _externalStateStruct = external;

    // Validate that all states are in the correct expected form
    // Can throw state format error or state size limit error
    StateValidation::performValidateStateRestrictions(_ftState, _ftBalancesUpdates, _ftStateIncoming, _nftState,
                                                      _nftBalancesUpdates, _nftStateIncoming, _contractState,
                                                      _contractStateUpdates, _contractStateDeletes);
}

void ScriptStateContext::validateFinalStateRestrictions() const {
    StateValidation::performValidateStateRestrictions(_ftState, _ftBalancesUpdates, _ftStateIncoming, _nftState,
                                                      _nftBalancesUpdates, _nftStateIncoming, _contractState,
                                                      _contractStateUpdates, _contractStateDeletes);
}

void ScriptStateContext::cleanupStateAndBalances() {
    ScriptStateContext::cleanupKeyspaces(_contractState);
    ScriptStateContext::cleanupKeyspaces(_contractStateUpdates);
    ScriptStateContext::cleanupKeyspaces(_contractStateDeletes);
    ScriptStateContext::cleanupEmptyFtTokenBalance(_ftState);
    ScriptStateContext::cleanupEmptyNftTokenBalance(_nftState);
}

void ScriptStateContext::contractStatePut(const std::vector<uint8_t> &keySpace, const std::vector<uint8_t> &keyName,
                                          const std::vector<uint8_t> &value) {
    std::string keySpaceStr = HexStrWith00Null(keySpace);
    std::string keyNameStr = HexStrWith00Null(keyName);
    std::string valueStr = HexStrWith00Null(value);
    json &keyspaceNodeState = ScriptStateContext::ensureKeyspaceExists(_contractState, keySpaceStr);
    json &keyspaceNodeUpdates = ScriptStateContext::ensureKeyspaceExists(_contractStateUpdates, keySpaceStr);
    json &keyspaceNodeDeletes = ScriptStateContext::ensureKeyspaceExists(_contractStateDeletes, keySpaceStr);
    keyspaceNodeState[keyNameStr] = valueStr;
    keyspaceNodeUpdates[keyNameStr] = valueStr;
    keyspaceNodeDeletes.erase(keyNameStr);
}

void ScriptStateContext::contractStateDelete(const std::vector<uint8_t> &keySpace,
                                             const std::vector<uint8_t> &keyName) {
    std::cout << "contractStateDelete:start" << std::endl;
    std::string keySpaceStr = HexStrWith00Null(keySpace);
    std::string keyNameStr = HexStrWith00Null(keyName);
    std::cout << "keySpaceStr="  << keySpaceStr << std::endl;
    std::cout << "keyNameStr="  << keyNameStr << std::endl;
    // Ensure the keyspaces exists
    json &keyspaceNodeState = ScriptStateContext::ensureKeyspaceExists(_contractState, keySpaceStr);
    json &keyspaceNodeUpdates = ScriptStateContext::ensureKeyspaceExists(_contractStateUpdates, keySpaceStr);
    json &keyspaceNodeDeletes = ScriptStateContext::ensureKeyspaceExists(_contractStateDeletes, keySpaceStr);
    // Remove it from the main state
    keyspaceNodeState.erase(keyNameStr);
    // Remove it from the updates
    keyspaceNodeUpdates.erase(keyNameStr);
    // Mark it as deleted
    keyspaceNodeDeletes[keyNameStr] = true;
    std::cout << "contractStateDelete:end" << std::endl;
}

json::const_iterator ScriptStateContext::getKeyspaceNode(const json &entity, const std::string &keySpaceStr) {
    return entity.find(keySpaceStr);
}

void ScriptStateContext::cleanupKeyspaces(json &entity) {
    for (auto &[key, value] : entity.items()) {
        // Should never happen
        if (!value.is_object()) {
            throw new StateKeyspaceCleanupError();
        }
         if (value.empty()) {
            entity.erase(key);
        }
    }
}

void ScriptStateContext::cleanupEmptyKeyspace(json &entity, const std::string &keySpaceStr) {
    auto it = entity.find(keySpaceStr);
    if (it != entity.end()) {
        if (it->empty()) {
            entity.erase(keySpaceStr);
        }
    }
}

void ScriptStateContext::cleanupEmptyFtTokenBalance(json &entity) {
    // Todo: determine if iterator returned by items will be invalidated on erase?
    // Todo: protectively use a vector and delete that way
    for (auto &[key, value] : entity.items()) {
        // Cannot use 0 balance in the main table
        std::uint64_t valueInt = value.template get<std::uint64_t>();
        if (valueInt == 0) {
            entity.erase(key);
        }
    }
}

void ScriptStateContext::cleanupEmptyNftTokenBalance(json &entity) {
    // Todo: determine if iterator returned by items will be invalidated on erase?
    // Todo: protectively use a vector and delete that way
    for (auto &[key, value] : entity.items()) {
        // Cannot use False entry in the main table
        bool boolValue = value.template get<bool>();
        if (!boolValue) {
            entity.erase(key);
        }
    }
}

json &ScriptStateContext::ensureKeyspaceExists(json &entity, const std::string &keySpaceStr) {
    auto foundKeyspaceIt = entity.find(keySpaceStr);
    if (foundKeyspaceIt != entity.end()) {
        return entity[keySpaceStr];
    }
    entity[keySpaceStr] = json({});
    return entity[keySpaceStr];
}

bool ScriptStateContext::contractStateGet(const std::vector<uint8_t> &keySpace, const std::vector<uint8_t> &keyName,
                                          std::vector<uint8_t> &value) const {
    json::const_iterator keyspaceNode = ScriptStateContext::getKeyspaceNode(_contractState, HexStr(keySpace));
    if (keyspaceNode == _contractState.end()) {
        return false;
    }
    auto it = keyspaceNode->find(HexStr(keyName));
    if (it != keyspaceNode->end()) {
        std::string keyValue = it->template get<std::string>();
        auto ss = ParseHex(keyValue);
        std::move(ss.begin(), ss.end(), std::back_inserter(value));
        return true;
    }
    return false;
}

bool ScriptStateContext::contractStateExists(const std::vector<uint8_t> &keySpace,
                                             const std::vector<uint8_t> &keyName) const {
    json::const_iterator keyspaceNode = ScriptStateContext::getKeyspaceNode(_contractState, HexStr(keySpace));
    if (keyspaceNode == _contractState.end()) {
        return false;
    }
    if (keyspaceNode->contains(HexStr(keyName))) {
        return true;
    }
    return false;
}

bool ScriptStateContext::contractWithdrawFt(const uint288 &ftId, uint32_t index, uint64_t withdrawAmount) {
    if (withdrawAmount <= 0) {
        return false;
    }
    // Second check if the existing balance is adequate to cover the requested withdraw amount
    std::string ftIdStr = ftId.GetHex();
    if (!_ftState.contains(ftIdStr)) {
        // No balance can be added
        return false;
    }
    auto valtype = _ftState[ftIdStr];
    uint64_t availableBalance = valtype.template get<std::uint64_t>();
    if (withdrawAmount > availableBalance) {
        return false;
    }
    uint64_t updatedBalance = availableBalance - withdrawAmount;
    if (updatedBalance == 0) {
        _ftState.erase(ftIdStr);
    } else {
        _ftState[ftIdStr] = updatedBalance;
    }
    _ftBalancesUpdates[ftIdStr] = updatedBalance;

    // Update the withdraw map
    auto findIt = _ftWithdrawMap.find(ftId);
    if (findIt == _ftWithdrawMap.end()) {
        std::map<uint32_t, uint64_t> mapper;
        _ftWithdrawMap.insert(std::make_pair(ftId, mapper));
    }
    auto it = _ftWithdrawMap.find(ftId);
    it->second.insert(std::make_pair(index, withdrawAmount));
    return true;
}

bool ScriptStateContext::contractWithdrawNft(const uint288 &nftId, uint32_t index) {
    // Second check if the existing balance is adequate to cover the requested withdraw amount
    std::string nftIdStr = nftId.GetHex();
    if (!_nftState.contains(nftIdStr)) {
        // Cannot withdraw because it does not exist
        return false;
    }
    _nftState.erase(nftIdStr);
    _nftBalancesUpdates[nftIdStr] = false;
    _nftWithdrawMap.insert(std::make_pair(nftId, index));
    return true;
}

bool ScriptStateContext::contractNftPut(const uint288 &nftId) {
    if (!_nftStateIncoming.contains(nftId.GetHex())) {
        // No incoming can be added
        return false;
    }
    // Do not allow adding to the same balance more than once
    if (!allowedNftPut(nftId)) {
        return false;
    }
    auto valtype = _nftStateIncoming[nftId.GetHex()];
    auto incomingAllowed = valtype.template get<bool>();
    if (!incomingAllowed) {
        throw new StateValidationTokenNftBalanceFormatError();
    }
    if (!performNftPut(nftId)) {
        return false;
    }
    return true;
}

bool ScriptStateContext::allowedNftPut(const uint288& nftId) {
    auto it = _nftPutsSet.find(nftId);
    if (it != _nftPutsSet.end()) {
        return false;
    }
    return true;
}

bool ScriptStateContext::performNftPut(const uint288& nftId) {
    // Record that balance for the token id is performed
    _nftPutsSet.insert(nftId);
    std::string nftIdStr = nftId.GetHex();
    if (!_nftStateIncoming.contains(nftIdStr)) {
        // No incoming balance can be added
        return false;
    }
    auto valtype = _nftStateIncoming[nftIdStr];
    _nftState[nftIdStr] = true;
    _nftBalancesUpdates[nftIdStr] = true;
    return true;
}

bool ScriptStateContext::contractFtBalanceAdd(const uint288& ftId) {
    if (!_ftStateIncoming.contains(ftId.GetHex())) {
        // No incoming balance can be added
        return false;
    }
    // Do not allow adding to the same balance more than once
    if (!allowedFtBalanceAdd(ftId)) {
        return false;
    }
    auto valtype = _ftStateIncoming[ftId.GetHex()];
    // Get the maximum allowed balance to add
    auto allowedToAddUpTo = valtype.template get<std::uint64_t>();
    if (!performFtBalanceAdd(ftId, allowedToAddUpTo)) {
        return false;
    }
    return true;
}

bool ScriptStateContext::allowedFtBalanceAdd(const uint288& ftId) {
    auto it = _ftAddsSet.find(ftId);
    if (it != _ftAddsSet.end()) {
        return false;
    }
    return true;
}

bool ScriptStateContext::performFtBalanceAdd(const uint288& ftId, uint64_t amount) {
    if (amount <= 0) {
        return false;
    }
    // Record that balance for the token id is performed
    _ftAddsSet.insert(ftId);
    std::string ftIdStr = ftId.GetHex();
    if (!_ftStateIncoming.contains(ftIdStr)) {
        // No incoming balance can be added
        return false;
    }
    auto valtype = _ftStateIncoming[ftIdStr];
    auto allowedToAddUpTo = valtype.template get<std::uint64_t>();
    if (amount > allowedToAddUpTo) {
        return false;
    }
    uint64_t currentValue = 0;
    if (_ftState.contains(ftIdStr)) {
        currentValue = _ftState[ftIdStr].template get<std::uint64_t>();
    }
    currentValue += amount;
    _ftState[ftIdStr] = currentValue;
    _ftBalancesUpdates[ftIdStr] = currentValue;
    return true;
}

uint64_t ScriptStateContext::contractFtBalance(const uint288 &ftId) {
    auto ftBalanceIt = _ftState.find(ftId.GetHex());
    if (ftBalanceIt == _ftState.end()) {
        // No balance found
        return 0;
    }
    return ftBalanceIt->template get<std::uint64_t>();
}

uint64_t ScriptStateContext::contractFtBalanceIncoming(const uint288 &ftId) {
    auto ftBalanceIt = _ftStateIncoming.find(ftId.GetHex());
    if (ftBalanceIt == _ftStateIncoming.end()) {
        // No balance found
        return 0;
    }
    return ftBalanceIt->template get<std::uint64_t>();
}

bool ScriptStateContext::contractNftExists(const uint288 &nftId) {
    auto nftBalanceIt = _nftState.find(nftId.GetHex());
    if (nftBalanceIt == _nftState.end()) {
        // No balance found
        return false;
    }
    auto result = nftBalanceIt->template get<bool>();
    return result;
}

bool ScriptStateContext::contractNftExistsIncoming(const uint288 &nftId) {
    auto nftBalanceIt = _nftStateIncoming.find(nftId.GetHex());
    if (nftBalanceIt == _nftStateIncoming.end()) {
        // No balance found
        return false;
    }
    auto result = nftBalanceIt->template get<bool>();
    return result;
}


uint32_t ScriptStateContext::getFtCount() const {
    return _ftState.size();
}

uint32_t ScriptStateContext::getFtCountIncoming() const {
    return _ftStateIncoming.size();
}

uint32_t ScriptStateContext::getNftCount() const {
    return _nftState.size();
}

uint32_t ScriptStateContext::getNftCountIncoming() const {
    return _nftStateIncoming.size();
}

bool ScriptStateContext::getFtItem(uint32_t index, uint288 &tokenId) const {
    // Inefficient, but it's okay for now
    // Todo: future optimization is create a vector representation of token ids in sorted order to have random access
    uint32_t counter = 0;
    auto it = _ftState.begin();
    while (it != _ftState.end()) {
        if (counter == index) {
            uint288 ref = uint288S(it.key().c_str());
            tokenId = ref;
            return true;
        }
        counter++;
        it++;
    }
    return false;
}

bool ScriptStateContext::getFtItemIncoming(uint32_t index, uint288 &tokenId) const {
    // Inefficient, but it's okay for now
    // Todo: future optimization is create a vector representation of token ids in sorted order to have random access
    uint32_t counter = 0;
    auto it = _ftStateIncoming.begin();
    while (it != _ftStateIncoming.end()) {
        if (counter == index) {
            uint288 ref = uint288S(it.key().c_str());
            tokenId = ref;
            return true;
        }
        counter++;
        it++;
    }
    return false;
}

bool ScriptStateContext::getNftItem(uint32_t index, uint288 &tokenId) const {
    uint32_t counter = 0;
    auto it = _nftState.begin();
    while (it != _nftState.end()) {
        if (counter == index) {
            uint288 ref = uint288S(it.key().c_str());
            tokenId = ref;
            return true;
        }
        counter++;
        it++;
    }
    return false;
}

bool ScriptStateContext::getNftItemIncoming(uint32_t index, uint288 &tokenId) const {
    uint32_t counter = 0;
    auto it = _nftStateIncoming.begin();
    while (it != _nftStateIncoming.end()) {
        if (counter == index) {
            uint288 ref = uint288S(it.key().c_str());
            tokenId = ref;
            return true;
        }
        counter++;
        it++;
    }
    return false;
}

bool ScriptStateContext::encodeFtWithdrawMap(json &ftWithdraws) const {
    std::map<uint288, std::map<uint32_t, uint64_t>>::const_iterator _ftWithdrawMapIt;
    json contractFtWithdraws({});
    for (_ftWithdrawMapIt = _ftWithdrawMap.begin(); _ftWithdrawMapIt != _ftWithdrawMap.end(); _ftWithdrawMapIt++) {
        uint288 tokenId = _ftWithdrawMapIt->first;
        std::map<uint32_t, uint64_t>::const_iterator outputsIt;
        for (outputsIt = _ftWithdrawMapIt->second.begin(); outputsIt != _ftWithdrawMapIt->second.end(); outputsIt++) {
            std::string tokenIdS = tokenId.GetHex();
            if (!contractFtWithdraws.contains(tokenIdS)) {
                contractFtWithdraws[tokenIdS] = json({});
            }
            contractFtWithdraws[tokenIdS][std::to_string(outputsIt->first)] = outputsIt->second;
        }
    }
    // If succeeded, then assign
    ftWithdraws = contractFtWithdraws;
    return true;
}

bool ScriptStateContext::encodeNftWithdrawMap(json &nftWithdraws) const {
    std::map<uint288, uint32_t>::const_iterator _nftWithdrawMapIt;
    json contractNftWithdraws({});
    for (_nftWithdrawMapIt = _nftWithdrawMap.begin(); _nftWithdrawMapIt != _nftWithdrawMap.end(); _nftWithdrawMapIt++) {
        uint288 tokenId = _nftWithdrawMapIt->first;
        uint32_t outputIdx = _nftWithdrawMapIt->second;
        std::string tokenIdS = tokenId.GetHex();
        if (!contractNftWithdraws.contains(tokenIdS)) {
            contractNftWithdraws[tokenIdS] = json({});
        }
        contractNftWithdraws[tokenIdS] = outputIdx;
    }
    // If succeeded, then assign
    nftWithdraws = contractNftWithdraws;
    return true;
}

bool ScriptStateContext::isAllowedBlockInfoHeight(const uint32_t height) const {
    uint32_t revisedHeight = height;
    if (revisedHeight == 0) {
        revisedHeight = _externalStateStruct.currentHeight;
    }
    auto it = _externalStateStruct.headers.find(revisedHeight);
    if (it == _externalStateStruct.headers.end()) {
        return false;
    }
    return true;
}

CBlockHeader ScriptStateContext::getBlockInfoByHeight(uint32_t height) const {
    uint32_t revisedHeight = height;
    if (revisedHeight == 0) {
        revisedHeight = _externalStateStruct.currentHeight;
    }

    HeightToBlockInfoStruct::const_iterator itemIt = _externalStateStruct.headers.find(revisedHeight);
    if (itemIt == _externalStateStruct.headers.end()) {
        throw new InvalidBlockInfoHeight();
    }
    return itemIt->second.header;
}

void ScriptStateContext::getCurrentBlockInfoHeader(uint32_t height, std::vector<uint8_t> &value) const {
    if (!isAllowedBlockInfoHeight(height)) {
        // Throw exception because we should not have been called at this level if it wasnt valid
        throw new InvalidBlockInfoHeight();
    }
    uint32_t revisedHeight = height;
    if (revisedHeight == 0) {
        revisedHeight = _externalStateStruct.currentHeight;
    }

    HeightToBlockInfoStruct::const_iterator itemIt = _externalStateStruct.headers.find(revisedHeight);
    if (itemIt == _externalStateStruct.headers.end()) {
        throw new InvalidBlockInfoHeight();
    }
    value = itemIt->second.headerHex;
}

uint64_t ScriptStateContext::getCurrentBlockInfoHeight(const uint32_t height) const {
    if (!isAllowedBlockInfoHeight(height)) {
        // Throw exception because we should not have been called at this level if it wasnt valid
        throw new InvalidBlockInfoHeight();
    }
    uint32_t revisedHeight = height;
    if (revisedHeight == 0) {
        revisedHeight = _externalStateStruct.currentHeight;
    }
    return revisedHeight;
}

uint32_t ScriptStateContext::getCurrentBlockInfoVersion(uint32_t height) const {
    if (!isAllowedBlockInfoHeight(height)) {
        // Throw exception because we should not have been called at this level if it wasnt valid
        throw new InvalidBlockInfoHeight();
    }
    uint32_t revisedHeight = height;
    if (revisedHeight == 0) {
        revisedHeight = _externalStateStruct.currentHeight;
    }
    CBlockHeader currentHeader = getBlockInfoByHeight(revisedHeight);
    return currentHeader.nVersion;
}

void ScriptStateContext::getCurrentBlockInfoPrevHash(uint32_t height, std::vector<uint8_t> &value) const {
    if (!isAllowedBlockInfoHeight(height)) {
        // Throw exception because we should not have been called at this level if it wasnt valid
        throw new InvalidBlockInfoHeight();
    }
    uint32_t revisedHeight = height;
    if (revisedHeight == 0) {
        revisedHeight = _externalStateStruct.currentHeight;
    }
    CBlockHeader currentHeader = getBlockInfoByHeight(revisedHeight);
    std::copy(currentHeader.hashPrevBlock.begin(), currentHeader.hashPrevBlock.end(), std::back_inserter(value));
}

void ScriptStateContext::getCurrentBlockInfoMerkleRoot(uint32_t height, std::vector<uint8_t> &value) const {
    if (!isAllowedBlockInfoHeight(height)) {
        // Throw exception because we should not have been called at this level if it wasnt valid
        throw new InvalidBlockInfoHeight();
    }
    uint32_t revisedHeight = height;
    if (revisedHeight == 0) {
        revisedHeight = _externalStateStruct.currentHeight;
    }
    CBlockHeader currentHeader = getBlockInfoByHeight(revisedHeight);
    std::copy(currentHeader.hashMerkleRoot.begin(), currentHeader.hashMerkleRoot.end(), std::back_inserter(value));
}

uint32_t ScriptStateContext::getCurrentBlockInfoTime(uint32_t height) const {
    if (!isAllowedBlockInfoHeight(height)) {
        // Throw exception because we should not have been called at this level if it wasnt valid
        throw new InvalidBlockInfoHeight();
    }
    uint32_t revisedHeight = height;
    if (revisedHeight == 0) {
        revisedHeight = _externalStateStruct.currentHeight;
    }
    CBlockHeader currentHeader = getBlockInfoByHeight(revisedHeight);
    return currentHeader.nTime;
}

uint32_t ScriptStateContext::getCurrentBlockInfoBits(uint32_t height) const {
    if (!isAllowedBlockInfoHeight(height)) {
        // Throw exception because we should not have been called at this level if it wasnt valid
        throw new InvalidBlockInfoHeight();
    }
    uint32_t revisedHeight = height;
    if (revisedHeight == 0) {
        revisedHeight = _externalStateStruct.currentHeight;
    }
    CBlockHeader currentHeader = getBlockInfoByHeight(revisedHeight);
    return currentHeader.nBits;
}

uint32_t ScriptStateContext::getCurrentBlockInfoNonce(uint32_t height) const {
    if (!isAllowedBlockInfoHeight(height)) {
        // Throw exception because we should not have been called at this level if it wasnt valid
        throw new InvalidBlockInfoHeight();
    }
    uint32_t revisedHeight = height;
    if (revisedHeight == 0) {
        revisedHeight = _externalStateStruct.currentHeight;
    }

    CBlockHeader currentHeader = getBlockInfoByHeight(revisedHeight);
    return currentHeader.nNonce;
}

uint64_t ScriptStateContext::getCurrentBlockInfoDifficulty(uint32_t height) const {
    if (!isAllowedBlockInfoHeight(height)) {
        // Throw exception because we should not have been called at this level if it wasnt valid
        throw new InvalidBlockInfoHeight();
    }
    uint32_t revisedHeight = height;
    if (revisedHeight == 0) {
        revisedHeight = _externalStateStruct.currentHeight;
    }
    CBlockHeader currentHeader = getBlockInfoByHeight(revisedHeight);

    int nShift = (currentHeader.nBits >> 24) & 0xff;
    double dDiff = double(0x0000ffff) / double(currentHeader.nBits & 0x00ffffff);

    while (nShift < 29) {
        dDiff *= 256.0;
        nShift++;
    }
    while (nShift > 29) {
        dDiff /= 256.0;
        nShift--;
    }
    // Round to the nearest
    return std::llround(dDiff);
}

uint32_t ScriptStateContext::getBlockInfoVersion(const std::vector<uint8_t> &header) const {
    CBlockHeader decodedHeader = ScriptStateContext::decodeHeader(header);
    return decodedHeader.nVersion;
}

void ScriptStateContext::getBlockInfoPrevHash(const std::vector<uint8_t> &header, std::vector<uint8_t> &value) const {
    CBlockHeader decodedHeader = ScriptStateContext::decodeHeader(header);
    std::copy(decodedHeader.hashPrevBlock.begin(), decodedHeader.hashPrevBlock.end(), std::back_inserter(value));
}

void ScriptStateContext::getBlockInfoMerkleRoot(const std::vector<uint8_t> &header, std::vector<uint8_t> &value) const {
    CBlockHeader decodedHeader = ScriptStateContext::decodeHeader(header);
    std::copy(decodedHeader.hashMerkleRoot.begin(), decodedHeader.hashMerkleRoot.end(), std::back_inserter(value));
}

uint32_t ScriptStateContext::getBlockInfoTime(const std::vector<uint8_t> &header) const {
    CBlockHeader decodedHeader = ScriptStateContext::decodeHeader(header);
    return decodedHeader.nTime;
}

uint32_t ScriptStateContext::getBlockInfoBits(const std::vector<uint8_t> &header) const {
    CBlockHeader decodedHeader = ScriptStateContext::decodeHeader(header);
    return decodedHeader.nBits;
}

uint32_t ScriptStateContext::getBlockInfoNonce(const std::vector<uint8_t> &header) const {
    CBlockHeader decodedHeader = ScriptStateContext::decodeHeader(header);
    return decodedHeader.nNonce;
}

uint64_t ScriptStateContext::getBlockInfoDifficulty(const std::vector<uint8_t> &header) const {
    CBlockHeader decodedHeader = ScriptStateContext::decodeHeader(header);
    int nShift = (decodedHeader.nBits >> 24) & 0xff;
    double dDiff = double(0x0000ffff) / double(decodedHeader.nBits & 0x00ffffff);

    while (nShift < 29) {
        dDiff *= 256.0;
        nShift++;
    }
    while (nShift > 29) {
        dDiff /= 256.0;
        nShift--;
    }
    // Round to the nearest
    return std::llround(dDiff);
}

CBlockHeader ScriptStateContext::decodeHeader(const std::vector<uint8_t> &header) {
    CBlockHeader decodedHeader;
    if (!DecodeHexBlockHeaderDup(HexStr(header), decodedHeader)) {
        throw HeaderDecodeError();
    }
    return decodedHeader;
}

bool ScriptStateContext::checkTxInBlock(const std::vector<uint8_t> &header, const std::vector<uint8_t> &proof,
                                        const uint256 &txid) const {
    // Todo: Decode the header
    // Verify header has the POW correct and also matches the hash merkle root of the merkleblock

    CDataStream ssMB(proof, SER_NETWORK, PROTOCOL_VERSION);
    CMerkleBlock merkleBlock;
    ssMB >> merkleBlock;
    std::vector<uint256> vMatch;
    std::vector<size_t> vIndex;
    if (merkleBlock.txn.ExtractMatches(vMatch, vIndex) != merkleBlock.header.hashMerkleRoot) {
        return false;
    }
    // Check if proof is valid, only add results if so
    for (const uint256 &hash : vMatch) {
        // One of them matches the txid which means it is a valid merkle proof
        if (hash == txid) {
            return true;
        }
    }
    return false;
}

ContractStateExternalStruct ScriptStateContext::validateContractStateExternal(const json &contractStateExternalJson) {
    // Validate the header is present and validate
    auto headersJsonEntry = contractStateExternalJson.find("headers");
    if (headersJsonEntry == contractStateExternalJson.end()) {
        throw HeaderKeyNotFoundError();
    }
    // Validate the height is present and validate
    auto heightJsonEntry = contractStateExternalJson.find("height");
    if (heightJsonEntry == contractStateExternalJson.end()) {
        throw HeightKeyNotFoundError();
    }
    // Check the height range is valid
    uint32_t currentHeight = heightJsonEntry->template get<std::uint32_t>();
    if (currentHeight > 10000000) {
        throw new HeightInvalidError();
    }
    ContractStateExternalStruct external;
    HeightToBlockInfoStruct heightHeaderSet;
    for (auto &[keyHeight, headerString] : headersJsonEntry->items()) {
        CBlockHeader currentHeader;
        unsigned int height = atoi(keyHeight.c_str());
        if (!DecodeHexBlockHeaderDup(headerString, currentHeader)) {
            throw CurrentHeaderDecodeError();
        }

        ExternalBlockInfoStruct externalBlockInfoStruct;
        externalBlockInfoStruct.header = currentHeader;
        externalBlockInfoStruct.height = height;
        const std::vector<uint8_t> header_data{ParseHex(headerString)};
        externalBlockInfoStruct.headerHex = header_data;
        heightHeaderSet.insert(std::make_pair(height, externalBlockInfoStruct));
    }
    external.headers = heightHeaderSet;
    external.currentHeight = currentHeight;
    return external;
}

json ScriptStateContext::getFtWithdrawsResult() const {
    json ftWithdraws({});
    if (!this->encodeFtWithdrawMap(ftWithdraws)) {
        throw new CriticalUnexpectedError();
    }
  
    return ftWithdraws;
}
json ScriptStateContext::getNftWithdrawsResult() const {
    json nftWithdraws({});
    if (!this->encodeNftWithdrawMap(nftWithdraws)) {
        throw new CriticalUnexpectedError();
    }  
    return nftWithdraws;
}
 
json ScriptStateContext::getFtIncomingBalancesAddedResult() const {
    json ftBalancesAdded({});
    if (!this->encodeFtIncomingBalancesAddedMap(ftBalancesAdded)) {
        throw new CriticalUnexpectedError();
    }
  
    return ftBalancesAdded;
}
json ScriptStateContext::getNftIncomingPutsResult() const {
    json nftPuts({});
    if (!this->encodeNftIncomingPutsMap(nftPuts)) {
        throw new CriticalUnexpectedError();
    }  
    return nftPuts;
}
 
bool ScriptStateContext::encodeFtIncomingBalancesAddedMap(json &ftBalancesAdded) const {
    std::set<uint288>::const_iterator ftAddsSetIt;
    json ftAddsSetJson({});
    for (ftAddsSetIt = _ftAddsSet.begin(); ftAddsSetIt != _ftAddsSet.end(); ftAddsSetIt++) {
        uint288 tokenId = *ftAddsSetIt;
        std::string tokenIdS = tokenId.GetHex();
        ftAddsSetJson[tokenIdS] = true;
    }
    // If succeeded, then assign
    ftBalancesAdded = ftAddsSetJson;
    return true;
}

bool ScriptStateContext::encodeNftIncomingPutsMap(json &nftPuts) const {
    std::set<uint288>::const_iterator nftPutsSetIt;
    json nftPutsJson({});
    for (nftPutsSetIt = _nftPutsSet.begin(); nftPutsSetIt != _nftPutsSet.end(); nftPutsSetIt++) {
        uint288 tokenId = *nftPutsSetIt;
        std::string tokenIdS = tokenId.GetHex();
        nftPutsJson[tokenIdS] = true;
    }
    // If succeeded, then assign
    nftPuts = nftPutsJson;
    return true;
}
