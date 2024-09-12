#pragma once
#include "constants.h"
#include "json.hpp"
#include <crypto/sha256.h>
#include <crypto/sha512.h>
#include <iostream>
#include <util/strencodings.h>
#include <vector>

using json = nlohmann::json;

class UnexpectedStateKeyTypeError : public std::exception {};

// Size limit errors
class StateValidationStateSizeLimitError : public std::exception {};
class StateValidationStateUpdateSizeLimitError : public std::exception {};
class StateValidationStateDeleteSizeLimitError : public std::exception {};
class StateValidationTokenFtBalanceSizeLimitError : public std::exception {};
class StateValidationTokenFtBalanceUpdateSizeLimitError : public std::exception {};
class StateValidationTokenNftBalanceSizeLimitError : public std::exception {};
class StateValidationTokenNftBalanceUpdateSizeLimitError : public std::exception {};
// Format errors
class StateValidationStateFormatError : public std::exception {};
class StateValidationStateUpdateFormatError : public std::exception {};
class StateValidationStateDeleteFormatError : public std::exception {};
class StateValidationTokenFtBalanceFormatError : public std::exception {};
class StateValidationTokenFtBalanceZeroFormatError : public std::exception {};
class StateValidationTokenFtBalanceUpdateFormatError : public std::exception {};
class StateValidationTokenNftBalanceFormatError : public std::exception {};
class StateValidationTokenNftBalanceUpdateFormatError : public std::exception {};

class StateKeyspaceCleanupError : public std::exception {};

template <typename T>
void AppendVector(std::vector<T> &a, const std::vector<T> &b) {
    a.reserve(a.size() + b.size());
    a.insert(a.end(), b.begin(), b.end());
}
static inline void CopyBytes(const std::vector<std::uint8_t> &bytes, uint8_t *dest, unsigned int *destLen) {
    std::copy(bytes.begin(), bytes.end(), dest);
    *destLen = bytes.size();
}
static inline void CopyBytesNoDestLen(const std::vector<std::uint8_t> &bytes, uint8_t *dest) {
    std::copy(bytes.begin(), bytes.end(), dest);
}

static inline bool isHexStr(std::string const &s) {
    return s.find_first_not_of("0123456789abcdef") == std::string::npos && s.length() % 2 == 0 && s.length() >= 2;
}

static inline std::string HexStrWith00Null(const std::vector<uint8_t> &value) {
    if (value.size() == 0) {
        return std::string("00");
    }
    return HexStr(value);
}

class StateValidation {
public:
    static void performValidateStateRestrictions(const json &ftState, const json &ftStateUpdates,
                                                 const json &ftStateIncoming, const json &nftState,
                                                 const json &nftStateUpdates, const json &nftStateIncoming,
                                                 const json &contractState, const json &contractStateUpdates,
                                                 const json &contractStateDeletes) {
        // validate each in turn...
        uint32_t stateByteCount = StateValidation::performValidateStateRestrictionsState(contractState);
        if (stateByteCount > MAX_STATE_FINAL_BYTES) {
            throw new StateValidationStateSizeLimitError();
        }
        uint32_t stateUpdatesByteCount = StateValidation::performValidateStateRestrictionsState(contractStateUpdates);

        if (stateUpdatesByteCount > MAX_STATE_UPDATE_BYTES) {
            throw new StateValidationStateUpdateSizeLimitError();
        }
        uint32_t stateDeletesByteCount =
            StateValidation::performValidateStateRestrictionsStateDeletes(contractStateDeletes);
        if (stateDeletesByteCount > MAX_STATE_UPDATE_BYTES) {
            throw new StateValidationStateDeleteSizeLimitError();
        }
        uint32_t ftBalancesByteCount = StateValidation::performValidateStateRestrictionsTokenFtBalances(ftState);
        if (ftBalancesByteCount > MAX_BALANCES_BYTES) {
            throw new StateValidationTokenFtBalanceSizeLimitError();
        }
        uint32_t ftBalancesUpdatesByteCount =
            StateValidation::performValidateStateRestrictionsTokenFtBalances(ftStateUpdates, true);
        if (ftBalancesUpdatesByteCount > MAX_BALANCES_UPDATE_BYTES) {
            throw new StateValidationTokenFtBalanceUpdateSizeLimitError();
        }
        // No bytes size validation on the incoming ft balances
        StateValidation::performValidateStateRestrictionsTokenFtBalances(ftStateIncoming);

        uint32_t nftBalancesByteCount = StateValidation::performValidateStateRestrictionsTokenNftBalances(nftState);
        if (nftBalancesByteCount > MAX_BALANCES_BYTES) {
            throw new StateValidationTokenNftBalanceSizeLimitError();
        }

        uint32_t nftBalancesUpdatesByteCount =
            StateValidation::performValidateStateRestrictionsTokenNftBalances(nftStateUpdates, true);
        if (nftBalancesUpdatesByteCount > MAX_BALANCES_UPDATE_BYTES) {
            throw new StateValidationTokenNftBalanceUpdateSizeLimitError();
        }
        // No bytes size validation validation on incoming nft balances
        StateValidation::performValidateStateRestrictionsTokenNftBalances(nftStateIncoming);
    }

    static uint32_t performValidateStateRestrictionsState(const json &obj) {
        uint32_t byteCount = 0;
        for (auto &[key, value] : obj.items()) {
            // Ensure key is a valid hex string
            if (!isHexStr(key)) {
                throw new StateValidationStateFormatError();
            }
            byteCount += key.length() / 2;
            // Ensure value is an object
            if (!value.is_object()) {
                throw new StateValidationStateFormatError();
            }
            // Ensure object is not empty
            if (value.empty()) {
                throw new StateValidationStateFormatError();
            }
            // Ensure second level keys are valid hex
            for (auto &[secondKey, secondValue] : value.items()) {
                if (!isHexStr(secondKey)) {
                    throw new StateValidationStateFormatError();
                }
                byteCount += secondKey.length() / 2;
                // Ensure second level values are valid hex strings
                if (!secondValue.is_string()) {
                    throw new StateValidationStateFormatError();
                }
                std::string secondValueStr = secondValue.template get<std::string>();
                if (!isHexStr(secondValueStr)) {
                    throw new StateValidationStateFormatError();
                }
                byteCount += secondValueStr.length() / 2;
            }
        }
        return byteCount;
    }

    static uint32_t performValidateStateRestrictionsStateDeletes(const json &obj) {
        uint32_t byteCount = 0;
        for (auto &[key, value] : obj.items()) {
            // Ensure key is a valid hex string
            if (!isHexStr(key)) {
                throw new StateValidationStateDeleteFormatError();
            }
            byteCount += key.length() / 2;
            // Ensure value is an object
            if (!value.is_object()) {
                throw new StateValidationStateDeleteFormatError();
            }
            // Ensure object is not empty
            if (value.empty()) {
                throw new StateValidationStateDeleteFormatError();
            }
            // Ensure second level keys are valid hex
            for (auto &[secondKey, secondValue] : value.items()) {
                if (!isHexStr(secondKey)) {
                    throw new StateValidationStateDeleteFormatError();
                }
                byteCount += secondKey.length() / 2;
                // Ensure second level values are boolean.
                // Note: they do not count towards the byte count
                // Must always be boolean true
                if (!secondValue.is_boolean()) {
                    throw new StateValidationStateDeleteFormatError();
                }
                bool secondValueBool = secondValue.template get<bool>();
                if (!secondValueBool) {
                    throw new StateValidationStateFormatError();
                }
            }
        }
        return byteCount;
    }

    static uint32_t performValidateStateRestrictionsTokenFtBalances(const json &obj, bool isAllowZeroBalance = false) {
        uint32_t byteCount = 0;
        for (auto &[key, value] : obj.items()) {
            // Ensure key is a valid hex string
            if (!isHexStr(key)) {
                throw new StateValidationTokenFtBalanceFormatError();
            }
            byteCount += key.length() / 2;
            // Ensure value is a number
            if (!value.is_number_unsigned()) {
                throw new StateValidationTokenFtBalanceFormatError();
            }
            // Allow zero balance if set
            uint64_t valueInt = value.template get<uint64_t>();
            if (!isAllowZeroBalance && valueInt == 0) {
                throw new StateValidationTokenFtBalanceZeroFormatError();
            }
            assert(sizeof(unsigned long) == 8);
            byteCount += 8;
        }
        return byteCount;
    }

    static uint32_t performValidateStateRestrictionsTokenNftBalances(const json &obj, bool isAllowFalse = false) {
        uint32_t byteCount = 0;
        for (auto &[key, value] : obj.items()) {
            // Ensure key is a valid hex string
            if (!isHexStr(key)) {
                throw new StateValidationTokenNftBalanceFormatError();
            }
            byteCount += key.length() / 2;
            // Ensure value is a bool
            if (!value.is_boolean()) {
                throw new StateValidationTokenNftBalanceFormatError();
            }
            // Allow false if set
            bool valueBool = value.template get<bool>();
            if (!isAllowFalse && !valueBool) {
                throw new StateValidationTokenNftBalanceFormatError();
            }
            // Do not count bytes for the value
        }
        return byteCount;
    }
};

// Given a json object, serialize all of the keys and values recursively as a std::vector<uint8_t>
static uint32_t GetStateDataVectorOnlyStrings(const json &stateData, std::vector<uint8_t> &resultDataVec) {
    for (auto &[key, value] : stateData.items()) {
        std::vector<uint8_t> keyBytes = ParseHex(key);
        AppendVector(resultDataVec, keyBytes);
        if (value.is_string()) {
            std::vector<uint8_t> valueBytes = ParseHex(value);
            AppendVector(resultDataVec, valueBytes);
        } else if (value.is_object()) {
            GetStateDataVectorOnlyStrings(value, resultDataVec);
        } else {
            throw new UnexpectedStateKeyTypeError();
        }
    }
    return resultDataVec.size();
}

static void SerializeUint64_t(uint64_t val, std::vector<uint8_t> &resultData) {
    uint8_t result[8];
    std::memcpy(result, &val, sizeof val);
    std::vector<uint8_t> serializedInt(&result[0], &result[0] + 8);
    resultData = serializedInt;
}
static void SerializeUint32_t(uint32_t val, std::vector<uint8_t> &resultData) {
    uint8_t result[4];
    std::memcpy(result, &val, sizeof val);
    std::vector<uint8_t> serializedInt(&result[0], &result[0] + 4);
    resultData = serializedInt;
}
static uint32_t GetStateDataVectorStringKeyBooleanValue(const json &stateData, std::vector<uint8_t> &resultDataVec) {
    for (auto &[key, value] : stateData.items()) {
        std::vector<uint8_t> keyBytes = ParseHex(key);
        AppendVector(resultDataVec, keyBytes);
        if (!value.is_boolean()) {
            throw new UnexpectedStateKeyTypeError();
        }
        // Do nothing with value because we only use the keys
    }
    return resultDataVec.size();
}

static uint32_t GetStateDataVectorStringKeyIntValue(const json &stateData, std::vector<uint8_t> &resultDataVec) {
    for (auto &[key, value] : stateData.items()) {
        std::vector<uint8_t> keyBytes = ParseHex(key);
        AppendVector(resultDataVec, keyBytes);
        if (!value.is_number_integer() || value < 0) {
            throw new UnexpectedStateKeyTypeError();
        }
        // Do nothing with value because we only use the keys
    }
    return resultDataVec.size();
}

// Get the hash of the state data serialized for keys and values
static std::vector<uint8_t> GetStateDataHashState(const json &data) {
    std::vector<uint8_t> vchPreimage;
    GetStateDataVectorOnlyStrings(data, vchPreimage);
    std::vector<uint8_t> vchHash(32);
    CSHA256().Write(vchPreimage.data(), vchPreimage.size()).Finalize(vchHash.data());
    return vchHash;
}

static std::vector<uint8_t> GetStateDataHashNftBalanceHash(const json &data) {
    std::vector<uint8_t> vchPreimage;
    GetStateDataVectorStringKeyBooleanValue(data, vchPreimage);
    std::vector<uint8_t> vchHash(32);
    CSHA256().Write(vchPreimage.data(), vchPreimage.size()).Finalize(vchHash.data());
    return vchHash;
}

static std::vector<uint8_t> GetStateDataHashFtBalanceHash(const json &data) {
    std::vector<uint8_t> vchPreimage;
    GetStateDataVectorStringKeyIntValue(data, vchPreimage);
    std::vector<uint8_t> vchHash(32);
    CSHA256().Write(vchPreimage.data(), vchPreimage.size()).Finalize(vchHash.data());
    return vchHash;
}

static std::vector<uint8_t> GetStateDataHashNftWithdraws(const json &data) {
    std::vector<uint8_t> vchPreimage;
    for (auto &[key, value] : data.items()) {
        std::vector<uint8_t> keyBytes = ParseHex(key);
        AppendVector(vchPreimage, keyBytes);
        if (!value.is_number_integer() || value < 0) {
            throw new UnexpectedStateKeyTypeError();
        }
        // Serialize the integer
        std::vector<uint8_t> serializedIntValue;
        SerializeUint32_t(value, serializedIntValue);
        AppendVector(vchPreimage, serializedIntValue);
    }
    std::vector<uint8_t> vchHash(32);
    CSHA256().Write(vchPreimage.data(), vchPreimage.size()).Finalize(vchHash.data());
    return vchHash;
}

static std::vector<uint8_t> GetStateDataHashFtWithdraws(const json &data) {
    std::vector<uint8_t> vchPreimage;
    for (auto &[key, value] : data.items()) {
        std::vector<uint8_t> keyBytes = ParseHex(key);
        AppendVector(vchPreimage, keyBytes);
        for (auto &[secondKey, secondValue] : value.items()) {
            uint64_t secondKeyInt = atoi(secondKey);
            std::vector<uint8_t> serializedSecondKeyIntBytes;
            SerializeUint64_t(secondKeyInt, serializedSecondKeyIntBytes);
            AppendVector(vchPreimage, serializedSecondKeyIntBytes);
            if (!secondValue.is_number_integer()) {
                throw new UnexpectedStateKeyTypeError();
            }
            // Serialize the integer value
            std::vector<uint8_t> serializedSEcondValueInt;
            SerializeUint64_t(secondValue, serializedSEcondValueInt);
            AppendVector(vchPreimage, serializedSEcondValueInt);
        }
    }
    std::vector<uint8_t> vchHash(32);
    CSHA256().Write(vchPreimage.data(), vchPreimage.size()).Finalize(vchHash.data());
    return vchHash;
}

static uint32_t GetStateDataVectorOnly2LevelStringKeysBooleanValue(const json &stateData,
                                                                   std::vector<uint8_t> &resultDataVec) {
    for (auto &[key, value] : stateData.items()) {
        if (!value.is_object()) {
            throw new UnexpectedStateKeyTypeError();
        }
        std::vector<uint8_t> keyBytes = ParseHex(key);
        AppendVector(resultDataVec, keyBytes);
        for (auto &[secondKey, secondValue] : value.items()) {
            std::vector<uint8_t> secondKeyBytes = ParseHex(secondKey);
            AppendVector(resultDataVec, secondKeyBytes);
            if (!secondValue.is_boolean()) {
                throw new UnexpectedStateKeyTypeError();
            }
            // Do nothing with value because we only use the keys
        }
    }
    return resultDataVec.size();
}

// Get the hash of the state data deletes serialized for keys and values
static std::vector<uint8_t> GetStateDataHashDeletes(const json &data) {
    std::vector<uint8_t> vchPreimage;
    GetStateDataVectorOnly2LevelStringKeysBooleanValue(data, vchPreimage);
    std::vector<uint8_t> vchHash(32);
    CSHA256().Write(vchPreimage.data(), vchPreimage.size()).Finalize(vchHash.data());
    return vchHash;
}

static std::vector<uint8_t> CalculateStateHash(const std::vector<uint8_t> &prevHash, const json &stateFinal,
                                               const json &stateUpdates, const json &stateDeletes,
                                               const json &ftIncoming, const json &nftIncoming, const json &ftBalances,
                                               const json &ftBalancesUpdates, const json &nftBalances,
                                               const json &nftBalancesUpdates, const json &ftWithdraws,
                                               const json &nftWithdraws) {
    std::vector<uint8_t> concatData(prevHash);
    std::vector<uint8_t> stateFinalHash = GetStateDataHashState(stateFinal);
    std::vector<uint8_t> stateUpdatesHash = GetStateDataHashState(stateUpdates);
    std::vector<uint8_t> stateDeletesHash = GetStateDataHashDeletes(stateDeletes);
    std::vector<uint8_t> nftIncomingHash = GetStateDataHashNftBalanceHash(nftIncoming);
    std::vector<uint8_t> ftIncomingHash = GetStateDataHashFtBalanceHash(ftIncoming);
    std::vector<uint8_t> nftBalancesHash = GetStateDataHashNftBalanceHash(nftBalances);
    std::vector<uint8_t> ftBalancesHash = GetStateDataHashFtBalanceHash(ftBalances);
    std::vector<uint8_t> nftBalancesUpdatesHash = GetStateDataHashNftBalanceHash(nftBalancesUpdates);
    std::vector<uint8_t> ftBalancesUpdatesHash = GetStateDataHashFtBalanceHash(ftBalancesUpdates);
    std::vector<uint8_t> nftWithdrawHash = GetStateDataHashNftWithdraws(nftWithdraws);
    std::vector<uint8_t> ftWithdrawHash = GetStateDataHashFtWithdraws(ftWithdraws);

    AppendVector(concatData, nftIncomingHash);
    AppendVector(concatData, ftIncomingHash);
    AppendVector(concatData, stateFinalHash);
    AppendVector(concatData, stateUpdatesHash);
    AppendVector(concatData, stateDeletesHash);
    AppendVector(concatData, nftBalancesHash);
    AppendVector(concatData, ftBalancesHash);
    AppendVector(concatData, nftBalancesUpdatesHash);
    AppendVector(concatData, ftBalancesUpdatesHash);
    AppendVector(concatData, nftWithdrawHash);
    AppendVector(concatData, ftWithdrawHash);

    // Store the updated state hash
    std::vector<uint8_t> vchHash(32);
    CSHA256().Write(concatData.data(), concatData.size()).Finalize(vchHash.data());
    return vchHash;
}
