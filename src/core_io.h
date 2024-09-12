// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2020 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <attributes.h>
#include <script/sighashtype.h>
#include <univalue.h>

#include <string>
#include <vector>

struct Amount;
class CBlock;
class CBlockHeader;
class CMutableTransaction;
class Config;
class CScript;
class CTransaction;
class uint160;
class uint256;

// core_read.cpp
CScript ParseScript(const std::string &s);
[[nodiscard]] bool DecodeHexTx(CMutableTransaction &tx,
                               const std::string &strHexTx);
[[nodiscard]] bool DecodeHexBlk(CBlock &, const std::string &strHexBlk);
bool DecodeHexBlockHeader(CBlockHeader &, const std::string &hex_header);

/**
 * Parse a hex string into 256 bits
 * @param[in] strHex a hex-formatted, 64-character string
 * @param[out] result the result of the parsing
 * @returns true if successful, false if not
 *
 * @see ParseHashV for an RPC-oriented version of this
 */
bool ParseHashStr(const std::string &strHex, uint256 &result);
/**
 * Variant of above: Parse a hex string into 160 bits.
 * @param[in] strHex a hex-formatted, 40-character string
 * @param[out] result the result of the parsing
 * @returns true if successful, false if not
 */
bool ParseHashStr(const std::string &strHex, uint160 &result);
std::vector<uint8_t> ParseHexUV(const UniValue &v, const std::string &strName);
SigHashType ParseSighashString(const UniValue &sighash);

// core_write.cpp
UniValue ValueFromAmount(const Amount &amount);
std::string FormatScript(const CScript &script);
std::string EncodeHexTx(const CTransaction &tx, const int serializeFlags = 0);
std::string SighashToStr(uint8_t sighash_type);
 