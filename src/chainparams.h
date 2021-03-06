// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2013 The Bitcoin developers
// Copyright (c) 2014 Kryptohash developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CHAIN_PARAMS_H
#define BITCOIN_CHAIN_PARAMS_H

#include "bignum.h"
#include "uint256.h"
#include "kryptohashnet.h"
#include "genesis.h"
#include <vector>

#include <boost/lexical_cast.hpp>

using namespace std;

#define MESSAGE_START_SIZE 4
typedef unsigned char MessageStartChars[MESSAGE_START_SIZE];

class CAddress;
class CBlock;

struct CDNSSeedData {
    string name, host;
    CDNSSeedData(const string &strName, const string &strHost) : name(strName), host(strHost) {}
};

/**
 * CChainParams defines various tweakable parameters of a given instance of the
 * Bitcoin system. There are three: the main network on which people trade goods
 * and services, the public test network which gets reset from time to time and
 * a regression test mode which is intended for private networks only. It has
 * minimal difficulty to ensure that blocks can be found instantly.
 */
class CChainParams
{
public:
    enum Network {
        MAIN,
        TESTNET,
        REGTEST,

        MAX_NETWORK_TYPES
    };

    enum Base58Type {
        PUBKEY_ADDRESS,
        SCRIPT_ADDRESS,
        SECRET_KEY,
        EXT_PUBLIC_KEY,
        EXT_SECRET_KEY,

        MAX_BASE58_TYPES
    };

    const uint320& HashGenesisBlock() const { return hashGenesisBlock; }
    const uint320& GenesisMerkleRoot() const { return genesisMerkleRoot; }
    const MessageStartChars& MessageStart() const { return pchMessageStart; }
    const vector<unsigned char>& GenesisPubKey() const { return vGenesisAddr; }
    const vector<unsigned char>& AlertKey() const { return vAlertPubKey; }
    int GetDefaultPort() const { return nDefaultPort; }
    int GetRegionCode() const { return nRegion; }
    int GetSideChainCode() const { return nSideChainCode; }
    uint64_t GetSideChainMask() const { return nSideChainMask; }
    const CBigNum& ProofOfWorkLimit() const { return bnProofOfWorkLimit; }
    int64_t RandomSubsidyEnds() const { return nRandomSubsidyEnds; }
    int64_t RandomSubsidyBegins() const { return nRandomSubsidyBegins; }
    int MaxSubsidy() const { return nMaxSubsidy; }
    int SideChainSubsidy() const { return nSideChainSubsidy; }
    virtual const CBlock& GenesisBlock() const = 0;
    virtual bool RequireRPCPassword() const { return true; }
    const string& DataDir() const { return strDataDir; }
    virtual Network NetworkID() const = 0;
    const vector<CDNSSeedData>& DNSSeeds() const { return vSeeds; }
    const std::vector<unsigned char> &Base58Prefix(Base58Type type) const { return base58Prefixes[type]; }
    virtual const vector<CAddress>& FixedSeeds() const = 0;
    virtual bool UpdateParams(const int nRegionIn, const CGenesis dataIn) const = 0;
    int RPCPort() const { return nRPCPort; }
    void SetSideChainMask(uint64_t nSideChainMaskIn) const { nSideChainMask = nSideChainMaskIn; }

protected:
    CChainParams() {}

    void SetRegionCode(int nRegionIn) const {
        nRegion = nRegionIn % MAX_NUM_OF_REGIONS;
        if (NetworkID() == CChainParams::TESTNET) {
            nDefaultPort = P2P_PORT_TESTNET(nRegionIn);
            nRPCPort = RPC_PORT_TESTNET(nRegionIn);
            strDataDir = "testnet";
        }
        else if (NetworkID() == CChainParams::REGTEST) {
            nDefaultPort = P2P_PORT_REGRESSION;
            nRPCPort = RPC_PORT_TESTNET(nRegionIn);
            strDataDir = "regtest";
        }
        else {
            nDefaultPort = P2P_PORT(nRegionIn);
            nRPCPort = RPC_PORT(nRegionIn);
            strDataDir = "region";
        }
        strDataDir += boost::lexical_cast<std::string>(nRegion);
    }

    mutable int nRegion;
    mutable int nDefaultPort;
    mutable int nRPCPort;
    mutable string strDataDir;
    mutable uint64_t nSideChainMask;
    mutable uint320 hashGenesisBlock;

    uint320 genesisMerkleRoot;
    MessageStartChars pchMessageStart;
    // Raw pub key bytes for the genesis block signing key.
    vector<unsigned char> vGenesisAddr;
    // Raw pub key bytes for the broadcast alert signing key.
    vector<unsigned char> vAlertPubKey;
    CBigNum bnProofOfWorkLimit;
    int64_t nRandomSubsidyBegins;
    int64_t nRandomSubsidyEnds;
    int nMaxSubsidy;
    int nSideChainCode;
    int nSideChainSubsidy;
    vector<CDNSSeedData> vSeeds;
    std::vector<unsigned char> base58Prefixes[MAX_BASE58_TYPES];
};

/**
 * Return the currently selected parameters. This won't change after app startup
 * outside of the unit tests.
 */
const CChainParams &Params();

/** Sets the params returned by Params() to those for the given network. */
void SelectParams(CChainParams::Network network);

/**
 * Looks for -regtest or -testnet and then calls SelectParams as appropriate.
 * Returns false if an invalid combination is given.
 */
bool SelectParamsFromCommandLine();

inline bool MainNet() {
    return Params().NetworkID() == CChainParams::MAIN;
}

inline bool TestNet() {
    // Note: it's deliberate that this returns "false" for regression test mode.
    return Params().NetworkID() == CChainParams::TESTNET;
}

inline bool RegTest() {
    return Params().NetworkID() == CChainParams::REGTEST;
}

#endif
