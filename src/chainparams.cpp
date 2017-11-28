// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2014-2017 Kryptohash developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"
#include "assert.h"
#include "core.h"
#include "protocol.h"
#include "util.h"

//
// Main network
//

unsigned int pnSeed[] =
{
    0xF8368368, 0x4F603EB2, 0x97250d45,
};

class CMainParams : public CChainParams {
public:
    CMainParams() {
        // The message start string is designed to be unlikely to occur in normal data.
        // The characters are rarely used upper ASCII, not valid as UTF-8, and produce
        // a large 4-byte int at any alignment.
        pchMessageStart[0] = 0xf1;
        pchMessageStart[1] = 0xec;
        pchMessageStart[2] = 0xb4;
        pchMessageStart[3] = 0x9d;
        vGenesisAddr = ParseHex("020DC9A10284FDA30C3749C308390BE2B0E2DF56BE836D136D37679F63B258EC13");
        vAlertPubKey = ParseHex("027C8D760AFB55F6B999AFE2CC8F659D63BB5FBD118750FE369D485B2F4C74D8A2");
        nSideChainCode = 0; //Default to 0. Not implemented yet.
        nSideChainMask = 0; //Default to 0. Not implemented yet.
        nRegion = 0; //Default to Region 0
        SetRegionCode(nRegion);

        bnProofOfWorkLimit = CBigNum(~uint320(0) >> 28);
		nSubsidyHalvingInterval = 210000;

        // Build the genesis block.
        const char* pszTimestamp = "The New York Times 11/27/2017: As Bitcoin Scrapes $10,000, an Investment Boom Like No Other.";
        CTransaction txNew;
        txNew.vin.resize(1);
        txNew.vout.resize(1);
        txNew.vin[0].prevout.n = (unsigned int)-2;
        txNew.vin[0].scriptSig = CScript() << 637599743 << CScriptNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew.vout[0].nValue = 1 * COIN;
        txNew.vout[0].scriptPubKey = CScript() << vGenesisAddr << OP_CHECKSIG;
        txNew.nTxTime = 0x15FFB35B590; // The millisecond when the Kryptohash Genesis block was created (UTC minus 1970/1/1 Epoch).
        genesis.vtx.push_back(txNew);
        genesis.hashPrevBlock = 0;
        genesis.hashMerkleRoot = genesis.BuildMerkleTree();
        //std::cout << genesis.hashMerkleRoot.GetHex() << std::endl;
        assert(genesis.hashMerkleRoot == uint320("0x7E8387C147159A25CEA51574E5D9841577E26CB01807CED2892E451C39BE7726D4C84F17B6C42EEB"));
        genesisMerkleRoot = genesis.hashMerkleRoot;
        genesis.nVersion = 1;
        genesis.nTxTime  = txNew.nTxTime;
        genesis.nBits    = bnProofOfWorkLimit.GetCompact(); //0x250FFFFF;
        genesis.nTime    = 300000; // Hardcoded to 5 minutes after genesis.
        genesis.nNonce   = 0;

        hashGenesisBlock = genesis.GetKryptoHash();
        //std::cout << hashGenesisBlock.GetHex() << std::endl;
        assert(hashGenesisBlock == uint320("0xC7D288CF00294F1837FB82412464CA537AE101EDF1BF40AB7972B9B9BA2EA60DF2EF7FABC10CAA73"));

        vSeeds.push_back(CDNSSeedData("seed0.kryptohash.com", "seed0.kryptohash.com"));
        vSeeds.push_back(CDNSSeedData("seed1.kryptohash.com", "seed1.kryptohash.com"));

        for (unsigned int i = 0; i < MAX_BASE58_TYPES; i++) 
        {
            base58Prefixes[i].clear();
        }

        base58Prefixes[SECRET_KEY].push_back(0);
        base58Prefixes[PUBKEY_ADDRESS].push_back(45);
        base58Prefixes[SCRIPT_ADDRESS].push_back(5);
        base58Prefixes[EXT_PUBLIC_KEY].push_back(4);
        base58Prefixes[EXT_PUBLIC_KEY].push_back(136);
        base58Prefixes[EXT_PUBLIC_KEY].push_back(178);
        base58Prefixes[EXT_PUBLIC_KEY].push_back(30);
        base58Prefixes[EXT_SECRET_KEY].push_back(4);
        base58Prefixes[EXT_SECRET_KEY].push_back(136);
        base58Prefixes[EXT_SECRET_KEY].push_back(173);
        base58Prefixes[EXT_SECRET_KEY].push_back(228);

        // Convert the pnSeeds array into usable address objects.
        for (unsigned int i = 0; i < ARRAYLEN(pnSeed); i++)
        {
            // It'll only connect to one or two seed nodes because once it connects,
            // it'll get a pile of addresses with newer timestamps.
            // Seed nodes are given a random 'last seen time' of between one and two
            // weeks ago.
            const int64_t nOneWeek = 7*24*60*60;
            struct in_addr ip;
            memcpy(&ip, &pnSeed[i], sizeof(ip));
            CAddress addr(CService(ip, GetDefaultPort()));
            addr.nTime = GetTime() - GetRand(nOneWeek) - nOneWeek;
            vFixedSeeds.push_back(addr);
        }
    }

    virtual const CBlock& GenesisBlock() const { return genesis; }
    virtual Network NetworkID() const { return CChainParams::MAIN; }

    virtual const vector<CAddress>& FixedSeeds() const {
        return vFixedSeeds;
    }

    virtual bool UpdateParams(const int nRegionIn, const CGenesis dataIn) const {
        CBlock updateGenesis = GenesisBlock();
        updateGenesis.nRegion = nRegionIn;
        updateGenesis.nTxTime = dataIn.nTxTime;
        updateGenesis.nNonce = dataIn.nNonce;

        uint320 hash = updateGenesis.GetKryptoHash();
        if (hash == dataIn.nHash) {
            SetRegionCode(nRegionIn);
            genesis.nRegion = updateGenesis.nRegion;
            genesis.nTxTime = updateGenesis.nTxTime;
            genesis.nNonce = updateGenesis.nNonce;
            hashGenesisBlock = hash;
            return true;
        }
        return false;
    }

protected:
    mutable CBlock genesis;
    vector<CAddress> vFixedSeeds;
};
static CMainParams mainParams;


//
// Testnet (v3)
//
class CTestNetParams : public CMainParams {
public:
    CTestNetParams() {
        // The message start string is designed to be unlikely to occur in normal data.
        // The characters are rarely used upper ASCII, not valid as UTF-8, and produce
        // a large 4-byte int at any alignment.
        pchMessageStart[0] = 0xf1;
        pchMessageStart[1] = 0x12;
        pchMessageStart[2] = 0x09;
        pchMessageStart[3] = 0x07;
        vAlertPubKey = ParseHex("02666664A1C0FD043653111261115CD51A74D37CB7814E45846718067173C94E24");
        nRegion = 0;
        SetRegionCode(nRegion);

		nSideChainSubsidy = 0;
        nSideChainMask = 0;
        bnProofOfWorkLimit = CBigNum(~uint320(0) >> 24);

        // Modify the testnet genesis block so the timestamp is valid for a later start.
        genesis.nTxTime = 0x15FFB35B600;
        genesis.nBits = bnProofOfWorkLimit.GetCompact();
        genesis.nNonce = 0;
        hashGenesisBlock = genesis.GetKryptoHash();
        //std::cout << hashGenesisBlock.GetHex() << std::endl;
        assert(hashGenesisBlock == uint320("0x74F7728492BAD6799FA080EADBF6502484F26DC9683FF9B504C9F0BEFCDF6EF421121541BF29E307"));

        vFixedSeeds.clear();
        vSeeds.clear();
        vSeeds.push_back(CDNSSeedData("testnet.kryptohash.com", "testnet.kryptohash.com"));

        for (unsigned int i = 0; i < MAX_BASE58_TYPES; i++)
        {
            base58Prefixes[i].clear();
        }

        base58Prefixes[SECRET_KEY].push_back(3);
        base58Prefixes[PUBKEY_ADDRESS].push_back(107);
        base58Prefixes[SCRIPT_ADDRESS].push_back(196);
        base58Prefixes[EXT_PUBLIC_KEY].push_back(4);
        base58Prefixes[EXT_PUBLIC_KEY].push_back(53);
        base58Prefixes[EXT_PUBLIC_KEY].push_back(135);
        base58Prefixes[EXT_PUBLIC_KEY].push_back(207);
        base58Prefixes[EXT_SECRET_KEY].push_back(4);
        base58Prefixes[EXT_SECRET_KEY].push_back(53);
        base58Prefixes[EXT_SECRET_KEY].push_back(131);
        base58Prefixes[EXT_SECRET_KEY].push_back(148);
    }
    virtual Network NetworkID() const { return CChainParams::TESTNET; }
};
static CTestNetParams testNetParams;


//
// Regression test
//
class CRegTestParams : public CTestNetParams {
public:
    CRegTestParams() {
        pchMessageStart[0] = 0xf1;
        pchMessageStart[1] = 0xfc;
        pchMessageStart[2] = 0xb5;
        pchMessageStart[3] = 0xad;

		nSideChainMask = 0;
        bnProofOfWorkLimit = CBigNum(~uint320(0) >> 24);

        // Modify the Regression test genesis block so the timestamp is valid for a later start.
        genesis.nTxTime = 0x15FFB35F000;
        genesis.nBits = bnProofOfWorkLimit.GetCompact();
        genesis.nNonce = 0;
        hashGenesisBlock = genesis.GetKryptoHash();
        nRegion = 0;
        SetRegionCode(nRegion);

        //std::cout << hashGenesisBlock.GetHex() << std::endl;
        assert(hashGenesisBlock == uint320("0x41F2B2F31DA7AF5F588A5A7FBD48F09E765D05FB8F1C64CA1155CBC84C6972E601D8FFDCD14DF706"));
        vSeeds.clear();  // Regtest mode doesn't have any DNS seeds.
    }

    virtual bool RequireRPCPassword() const { return false; }
    virtual Network NetworkID() const { return CChainParams::REGTEST; }
};
static CRegTestParams regTestParams;

static CChainParams *pCurrentParams = &mainParams;

const CChainParams &Params() {
    return *pCurrentParams;
}

void SelectParams(CChainParams::Network network) {
    switch (network) {
        case CChainParams::MAIN:
            pCurrentParams = &mainParams;
            break;
        case CChainParams::TESTNET:
            pCurrentParams = &testNetParams;
            break;
        case CChainParams::REGTEST:
            pCurrentParams = &regTestParams;
            break;
        default:
            assert(false && "Unimplemented network");
            return;
    }
}

bool SelectParamsFromCommandLine() {
    bool fRegTest = GetBoolArg("-regtest", false);
    bool fTestNet = GetBoolArg("-testnet", false);

    if (fTestNet && fRegTest) {
        return false;
    }

    if (fRegTest) {
        SelectParams(CChainParams::REGTEST);
    } else if (fTestNet) {
        SelectParams(CChainParams::TESTNET);
    } else {
        SelectParams(CChainParams::MAIN);
    }
    return true;
}
