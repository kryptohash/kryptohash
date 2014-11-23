// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2014 Kryptohash developers
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
    0x92250d45,
};

class CMainParams : public CChainParams {
public:
    CMainParams() {
        // The message start string is designed to be unlikely to occur in normal data.
        // The characters are rarely used upper ASCII, not valid as UTF-8, and produce
        // a large 4-byte int at any alignment.
        pchMessageStart[0] = 0xf1;
        pchMessageStart[1] = 0xeb;
        pchMessageStart[2] = 0xb4;
        pchMessageStart[3] = 0x9d;
        vGenesisAddr = ParseHex("020DC9A10284FDA30C3749C308390BE2B0E2DF56BE836D136D37679F63B258EC13");
        vAlertPubKey = ParseHex("027C8D760AFB55F6B999AFE2CC8F659D63BB5FBD118750FE369D485B2F4C74D8A2");
        nHashCoinCode = 0; //Default to 0. Not implemented yet.
        nHashCoinMask = 0; //Default to 0. Not implemented yet.
        nRegion = 0; //Default to Region 0
        SetRegionCode(nRegion);

        bnProofOfWorkLimit = CBigNum(~uint320(0) >> 24);
        nMaxSubsidy = 400;
        nRandomSubsidyBegins = 100;
        nRandomSubsidyEnds = 125000;

        // Build the genesis block.
        const char* pszTimestamp = "The Guardian 11/13/2014: Comet 67P becomes landing site for Philae in historic touchdown";
        CTransaction txNew;
        txNew.vin.resize(1);
        txNew.vout.resize(1);
        txNew.vin[0].prevout.n = (unsigned int)-2;
        txNew.vin[0].scriptSig = CScript() << 637599743 << CScriptNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew.vout[0].nValue = 1 * COIN;
        txNew.vout[0].scriptPubKey = CScript() << vGenesisAddr << OP_CHECKSIG;
        txNew.nTxTime = 0x149aba00000; // The millisecond when the Kryptohash Genesis block was created (UTC minus 1970/1/1 Epoch).
        genesis.vtx.push_back(txNew);
        genesis.hashPrevBlock = 0;
        genesis.hashMerkleRoot = genesis.BuildMerkleTree();
        //std::cout << genesis.hashMerkleRoot.GetHex() << std::endl;
        assert(genesis.hashMerkleRoot == uint320("0xD34068077BFD951BF202CA7E31D928B7B27599D65429DA5839E1338F023D85BB45115E8C8F720882"));
        genesisMerkleRoot = genesis.hashMerkleRoot;
        genesis.nVersion = 1;
        genesis.nTxTime  = txNew.nTxTime;
        genesis.nBits    = bnProofOfWorkLimit.GetCompact(); //0x2600FFFF;
        genesis.nTime    = 300000; // Hardcoded to 5 minutes after genesis.
        genesis.nNonce   = 0x6261b;

        hashGenesisBlock = genesis.GetKryptoHash();
        //std::cout << hashGenesisBlock.GetHex() << std::endl;
        assert(hashGenesisBlock == uint320("0x000000AA3109C4FA8691DDF8F96FCFBBEDBB8B1F3BE7675B875CD1552468A58F4F8997BF6636DB9F"));

        vSeeds.push_back(CDNSSeedData("seed0.kryptohash.org", "seed0.kryptohash.org"));
        vSeeds.push_back(CDNSSeedData("seed1.kryptohash.org", "seed1.kryptohash.org"));

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

    virtual bool UpdateParams(const int nRegionIn, const Genesis::CGenesisData dataIn) const {
        CBlock updateGenesis = GenesisBlock();
        updateGenesis.nRegion = nRegionIn;
        updateGenesis.nTxTime = dataIn.nTxTime;
        updateGenesis.nNonce = dataIn.nNonce;

        uint320 hash = updateGenesis.GetKryptoHash();
        if (hash == dataIn.hash) {
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
        pchMessageStart[1] = 0x11;
        pchMessageStart[2] = 0x09;
        pchMessageStart[3] = 0x07;
        vAlertPubKey = ParseHex("02666664A1C0FD043653111261115CD51A74D37CB7814E45846718067173C94E24");
        nRegion = 0;
        SetRegionCode(nRegion);

        nMaxSubsidy = 400;
        nRandomSubsidyBegins = 0;
        nRandomSubsidyEnds = 125000;
        nHashCoinMask = 0;
        bnProofOfWorkLimit = CBigNum(~uint320(0) >> 24);

        // Modify the testnet genesis block so the timestamp is valid for a later start.
        genesis.nTxTime = 0x149ABA02710;
        genesis.nBits = bnProofOfWorkLimit.GetCompact();
        genesis.nNonce = 0x221fbd1;
        hashGenesisBlock = genesis.GetKryptoHash();
        //std::cout << hashGenesisBlock.GetHex() << std::endl;
        assert(hashGenesisBlock == uint320("0x000000071BFA8530EFDDBF308A70BA52F06402AB2223C95A6FDD21FE64B25128DB9EB171D04F4DB0"));

        vFixedSeeds.clear();
        vSeeds.clear();
        vSeeds.push_back(CDNSSeedData("testnet.kryptohash.org", "testnet.kryptohash.org"));

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
        pchMessageStart[1] = 0xfb;
        pchMessageStart[2] = 0xb5;
        pchMessageStart[3] = 0xad;
        nMaxSubsidy = 400;
        nRandomSubsidyBegins = 0;
        nRandomSubsidyEnds = 125000;
        nHashCoinMask = 0;
        bnProofOfWorkLimit = CBigNum(~uint320(0) >> 24);

        // Modify the Regression test genesis block so the timestamp is valid for a later start.
        genesis.nTxTime = 0x149ABA04E20;
        genesis.nBits = bnProofOfWorkLimit.GetCompact();
        genesis.nNonce = 0x37aab9;
        hashGenesisBlock = genesis.GetKryptoHash();
        nRegion = 0;
        SetRegionCode(nRegion);

        //std::cout << hashGenesisBlock.GetHex() << std::endl;
        assert(hashGenesisBlock == uint320("0x00000051E60392D4DCEB99C06A62FD23EBE1981D51854DE5614050EAE39ABEBACB770BDDEC466B94"));
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
