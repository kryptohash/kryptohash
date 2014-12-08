// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2014 Kryptohash developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "checkpoints.h"

#include "main.h"
#include "uint256.h"

#include <stdint.h>

#include <boost/assign/list_of.hpp> // for 'map_list_of()'
#include <boost/foreach.hpp>

namespace Checkpoints
{
    typedef std::map<int64_t, uint320> MapCheckpoints;

    // How many times we expect transactions after the last checkpoint to
    // be slower. This number is a compromise, as it can't be accurate for
    // every system. When reindexing from a fast disk with a slow CPU, it
    // can be up to 20, while when downloading from a slow network with a
    // fast multicore CPU, it won't be much higher than 1.
    static const double SIGCHECK_VERIFICATION_FACTOR = 5.0;

    struct CCheckpointData {
        const MapCheckpoints *mapCheckpoints;
        int64_t nTimeLastCheckpoint;
        int64_t nTransactionsLastCheckpoint;
        double fTransactionsPerDay;
    };

    bool fEnabled = true;

    // What makes a good checkpoint block?
    // + Is surrounded by blocks with reasonable timestamps
    //   (no blocks before with a timestamp after, none after with
    //    timestamp before)
    // + Contains no strange transactions
    static MapCheckpoints mapCheckpoints =
        boost::assign::map_list_of
        (99, uint320("00000018CE97B434F8396CB989C61190BB72B8CD2A7352C48C91AEDB2E0F8AFCE8CDB7A59334E95B"))
        (5000, uint320("0000000BC13E7BCFC9CFB664D4EA05D6732F5FB49DED407DA33E45FE351A5BD3A81F003BFC2096AC"))
        (5098, uint320("0000000853574F2FEEEE8EE642C72D8E1A40DBDFAFD01CC1B8F23EE6EBC565B16EDFF9E336B0DA0F"))
        (5600, uint320("000000012A064B7393C4A6C6CCD71B52640804A5DD8ABE76FDE35AD12EF00D7FE3DCE691938535DD"))
        ;
    static const CCheckpointData data = {
        &mapCheckpoints,
        0x14A283B4E58, // * UNIX timestamp of last checkpoint block
        13736,         // * total number of transactions between genesis and last checkpoint
                       //   (the tx=... number in the SetBestChain debug.log lines)
        60000.0        // * estimated number of transactions per day after checkpoint
    };

    static MapCheckpoints mapCheckpointsTestnet =
        boost::assign::map_list_of
        ( 0, uint320(0))
        ;
    static const CCheckpointData dataTestnet = {
        &mapCheckpointsTestnet,
        0x1488DDBA3EE,
        0,
        300.0
    };

    static MapCheckpoints mapCheckpointsRegtest =
        boost::assign::map_list_of
        ( 0, uint320(0))
        ;
    static const CCheckpointData dataRegtest = {
        &mapCheckpointsRegtest,
        0,
        0,
        0
    };

    const CCheckpointData &Checkpoints() {
        if (Params().NetworkID() == CChainParams::TESTNET) {
            return dataTestnet;
        }
        else if (Params().NetworkID() == CChainParams::MAIN) {
            return data;
        }
        else {
            return dataRegtest;
        }
    }

    bool CheckBlock(int64_t nHeight, const uint320& hash)
    {
        if (!fEnabled) {
            return true;
        }
        const MapCheckpoints& checkpoints = *Checkpoints().mapCheckpoints;

        MapCheckpoints::const_iterator i = checkpoints.find(nHeight);
        if (i == checkpoints.end()) {
            return true;
        }
        return hash == i->second;
    }

    // Guess how far we are in the verification process at the given block index
    double GuessVerificationProgress(CBlockIndex *pindex, bool fSigchecks) {
        if (pindex == NULL) {
            return 0.0;
        }
        int64_t nNow = time(NULL);

        double fSigcheckVerificationFactor = fSigchecks ? SIGCHECK_VERIFICATION_FACTOR : 1.0;
        double fWorkBefore = 0.0; // Amount of work done before pindex
        double fWorkAfter = 0.0;  // Amount of work left after pindex (estimated)
        // Work is defined as: 1.0 per transaction before the last checkpoint, and
        // fSigcheckVerificationFactor per transaction after.

        const CCheckpointData &data = Checkpoints();

        if (pindex->nChainTx <= data.nTransactionsLastCheckpoint) {
            double nCheapBefore = pindex->nChainTx;
            double nCheapAfter = data.nTransactionsLastCheckpoint - pindex->nChainTx;
            double nExpensiveAfter = (nNow - data.nTimeLastCheckpoint)/86400.0*data.fTransactionsPerDay;
            fWorkBefore = nCheapBefore;
            fWorkAfter = nCheapAfter + nExpensiveAfter*fSigcheckVerificationFactor;
        } else {
            double nCheapBefore = data.nTransactionsLastCheckpoint;
            double nExpensiveBefore = pindex->nChainTx - data.nTransactionsLastCheckpoint;
            double nExpensiveAfter = (nNow - pindex->nTime)/86400.0*data.fTransactionsPerDay;
            fWorkBefore = nCheapBefore + nExpensiveBefore*fSigcheckVerificationFactor;
            fWorkAfter = nExpensiveAfter*fSigcheckVerificationFactor;
        }

        return fWorkBefore / (fWorkBefore + fWorkAfter);
    }

    int64_t GetTotalBlocksEstimate()
    {
        if (!fEnabled) {
            return 0;
        }
        const MapCheckpoints& checkpoints = *Checkpoints().mapCheckpoints;

        return checkpoints.rbegin()->first;
    }

    CBlockIndex* GetLastCheckpoint(const std::map<uint320, CBlockIndex*>& mapBlockIndex)
    {
        if (!fEnabled) {
            return NULL;
        }
        const MapCheckpoints& checkpoints = *Checkpoints().mapCheckpoints;

        BOOST_REVERSE_FOREACH(const MapCheckpoints::value_type& i, checkpoints)
        {
            const uint320& hash = i.second;
            std::map<uint320, CBlockIndex*>::const_iterator t = mapBlockIndex.find(hash);
            if (t != mapBlockIndex.end()) {
                return t->second;
            }
        }
        return NULL;
    }
}

namespace PIDCheckpoints
{
    typedef std::map<int64_t, CPID> MapPIDCheckpoints;

    struct CPIDCheckpointData {
        const MapPIDCheckpoints *mapPIDCheckpoints;
        int64_t nTimeLastCheckpoint;
    };

    bool fEnabled = true;

    static MapPIDCheckpoints mapPIDCheckpoints =
        boost::assign::map_list_of
        (0, CPID(180.0f, 1.0f, 0.05f, 0.1f))
        (5600, CPID(180.0f, 1.0f, 0.05f, 0.1f, 0.0f, 0.0f, 0.0f, 0, 5599, 180.0f, 0x2507ffff))
        ;
    static const CPIDCheckpointData data = {
        &mapPIDCheckpoints,
        0x148d455b42a // * timestamp of last PID checkpoint
    };

    static MapPIDCheckpoints mapPIDCheckpointsTestnet =
        boost::assign::map_list_of
        (0, CPID(180.0f, 1.0f, 0.05f, 0.1f))
        ;
    static const CPIDCheckpointData dataTestnet = {
        &mapPIDCheckpointsTestnet,
        0x148d455b42a
    };

    static MapPIDCheckpoints mapPIDCheckpointsRegtest =
        boost::assign::map_list_of
        (0, CPID(180.0f, 1.0f, 0.05f, 0.1f))
        ;
    static const CPIDCheckpointData dataRegtest = {
        &mapPIDCheckpointsRegtest,
        0
    };

    const CPIDCheckpointData &PIDCheckpoints() {
        if (Params().NetworkID() == CChainParams::TESTNET) {
            return dataTestnet;
        }
        else if (Params().NetworkID() == CChainParams::MAIN) {
            return data;
        }
        else {
            return dataRegtest;
        }
    }

    int64_t PIDGetHeightLastCheckpoint()
    {
        if (!fEnabled) {
            return 0;
        }
        const MapPIDCheckpoints& PIDcheckpoints = *PIDCheckpoints().mapPIDCheckpoints;

        return PIDcheckpoints.rbegin()->first;
    }

    int64_t PIDGetTimeLastCheckpoint()
    {
        if (!fEnabled) {
            return 0;
        }
        const int64_t PIDcheckpointTime = PIDCheckpoints().nTimeLastCheckpoint;

        return PIDcheckpointTime;
    }

    const CPID* GetPIDCheckpoint(int64_t height)
    {
        if (!fEnabled) {
            return NULL;
        }
        const MapPIDCheckpoints& PIDcheckpoints = *PIDCheckpoints().mapPIDCheckpoints;

        BOOST_REVERSE_FOREACH(const MapPIDCheckpoints::value_type& i, PIDcheckpoints)
        {
            if (i.first <= height) {
                const CPID& PIDChkpoint = i.second;
                return &PIDChkpoint;
            }
        }
        return NULL;
    }

}
