// Copyright (c) 2009-2013 The Bitcoin developers
// Copyright (c) 2014 Kryptohash developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CHECKPOINT_H
#define BITCOIN_CHECKPOINT_H

#include <map>
#include <stdint.h>

class CBlockIndex;
class uint320;
class CPID;

/** Block-chain checkpoints are compiled-in sanity checks.
 * They are updated every release or three.
 */
namespace Checkpoints
{
    // Returns true if block passes checkpoint checks
    bool CheckBlock(int64_t nHeight, const uint320& hash);

    // Return conservative estimate of total number of blocks, 0 if unknown
    int64_t GetTotalBlocksEstimate();

    // Returns last CBlockIndex* in mapBlockIndex that is a checkpoint
    CBlockIndex* GetLastCheckpoint(const std::map<uint320, CBlockIndex*>& mapBlockIndex);

    double GuessVerificationProgress(CBlockIndex *pindex, bool fSigchecks = true);

    extern bool fEnabled;
}

/** PID checkpoints are compiled-in sanity checks.
* They are updated every release or three.
*/
namespace PIDCheckpoints
{
    // Return conservative estimate of total number of PID checkpoints, 0 if unknown
    int64_t PIDGetHeightLastCheckpoint();
    // Return the time of the last PID checkpoints, 0 if unknown
    int64_t PIDGetTimeLastCheckpoint();

    // Returns CPID* that is a checkpoint
    const CPID* GetPIDCheckpoint(int64_t height);

    extern bool fEnabled;
}

#endif
