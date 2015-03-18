// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2014 Kryptohash developers 
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "miner.h"

#include "core.h"
#include "main.h"
#include "net.h"
#ifdef ENABLE_WALLET
#include "wallet.h"
#endif

//////////////////////////////////////////////////////////////////////////////
//
// KryptohashMiner
//

int static FormatHashBlocks(void* pbuffer, unsigned int len)
{
    unsigned char* pdata = (unsigned char*)pbuffer;
    unsigned int blocks = 1 + ((len + 8) / 64);
    unsigned char* pend = pdata + 64 * blocks;
    memset(pdata + len, 0, 64 * blocks - len);
    pdata[len] = 0x80;
    unsigned int bits = len * 8;
    pend[-1] = (bits >> 0) & 0xff;
    pend[-2] = (bits >> 8) & 0xff;
    pend[-3] = (bits >> 16) & 0xff;
    pend[-4] = (bits >> 24) & 0xff;
    return blocks;
}

// Some explaining would be appreciated
class COrphan
{
public:
    const CTransaction* ptx;
    set<uint320> setDependsOn;
    double dPriority;
    double dFeePerKb;

    COrphan(const CTransaction* ptxIn)
    {
        ptx = ptxIn;
        dPriority = dFeePerKb = 0;
    }

    void print() const
    {
        LogPrintf("COrphan(hash=%s, dPriority=%.1f, dFeePerKb=%.1f)\n",
               ptx->GetHash().ToString(), dPriority, dFeePerKb);
        BOOST_FOREACH(uint320 hash, setDependsOn)
            LogPrintf("   setDependsOn %s\n", hash.ToString());
    }
};


uint64_t nLastBlockTx = 0;
uint64_t nLastBlockSize = 0;

// We want to sort transactions by priority and fee, so:
typedef boost::tuple<double, double, const CTransaction*> TxPriority;
class TxPriorityCompare
{
    bool byFee;
public:
    TxPriorityCompare(bool _byFee) : byFee(_byFee) { }
    bool operator()(const TxPriority& a, const TxPriority& b)
    {
        if (byFee)
        {
            if (a.get<1>() == b.get<1>())
                return a.get<0>() < b.get<0>();
            return a.get<1>() < b.get<1>();
        }
        else
        {
            if (a.get<0>() == b.get<0>())
                return a.get<1>() < b.get<1>();
            return a.get<0>() < b.get<0>();
        }
    }
};

CBlockTemplate* CreateNewBlock(const CScript& scriptPubKeyIn)
{
    // Create new block
    auto_ptr<CBlockTemplate> pblocktemplate(new CBlockTemplate());
    if(!pblocktemplate.get())
        return NULL;
    CBlock *pblock = &pblocktemplate->block; // pointer for convenience

#if 0 // No longer needed after block 50,000 because, CBlockHeader::CURRENT_VERSION is now set to 2
    // Switch to block version 2 at height 50,000 in MainNet
    if ((MainNet() && (chainActive.Tip()->nHeight + 1) >= nHEIGHT_50000) ||
        (TestNet() && (chainActive.Tip()->nHeight + 1) >= 25) ) {
        pblock->nVersion = 2;
    }
#endif

    // Create coinbase tx
    CTransaction txNew;
    txNew.vin.resize(1);
    txNew.vin[0].prevout.SetNull();
    txNew.vout.resize(1);
    txNew.vout[0].scriptPubKey = scriptPubKeyIn;
    txNew.nTxTime = GetTimeMillis();
    txNew.nHashCoin = 0; // Always zero

    // Add our coinbase tx as first transaction
    pblock->vtx.push_back(txNew);
    pblocktemplate->vTxFees.push_back(-1); // updated at end
    pblocktemplate->vTxSigOps.push_back(-1); // updated at end

    // Largest block you're willing to create:
    unsigned int nBlockMaxSize = GetArg("-blockmaxsize", DEFAULT_BLOCK_MAX_SIZE);
    // Limit to betweeen 1K and MAX_BLOCK_SIZE-1K for sanity:
    nBlockMaxSize = std::max((unsigned int)1000, std::min((unsigned int)(MAX_BLOCK_SIZE-1000), nBlockMaxSize));

    // How much of the block should be dedicated to high-priority transactions,
    // included regardless of the fees they pay
    unsigned int nBlockPrioritySize = GetArg("-blockprioritysize", DEFAULT_BLOCK_PRIORITY_SIZE);
    nBlockPrioritySize = std::min(nBlockMaxSize, nBlockPrioritySize);

    // Minimum block size you want to create; block will be filled with free transactions
    // until there are no more or the block reaches this size:
    unsigned int nBlockMinSize = GetArg("-blockminsize", DEFAULT_BLOCK_MIN_SIZE);
    nBlockMinSize = std::min(nBlockMaxSize, nBlockMinSize);

    // Collect memory pool transactions into the block
    int64_t nFees = 0;
    {
        LOCK2(cs_main, mempool.cs);
        CBlockIndex* pindexPrev = chainActive.Tip();
        CCoinsViewCache view(*pcoinsTip, true);

        // Priority order to process transactions
        list<COrphan> vOrphan; // list memory doesn't move
        map<uint320, vector<COrphan*> > mapDependers;
        bool fPrintPriority = GetBoolArg("-printpriority", false);

        // This vector will be sorted into a priority queue:
        vector<TxPriority> vecPriority;
        vecPriority.reserve(mempool.mapTx.size());
        for (map<uint320, CTxMemPoolEntry>::iterator mi = mempool.mapTx.begin(); mi != mempool.mapTx.end(); ++mi)
        {
            const CTransaction& tx = mi->second.GetTx();
            if (tx.IsCoinBase() || !IsFinalTx(tx, pindexPrev->nHeight + 1))
                continue;

            COrphan* porphan = NULL;
            double dPriority = 0;
            int64_t nTotalIn = 0;
            bool fMissingInputs = false;
            BOOST_FOREACH(const CTxIn& txin, tx.vin)
            {
                // Read prev transaction
                if (!view.HaveCoins(txin.prevout.hash))
                {
                    // This should never happen; all transactions in the memory
                    // pool should connect to either transactions in the chain
                    // or other transactions in the memory pool.
                    if (!mempool.mapTx.count(txin.prevout.hash))
                    {
                        LogPrintf("ERROR: mempool transaction missing input\n");
                        if (fDebug) assert("mempool transaction missing input" == 0);
                        fMissingInputs = true;
                        if (porphan)
                            vOrphan.pop_back();
                        break;
                    }

                    // Has to wait for dependencies
                    if (!porphan)
                    {
                        // Use list for automatic deletion
                        vOrphan.push_back(COrphan(&tx));
                        porphan = &vOrphan.back();
                    }
                    mapDependers[txin.prevout.hash].push_back(porphan);
                    porphan->setDependsOn.insert(txin.prevout.hash);
                    nTotalIn += mempool.mapTx[txin.prevout.hash].GetTx().vout[txin.prevout.n].nValue;
                    continue;
                }
                const CCoins &coins = view.GetCoins(txin.prevout.hash);

                int64_t nValueIn = coins.vout[txin.prevout.n].nValue;
                nTotalIn += nValueIn;

                int nConf = pindexPrev->nHeight - coins.nHeight + 1;

                dPriority += (double)nValueIn * nConf;
            }
            if (fMissingInputs) 
                continue;

            // Priority is sum(valuein * age) / modified_txsize
            unsigned int nTxSize = ::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION);
            dPriority = tx.ComputePriority(dPriority, nTxSize);

            // This is a more accurate fee-per-kilobyte than is used by the client code, because the
            // client code rounds up the size to the nearest 1K. That's good, because it gives an
            // incentive to create smaller transactions.
            double dFeePerKb =  double(nTotalIn-tx.GetValueOut()) / (double(nTxSize)/1000.0);

            if (porphan)
            {
                porphan->dPriority = dPriority;
                porphan->dFeePerKb = dFeePerKb;
            }
            else
                vecPriority.push_back(TxPriority(dPriority, dFeePerKb, &mi->second.GetTx()));
        }

        // Collect transactions into block
        uint64_t nBlockSize = 1000;
        uint64_t nBlockTx = 0;
        int64_t currTime = GetAdjustedTime() * 1000; // in Milliseconds
        int64_t minTxTime = currTime;
        int nBlockSigOps = 100;
        bool fSortedByFee = (nBlockPrioritySize <= 0);

        TxPriorityCompare comparer(fSortedByFee);
        std::make_heap(vecPriority.begin(), vecPriority.end(), comparer);

        while (!vecPriority.empty())
        {
            // Take highest priority transaction off the priority queue:
            double dPriority = vecPriority.front().get<0>();
            double dFeePerKb = vecPriority.front().get<1>();
            const CTransaction& tx = *(vecPriority.front().get<2>());

            std::pop_heap(vecPriority.begin(), vecPriority.end(), comparer);
            vecPriority.pop_back();

            // Size limits
            unsigned int nTxSize = ::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION);
            if (nBlockSize + nTxSize >= nBlockMaxSize)
                continue;

            // Legacy limits on sigOps:
            unsigned int nTxSigOps = GetLegacySigOpCount(tx);
            if (nBlockSigOps + nTxSigOps >= MAX_BLOCK_SIGOPS)
                continue;

            // Skip free transactions if we're past the minimum block size:
            if (fSortedByFee && (dFeePerKb < CTransaction::nMinRelayTxFee) && (nBlockSize + nTxSize >= nBlockMinSize))
                continue;

            // Prioritize by fee once past the priority size or we run out of high-priority
            // transactions:
            if (!fSortedByFee &&
                ((nBlockSize + nTxSize >= nBlockPrioritySize) || !AllowFree(dPriority)))
            {
                fSortedByFee = true;
                comparer = TxPriorityCompare(fSortedByFee);
                std::make_heap(vecPriority.begin(), vecPriority.end(), comparer);
            }

            if (!view.HaveInputs(tx))
                continue;

            int64_t nTxFees = view.GetValueIn(tx) - tx.GetValueOut();

            nTxSigOps += GetP2SHSigOpCount(tx, view);
            if (nBlockSigOps + nTxSigOps >= MAX_BLOCK_SIGOPS)
                continue;

            CValidationState state;
            if (!CheckInputs(tx, state, view, true, SCRIPT_VERIFY_P2SH))
                continue;

            CTxUndo txundo;
            uint320 hash = tx.GetHash();
            UpdateCoins(tx, state, view, txundo, pindexPrev->nHeight+1, hash);

            // Find the oldest transaction time. 
            // Cap nTxTime values that are older than 10 mins or, older than the median of the
            // past 11 blocks. This is to prevent Diff manipulation by sending low priority TXs
            // that could take a very long time to get included in a block.
            int64_t nTxTimePastLimit = pindexPrev->GetMedianTimePast();
            if (currTime - nTxTimePastLimit > 600000) {
                nTxTimePastLimit = currTime - 600000;
            }
            if (tx.nTxTime < nTxTimePastLimit) {
                minTxTime = nTxTimePastLimit;
            }
            else {
                minTxTime = min(minTxTime, tx.nTxTime);
            }

            // Added
            pblock->vtx.push_back(tx);
            pblocktemplate->vTxFees.push_back(nTxFees);
            pblocktemplate->vTxSigOps.push_back(nTxSigOps);
            nBlockSize += nTxSize;
            ++nBlockTx;
            nBlockSigOps += nTxSigOps;
            nFees += nTxFees;

            if (fPrintPriority)
            {
                LogPrintf("priority %.1f feeperkb %.1f txid %s\n",
                       dPriority, dFeePerKb, tx.GetHash().ToString());
            }

            // Add transactions that depend on this one to the priority queue
            if (mapDependers.count(hash))
            {
                BOOST_FOREACH(COrphan* porphan, mapDependers[hash])
                {
                    if (!porphan->setDependsOn.empty())
                    {
                        porphan->setDependsOn.erase(hash);
                        if (porphan->setDependsOn.empty())
                        {
                            vecPriority.push_back(TxPriority(porphan->dPriority, porphan->dFeePerKb, porphan->ptx));
                            std::push_heap(vecPriority.begin(), vecPriority.end(), comparer);
                        }
                    }
                }
            }
        }

        nLastBlockTx = nBlockTx;
        nLastBlockSize = nBlockSize;
        LogPrintf("CreateNewBlock(): total size %u\n", nBlockSize);

        pblock->hashPrevBlock = pindexPrev->GetBlockHash();
        pblock->vtx[0].vout[0].nValue = GetBlockValue(pindexPrev->nHeight + 1, nFees, pblock->hashPrevBlock);
        pblocktemplate->vTxFees[0] = -nFees;

        // Fill in header

        // Use the oldest TxTime found in the mempool.
        pblock->nTxTime = minTxTime;
        // nTime is the difference between current time and the oldest nTxTime in the mempool.
        pblock->nTime = currTime - minTxTime;
#if 0
        pblock->nBits = GetNextWorkRequired(pindexPrev, pblock);
#else
        pblock->nBits   = GetNextWorkRequiredPID(pindexPrev, pblock);
#endif
        pblock->nNonce  = 0;
        pblock->vtx[0].vin[0].scriptSig = CScript() << OP_0 << OP_0;
        pblocktemplate->vTxSigOps[0] = GetLegacySigOpCount(pblock->vtx[0]);

        CBlockIndex indexDummy(*pblock);
        indexDummy.pprev = pindexPrev;
        indexDummy.nHeight = pindexPrev->nHeight + 1;
        CCoinsViewCache viewNew(*pcoinsTip, true);
        CValidationState state;
        if (!ConnectBlock(*pblock, state, &indexDummy, viewNew, true))
            throw std::runtime_error("CreateNewBlock() : ConnectBlock failed");
    }

    return pblocktemplate.release();
}

void IncrementExtraNonce(CBlock* pblock, CBlockIndex* pindexPrev, unsigned int& nExtraNonce)
{
    // Update nExtraNonce
    static uint320 hashPrevBlock;
    if (hashPrevBlock != pblock->hashPrevBlock)
    {
        nExtraNonce = 0;
        hashPrevBlock = pblock->hashPrevBlock;
    }
    ++nExtraNonce;
    int64_t nHeight = pindexPrev->nHeight+1; // Height first in coinbase required for block.version=2
    pblock->vtx[0].vin[0].scriptSig = (CScript() << nHeight << CScriptNum(nExtraNonce)) + COINBASE_FLAGS;
    assert(pblock->vtx[0].vin[0].scriptSig.size() <= 100);

    pblock->hashMerkleRoot = pblock->BuildMerkleTree();
}

void FormatKryptoHashBuffers(CBlock* pblock, Keccak_HashInstance *keccakInstance, char* pdata)
{
    //
    // Pre-build hash buffers
    //
#pragma pack(push,4)
    struct
    {
        struct unnamed2
        {
            int nVersion;            //  4 bytes
            int nRegion;             //  4 bytes
            uint320  hashPrevBlock;  // 40 bytes
            uint320  hashMerkleRoot; // 40 bytes
            int64_t  nTxTime;        //  8 bytes
            uint64_t nHashCoin;      //  8 bytes
            uint32_t sigchecksum;    //  4 bytes
            uint32_t nBits;          //  4 bytes
            uint32_t nTime;          //  4 bytes
            uint32_t nNonce;         //  4 bytes
        } block;                     //120 bytes
        unsigned char pchPadding[72];
    } tmp;
#pragma pack(pop)

    memset(&tmp, 0, sizeof(tmp));

    tmp.block.nVersion        = pblock->nVersion;
    tmp.block.nRegion         = pblock->nRegion;
    tmp.block.hashPrevBlock   = pblock->hashPrevBlock;
    tmp.block.hashMerkleRoot  = pblock->hashMerkleRoot;
    tmp.block.nTxTime         = pblock->nTxTime;
    tmp.block.nHashCoin       = pblock->nHashCoin;
    tmp.block.sigchecksum     = pblock->sigchecksum;
    tmp.block.nBits           = pblock->nBits;
    tmp.block.nTime           = pblock->nTime;
    tmp.block.nNonce          = pblock->nNonce;

    FormatHashBlocks(&tmp.block, sizeof(tmp.block));

    if (keccakInstance != NULL) {
        // Precalc the first 112 bytes of the block header, which stays constant
        Keccak_HashUpdate(keccakInstance, (BitSequence *)&tmp.block, 112 * 8);
    }
    memcpy(pdata, &tmp.block, sizeof(tmp.block));
}


#ifdef ENABLE_WALLET

CBlockTemplate* CreateNewBlockWithKey(CReserveKey& reservekey)
{
    CPubKey pubkey;
    if (!reservekey.GetReservedKey(pubkey))
        return NULL;

    CScript scriptPubKey = CScript() << pubkey << OP_CHECKSIG;
    return CreateNewBlock(scriptPubKey);
}

bool CheckWork(CBlock* pblock, CWallet& wallet, CReserveKey& reservekey)
{
    uint320 hash = pblock->GetKryptoHash();
    uint320 hashTarget = CBigNum().SetCompact(pblock->nBits).getuint320();

    if (hash > hashTarget)
        return false;

    //// debug print
    LogPrintf("KryptohashMiner:\n");
    LogPrintf("proof-of-work found  \n  hash: %s  \ntarget: %s\n", hash.GetHex(), hashTarget.GetHex());
    pblock->print();
    LogPrintf("generated %s\n", FormatMoney(pblock->vtx[0].vout[0].nValue));

    // Found a solution
    {
        LOCK(cs_main);
        if (pblock->hashPrevBlock != chainActive.Tip()->GetBlockHash())
            return error("KryptohashMiner : generated block is stale");

        // Remove key from key pool
        reservekey.KeepKey();

        // Track how many getdata requests this block gets
        {
            LOCK(wallet.cs_wallet);
            wallet.mapRequestCount[pblock->GetKryptoHash()] = 0;
        }

        // Process this block the same as if we had received it from another node
        CValidationState state;
        if (!ProcessBlock(state, NULL, pblock))
            return error("KryptohashMiner : ProcessBlock, block not accepted");
    }

    return true;
}

#if 0 
// Internal miner disabled for 2 reasons. 1) CPU mining way too slow; 2) it never actually worked.

//////////////////////////////////////////////////////////////////////////////
//
// Internal miner
//
double dHashesPerSec = 0.0;
int64_t nHPSTimerStart = 0;


//
// ScanHash scans nonces looking for a hash with at least some zero bits.
// It operates on big endian data.  Caller does the byte reversing.
// All input buffers are 16-byte aligned.  nNonce is usually preserved
// between calls, but periodically or if nNonce is 0xffff0000 or above,
// the block is rebuilt and nNonce starts over at zero.
//
unsigned int static ScanKryptoHash(Keccak_HashInstance *keccakHeader, char* pdata, char* phash, unsigned char* phash1, unsigned int& nHashesDone, int version)
{
    uint32_t& nNonce = *(uint32_t*)(pdata + 4);

    // KryptoHash Proof of Work uses SHAKE320 hash function. 
    // It first hashes the 120 bytes long block header into a bitstream that is 'KPROOF_OF_WORK_SZ' bytes long.
    // Then, the entire bitstream is hashed into a 40 bytes long final hash that has to meet the minimum proof
    // of work provided in the block header nBits field.

    for (;;)
    {
        Keccak_HashInstance keccakInstance;

        // Make a copy of the keccak instance that contains the hash of the first 112 bytes of the block header.
        keccakInstance = *keccakHeader;

        // Using hash of the header that was previous calculated, hash pdata that has a new Nonce
        // and store it into phash.
        Keccak_HashUpdate(&keccakInstance, (BitSequence *)pdata, 8 * 8);
        Keccak_HashFinal(&keccakInstance, NULL);
        Keccak_HashSqueeze(&keccakInstance, (BitSequence *)phash1, KPROOF_OF_WORK_SZ * 8);

        if (version <= 1) {
	        // Now hash phash1 into phash using SHAKE320
            SHAKE320(phash1, KPROOF_OF_WORK_SZ * 8, (BitSequence *)phash, 40);
        }
        else {
            // Swap blocks in chunks of KRATE size
            unsigned char *p1 = phash1 + KPROOF_OF_WORK_SZ;
            unsigned char scratchpad2[KPROOF_OF_WORK_SZ + 16];
            unsigned char *p2 = alignup<16>(scratchpad2);

            for (int i = 0; i < KPOW_MUL; i++)
            {
                p1 -= KRATE;
                memcpy(p2, p1, KRATE);
                p2 += KRATE;
            }
            SHAKE320(scratchpad2, KPROOF_OF_WORK_SZ * 8, (BitSequence *)phash, 40);
        }

        // Return the nonce if the hash has at least some zero bits,
        // caller will check if it has enough to reach the target
        if (((unsigned short*)phash)[19] == 0)
            return nNonce;

        // increment nonce. will try again.
        nNonce++;

        // If nothing found after trying for a while, return -1
        if ((nNonce & 0x1fff) == 0)
        {
            nHashesDone = 0x1fff+1;
            return (unsigned int) -1;
        }

        if ((nNonce & 0x3ff) == 0)
            boost::this_thread::interruption_point();

    }
}

void static KryptohashMiner(CWallet *pwallet)
{
    LogPrintf("KryptohashMiner started\n");
    SetThreadPriority(THREAD_PRIORITY_LOWEST);
    RenameThread("Kryptohash-miner");

    // Each thread has its own key and counter
    CReserveKey reservekey(pwallet);
    unsigned int nExtraNonce = 0;

    try { 
        while (true) {
            int64_t nTimer, nStart;

            if (Params().NetworkID() != CChainParams::REGTEST) {
                // Busy-wait for the network to come online so we don't waste time mining
                // on an obsolete chain. In regtest mode we expect to fly solo.
                while (vNodes.empty())
                    MilliSleep(1000);
            }

            //
            // Create new block
            //
            unsigned int nTransactionsUpdatedLast = mempool.GetTransactionsUpdated();
            CBlockIndex* pindexPrev = chainActive.Tip();

            auto_ptr<CBlockTemplate> pblocktemplate(CreateNewBlockWithKey(reservekey));
            if (!pblocktemplate.get())
                return;

            CBlock *pblock = &pblocktemplate->block;
            IncrementExtraNonce(pblock, pindexPrev, nExtraNonce);

            LogPrintf("Running KryptohashMiner with %u transactions in block (%u bytes)\n", pblock->vtx.size(),
                      ::GetSerializeSize(*pblock, SER_NETWORK, PROTOCOL_VERSION));

            //
            // Pre-build hash buffers
            //
            Keccak_HashInstance keccakHeader;
            // Using SHAKE320
            Keccak_HashInitialize(&keccakHeader, SHAKE320_R, SHAKE320_C, 0, SHAKE320_P);

            char  pdatabuf[120+16];
            char* pdata = alignup<16>(pdatabuf);

            FormatKryptoHashBuffers(pblock, &keccakHeader, pdata);

            int32_t& nVersion     = *(int32_t *)(pdata +   0);
            uint32_t& nBlockTime  = *(uint32_t*)(pdata + 112);
            uint32_t& nBlockNonce = *(uint32_t*)(pdata + 116);

            uint320 hashTarget = CBigNum().SetCompact(pblock->nBits).getuint320();
            uint320 hashbuf[2];
            uint320& hash = *alignup<16>(hashbuf);

            unsigned char scratchpad[KPROOF_OF_WORK_SZ + 16];
            unsigned char* hash1 = alignup<16>(scratchpad);

            //
            // Search
            //
            nTimer = nStart = GetTime();

            while (true)
            {
                unsigned int nHashesDone = 0;
                unsigned int nNonceFound;

                // Kryptohash 320bits
                nNonceFound = ScanKryptoHash(&keccakHeader, pdata + 112, (char*)&hash, hash1, nHashesDone, nVersion);

                // Check if something found
                if (nNonceFound != (unsigned int) -1)
                {
                    for (unsigned int i = 0; i < sizeof(hash)/4; i++)
                        ((unsigned int*)&hash)[i] = ByteReverse(((unsigned int*)&hash)[i]);

                    if (hash <= hashTarget)
                    {
                        // Found a solution
                        pblock->nNonce = nNonceFound;
                        assert(hash == pblock->GetKryptoHash());
                        SetThreadPriority(THREAD_PRIORITY_NORMAL);
                        CheckWork(pblock, *pwallet, reservekey);
                        SetThreadPriority(THREAD_PRIORITY_LOWEST);

                        // In regression test mode, stop mining after a block is found. This
                        // allows developers to controllably generate a block on demand.
                        if (Params().NetworkID() == CChainParams::REGTEST)
                            throw boost::thread_interrupted();

                        break;
                    }
                    // Not found. Will try again.
                    nBlockNonce++;
                }

                // Meter hashes/sec
                static int64_t nHashCounter;
                if (nHPSTimerStart == 0)
                {
                    nHPSTimerStart = GetTimeMillis();
                    nHashCounter = 0;
                }
                else
                    nHashCounter += nHashesDone;

                if (GetTimeMillis() - nHPSTimerStart > 4000)
                {
                    static CCriticalSection cs;
                    {
                        LOCK(cs);
                        if (GetTimeMillis() - nHPSTimerStart > 4000)
                        {
                            dHashesPerSec = 1000.0 * nHashCounter / (GetTimeMillis() - nHPSTimerStart);
                            nHPSTimerStart = GetTimeMillis();
                            nHashCounter = 0;
                            static int64_t nLogTime;
                            if (GetTime() - nLogTime > 30 * 60)
                            {
                                nLogTime = GetTime();
                                LogPrintf("hashmeter %6.0f khash/s\n", dHashesPerSec/1000.0);
                            }
                        }
                    }
                }

                // Check for stop or if block needs to be rebuilt
                boost::this_thread::interruption_point();
                if (vNodes.empty() && Params().NetworkID() != CChainParams::REGTEST)
                    break;
                if (nBlockNonce > 0xffff0000)
                    break;
                if (mempool.GetTransactionsUpdated() != nTransactionsUpdatedLast && GetTime() - nStart > 60)
                    break;
                if (pindexPrev != chainActive.Tip())
                    break;

                // Update nTime every 1 minute
                if (GetTime() - nTimer > 60) {
                    UpdateTimeElapsed(*pblock, pindexPrev);
                    nBlockTime = pblock->nTime;
                    nTimer = GetTime();
                }
            }
        } 
    }
    catch (boost::thread_interrupted)
    {
        LogPrintf("KryptohashMiner terminated\n");
        throw;
    }
}

void GenerateCoins(bool fGenerate, CWallet* pwallet, int nThreads)
{
    static boost::thread_group* minerThreads = NULL;

    if (nThreads < 0) {
        if (Params().NetworkID() == CChainParams::REGTEST)
            nThreads = 1;
        else
            nThreads = boost::thread::hardware_concurrency();
    }

    if (minerThreads != NULL)
    {
        minerThreads->interrupt_all();
        delete minerThreads;
        minerThreads = NULL;
    }

    if (nThreads == 0 || !fGenerate)
        return;

    minerThreads = new boost::thread_group();
    for (int i = 0; i < nThreads; i++)
        minerThreads->create_thread(boost::bind(&KryptohashMiner, pwallet));
}

#endif

#endif // ENABLE_WALLET