// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2013 The Bitcoin developers
// Copyright (c) 2014 Kryptohash developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_TXMEMPOOL_H
#define BITCOIN_TXMEMPOOL_H

#include <list>

#include "coins.h"
#include "core.h"
#include "sync.h"

/** Fake height value used in CCoins to signify they are only in the memory pool (since 0.8) */
static const unsigned int MEMPOOL_HEIGHT = 0x7FFFFFFF;

/*
 * CTxMemPool stores these:
 */
class CTxMemPoolEntry
{
private:
    CTransaction tx;
    int64_t nFee; // Cached to avoid expensive parent-transaction lookups
    size_t nTxSize; // ... and avoid recomputing tx size
    int64_t nTime; // Local time when entering the mempool
    double dPriority; // Priority when entering the mempool
    int64_t nHeight; // Chain height when entering the mempool

public:
    CTxMemPoolEntry(const CTransaction& _tx, int64_t _nFee,
                    int64_t _nTime, double _dPriority, int64_t _nHeight);
    CTxMemPoolEntry();
    CTxMemPoolEntry(const CTxMemPoolEntry& other);

    const CTransaction& GetTx() const { return this->tx; }
    double GetPriority(int64_t currentHeight) const;
    int64_t GetFee() const { return nFee; }
    size_t GetTxSize() const { return nTxSize; }
    int64_t GetTime() const { return nTime; }
    int64_t GetHeight() const { return nHeight; }
};

/*
 * CTxMemPool stores valid-according-to-the-current-best-chain
 * transactions that may be included in the next block.
 *
 * Transactions are added when they are seen on the network
 * (or created by the local node), but not all transactions seen
 * are added to the pool: if a new transaction double-spends
 * an input of a transaction in the pool, it is dropped,
 * as are non-standard transactions.
 */
class CTxMemPool
{
private:
    bool fSanityCheck; // Normally false, true if -checkmempool or -regtest
    uint64_t nTransactionsUpdated;

public:
    mutable CCriticalSection cs;
    std::map<uint320, CTxMemPoolEntry> mapTx;
    std::map<COutPoint, CInPoint> mapNextTx;

    CTxMemPool();

    /*
     * If sanity-checking is turned on, check makes sure the pool is
     * consistent (does not contain two transactions that spend the same inputs,
     * all inputs are in the mapNextTx array). If sanity-checking is turned off,
     * check does nothing.
     */
    void check(CCoinsViewCache *pcoins) const;
    void setSanityCheck(bool _fSanityCheck) { fSanityCheck = _fSanityCheck; }

    bool addUnchecked(const uint320& hash, const CTxMemPoolEntry &entry);
    void remove(const CTransaction &tx, std::list<CTransaction>& removed, bool fRecursive = false);
    void removeConflicts(const CTransaction &tx, std::list<CTransaction>& removed);
    void clear();
    void queryHashes(std::vector<uint320>& vtxid);
    void pruneSpent(const uint320& hash, CCoins &coins);
    uint64_t GetTransactionsUpdated() const;
    void AddTransactionsUpdated(unsigned int n);

    unsigned long size()
    {
        LOCK(cs);
        return mapTx.size();
    }

    bool exists(uint320 hash)
    {
        LOCK(cs);
        return (mapTx.count(hash) != 0);
    }

    bool lookup(uint320 hash, CTransaction& result) const;
};

/** CCoinsView that brings transactions from a memorypool into view.
    It does not check for spendings by memory pool transactions. */
class CCoinsViewMemPool : public CCoinsViewBacked
{
protected:
    CTxMemPool &mempool;

public:
    CCoinsViewMemPool(CCoinsView &baseIn, CTxMemPool &mempoolIn);
    bool GetCoins(const uint320 &txid, CCoins &coins);
    bool HaveCoins(const uint320 &txid);
};

#endif /* BITCOIN_TXMEMPOOL_H */
