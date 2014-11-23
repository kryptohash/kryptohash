// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2013 The Bitcoin developers
// Copyright (c) 2014 Kryptohash developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CORE_H
#define BITCOIN_CORE_H

#include "script.h"
#include "serialize.h"
#include "uint256.h"
#include "chainparams.h"

#include <stdint.h>

class CTransaction;

/* No transaction larger than this (in Kryptohash-toshi) is valid, including pre-mined coins */
static const int64_t MAX_MONEY = 10000000000000 * COIN;
inline bool MoneyRange(int64_t nValue) { return (nValue >= 0 && nValue <= MAX_MONEY); }

/** An outpoint - a combination of a transaction hash and an index n into its vout */
class COutPoint
{
public:
    uint320 hash;
    unsigned int n;

    COutPoint() { SetNull(); }
    COutPoint(uint320 hashIn, unsigned int nIn) { hash = hashIn; n = nIn; }
    IMPLEMENT_SERIALIZE( READWRITE(FLATDATA(*this)); )

    void SetNull()
    { 
        hash = 0;
        n = (unsigned int)-1; 
    }

    bool IsNull() const 
    { 
        return (hash == 0 && n == (unsigned int)-1); 
    }

    bool IsGenesis() const
    {
        return (hash == 0 && n == (unsigned int)-2);
    }

    friend bool operator<(const COutPoint& a, const COutPoint& b)
    {
        return (a.hash < b.hash || (a.hash == b.hash && a.n < b.n));
    }

    friend bool operator==(const COutPoint& a, const COutPoint& b)
    {
        return (a.hash == b.hash && a.n == b.n);
    }

    friend bool operator!=(const COutPoint& a, const COutPoint& b)
    {
        return !(a == b);
    }

    std::string ToString() const;
    void print() const;
};

/** An inpoint - a combination of a transaction and an index n into its vin */
class CInPoint
{
public:
    const CTransaction* ptx;
    unsigned int n;

    CInPoint() { SetNull(); }
    CInPoint(const CTransaction* ptxIn, unsigned int nIn) { ptx = ptxIn; n = nIn; }
    void SetNull() { ptx = NULL; n = (unsigned int) -1; }
    bool IsNull() const { return (ptx == NULL && n == (unsigned int) -1); }
};

/*
 * An input of a transaction.  It contains the location of the previous
 * transaction's output that it claims and a signature that matches the
 * output's public key.
 */
class CTxIn
{
public:
    COutPoint prevout;
    CScript scriptSig;
    unsigned int nSequence;

    CTxIn()
    {
        nSequence = std::numeric_limits<unsigned int>::max();
    }

    explicit CTxIn(COutPoint prevoutIn, CScript scriptSigIn=CScript(), unsigned int nSequenceIn=std::numeric_limits<unsigned int>::max());
    CTxIn(uint320 hashPrevTx, unsigned int nOut, CScript scriptSigIn=CScript(), unsigned int nSequenceIn=std::numeric_limits<unsigned int>::max());

    IMPLEMENT_SERIALIZE
    (
        READWRITE(prevout);
        READWRITE(scriptSig);
        READWRITE(nSequence);
    )

    bool IsFinal() const
    {
        return (nSequence == std::numeric_limits<unsigned int>::max());
    }

    friend bool operator==(const CTxIn& a, const CTxIn& b)
    {
        return (a.prevout   == b.prevout &&
                a.scriptSig == b.scriptSig &&
                a.nSequence == b.nSequence);
    }

    friend bool operator!=(const CTxIn& a, const CTxIn& b)
    {
        return !(a == b);
    }

    std::string ToString() const;
    void print() const;
};

/*
 * An output of a transaction.  It contains the public key that the next input
 * must be able to sign with to claim it.
 */
class CTxOut
{
public:
    int64_t nValue;
    CScript scriptPubKey;

    CTxOut()
    {
        SetNull();
    }

    CTxOut(int64_t nValueIn, CScript scriptPubKeyIn);

    IMPLEMENT_SERIALIZE
    (
        READWRITE(nValue);
        READWRITE(scriptPubKey);
    )

    void SetNull()
    {
        nValue = -1;
        scriptPubKey.clear();
    }

    bool IsNull() const
    {
        return (nValue == -1);
    }

    bool IsEmpty() const
    {
        return (nValue == 0 && scriptPubKey.empty());
    }

    uint256 GetHash256() const;

    uint320 GetHash() const;

    bool IsDust(int64_t nMinRelayTxFee) const
    {
        // "Dust" is defined in terms of CTransaction::nMinRelayTxFee,
        // which has units satoshis-per-kilobyte.
        // If you'd pay more than 1/3 in fees
        // to spend something, then we consider it dust.
        // A typical txout is 34 bytes big, and will
        // need a CTxIn of at least 148 bytes to spend,
        // so dust is a txout less than 546 satoshis 
        // with default nMinRelayTxFee.
        return ((nValue*1000)/(3*((int)GetSerializeSize(SER_DISK,0)+148)) < nMinRelayTxFee);
    }

    friend bool operator==(const CTxOut& a, const CTxOut& b)
    {
        return (a.nValue       == b.nValue &&
                a.scriptPubKey == b.scriptPubKey);
    }

    friend bool operator!=(const CTxOut& a, const CTxOut& b)
    {
        return !(a == b);
    }

    std::string ToString() const;
    void print() const;
};

/*
 * The basic transaction that is broadcasted on the network and contained in
 * blocks.  A transaction can contain multiple inputs and outputs.
 */
class CTransaction
{
public:
    static int64_t nMinTxFee;
    static int64_t nMinRelayTxFee;
    static const int CURRENT_VERSION=2;
    int nVersion;
    std::vector<CTxIn> vin;
    std::vector<CTxOut> vout;
    int64_t nTxTime;
    int64_t nLockTime;
    uint64_t nHashCoin;

    // Denial-of-service detection:
    mutable int nDoS;

    CTransaction()
    {
        SetNull();
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(this->nVersion);
        nVersion = this->nVersion;
        READWRITE(vin);
        READWRITE(vout);
        READWRITE(nTxTime);
        READWRITE(nLockTime);
        READWRITE(nHashCoin);
    )

    void SetNull()
    {
        nVersion = CTransaction::CURRENT_VERSION;
        vin.clear();
        vout.clear();
        nTxTime = 0;
        nLockTime = 0;
        nHashCoin = 0;
        nDoS = 0;  // Denial-of-service prevention
    }

    bool IsNull() const
    {
        return (vin.empty() && vout.empty());
    }

    bool DoS(int nDoSIn, bool fIn) const 
    { 
        nDoS += nDoSIn; 
        return fIn; 
    }

    uint256 GetHash256() const;

    uint320 GetHash() const;

    uint320 GetKryptoHash() const;

    bool IsNewerThan(const CTransaction& old) const;

    // Return sum of txouts.
    int64_t GetValueOut() const;
    // GetValueIn() is a method on CCoinsViewCache, because
    // inputs must be known to compute value in.

    // Compute priority, given priority of inputs and (optionally) tx size
    double ComputePriority(double dPriorityInputs, unsigned int nTxSize=0) const;

    bool IsCoinBase() const
    {
        return (vin.size() == 1 && vin[0].prevout.IsNull());
    }

    bool IsCoinShare() const
    {
        return (vin.size() == 1 && vin[0].prevout.IsGenesis());
    }

    bool IsCoinStake() const
    {
        // from peercoin: the coin stake transaction is marked with the first output empty
        return (vin.size() > 0 && (!vin[0].prevout.IsNull()) && vout.size() >= 2 && vout[0].IsEmpty());
    }

    friend bool operator==(const CTransaction& a, const CTransaction& b)
    {
        return (a.nVersion == b.nVersion &&
                a.vin         == b.vin &&
                a.vout        == b.vout &&
                a.nTxTime     == b.nTxTime &&
                a.nLockTime   == b.nLockTime &&
                a.nHashCoin   == b.nHashCoin );
    }

    friend bool operator!=(const CTransaction& a, const CTransaction& b)
    {
        return !(a == b);
    }


    std::string ToString() const;
    void print() const;
};

/** wrapper for CTxOut that provides a more compact serialization */
class CTxOutCompressor
{
private:
    CTxOut &txout;

public:
    static uint64_t CompressAmount(uint64_t nAmount);
    static uint64_t DecompressAmount(uint64_t nAmount);

    CTxOutCompressor(CTxOut &txoutIn) : txout(txoutIn) { }

#ifdef _MSC_VER
    IMPLEMENT_SERIALIZE({
        if (!fRead) {
            uint64_t nVal = CompressAmount(txout.nValue);
            READWRITE(VARINT(nVal));
        } else {
            uint64_t nVal = 0;
            READWRITE(VARINT(nVal));
            txout.nValue = DecompressAmount(nVal);
        }
        CScriptCompressor cscript(REF(txout.scriptPubKey));
        READWRITE(cscript);
    };)
#else
    IMPLEMENT_SERIALIZE(({
        if (!fRead) {
            uint64_t nVal = CompressAmount(txout.nValue);
            READWRITE(VARINT(nVal));
        }
        else {
            uint64_t nVal = 0;
            READWRITE(VARINT(nVal));
            txout.nValue = DecompressAmount(nVal);
        }
        CScriptCompressor cscript(REF(txout.scriptPubKey));
        READWRITE(cscript);
    });)
#endif
};

/*
 * Undo information for a CTxIn
 *
 *  Contains the prevout's CTxOut being spent, and if this was the
 *  last output of the affected transaction, its metadata as well
 *  (coinbase or not, height, transaction version)
 */
class CTxInUndo
{
public:
    CTxOut txout;         // the txout data before being spent
    bool fCoinBase;       // if the outpoint was the last unspent: whether it belonged to a coinbase
    int64_t nHeight;      // if the outpoint was the last unspent: its height
    int nVersion;         // if the outpoint was the last unspent: its version

    CTxInUndo() : txout(), fCoinBase(false), nHeight(0), nVersion(0) {}
    CTxInUndo(const CTxOut &txoutIn, bool fCoinBaseIn = false, int64_t nHeightIn = 0, int nVersionIn = 0) : txout(txoutIn), fCoinBase(fCoinBaseIn), nHeight(nHeightIn), nVersion(nVersionIn) { }

    unsigned int GetSerializeSize(int nType, int nVersion) const 
    {
        return ::GetSerializeSize(VARINT(nHeight*2+(fCoinBase ? 1 : 0)), nType, nVersion) +
               (nHeight > 0 ? ::GetSerializeSize(VARINT(this->nVersion), nType, nVersion) : 0) +
               ::GetSerializeSize(CTxOutCompressor(REF(txout)), nType, nVersion);
    }

    template<typename Stream>
    void Serialize(Stream &s, int nType, int nVersion) const 
    {
        ::Serialize(s, VARINT(nHeight*2+(fCoinBase ? 1 : 0)), nType, nVersion);
        if (nHeight > 0)
            ::Serialize(s, VARINT(this->nVersion), nType, nVersion);
        ::Serialize(s, CTxOutCompressor(REF(txout)), nType, nVersion);
    }

    template<typename Stream>
    void Unserialize(Stream &s, int nType, int nVersion) 
    {
        int64_t nCode = 0;
        ::Unserialize(s, VARINT(nCode), nType, nVersion);
        nHeight = nCode / 2;
        fCoinBase = nCode & 1;
        if (nHeight > 0)
            ::Unserialize(s, VARINT(this->nVersion), nType, nVersion);
        ::Unserialize(s, REF(CTxOutCompressor(REF(txout))), nType, nVersion);
    }
};

/** Undo information for a CTransaction */
class CTxUndo
{
public:
    // undo information for all txins
    std::vector<CTxInUndo> vprevout;

    IMPLEMENT_SERIALIZE
    (
        READWRITE(vprevout);
    )
};


/** Nodes collect new transactions into a block, hash them into a hash tree,
 * and scan through nonce values to make the block's hash satisfy proof-of-work
 * requirements.  When they solve the proof-of-work, they broadcast the block
 * to everyone and the block is added to the block chain.  The first transaction
 * in the block is a special one that creates a new coin owned by the creator
 * of the block.
 */
class CBlockHeader
{
public:
    // header
    static const int CURRENT_VERSION=1;
    int nVersion;
    int nRegion;
    uint320  hashPrevBlock;
    uint320  hashMerkleRoot;
    int64_t  nTxTime;
    uint64_t nHashCoin;
    uint32_t sigchecksum;
    uint32_t nBits;
    uint32_t nTime;
    uint32_t nNonce;

    CBlockHeader()
    {
        SetNull();
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(this->nVersion);
        nVersion = this->nVersion;
        READWRITE(nRegion);
        READWRITE(hashPrevBlock);
        READWRITE(hashMerkleRoot);
        READWRITE(nTxTime);
        READWRITE(nHashCoin);
        READWRITE(sigchecksum);
        READWRITE(nBits);
        READWRITE(nTime);
        READWRITE(nNonce);
    )

    void SetNull()
    {
        nVersion = CBlockHeader::CURRENT_VERSION;
        nRegion = Params().GetRegionCode();
        hashPrevBlock = 0;
        hashMerkleRoot = 0;
        nTxTime = 0;
        nHashCoin = 0;
        sigchecksum = 0;
        nBits = 0;
        nTime = 0;
        nNonce = 0;
    }

    bool IsNull() const
    {
        return (nBits == 0);
    }

    uint256 GetHash256() const;

    uint320 GetHash() const;

    uint320 GetKryptoHash() const;

    int64_t GetBlockTxTime() const
    {
        return nTxTime;
    }

    int64_t GetBlockTime() const
    {
        return nTime;
    }
};


class CBlock : public CBlockHeader
{
public:
    // network and disk
    std::vector<CTransaction> vtx;

    // from ppcoin: block signature - signed by coin base txout[0]'s owner
    std::vector<unsigned char> vchBlockSig;

    // memory only
    mutable std::vector<uint320> vMerkleTree;

    // Denial-of-service detection:
    mutable int nDoS;

    CBlock()
    {
        SetNull();
    }

    CBlock(const CBlockHeader &header)
    {
        SetNull();
        *((CBlockHeader*)this) = header;
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(*(CBlockHeader*)this);
        // ConnectBlock depends on vtx following header to generate CDiskTxPos
        if (!(nType & (SER_GETHASH | SER_BLOCKHEADERONLY)))
        {
            READWRITE(vtx);
            READWRITE(vchBlockSig);
        }
        else if (fRead)
        {
            const_cast<CBlock*>(this)->vtx.clear();
            const_cast<CBlock*>(this)->vchBlockSig.clear();
        }
    )

    void SetNull()
    {
        CBlockHeader::SetNull();
        vtx.clear();
        vchBlockSig.clear();
        vMerkleTree.clear();
    }

    bool DoS(int nDoSIn, bool fIn) const 
    { 
        nDoS += nDoSIn; 
        return fIn; 
    }

    CBlockHeader GetBlockHeader() const
    {
        CBlockHeader block;
        block.nVersion       = nVersion;
        block.nRegion        = nRegion;
        block.hashPrevBlock  = hashPrevBlock;
        block.hashMerkleRoot = hashMerkleRoot;
        block.nTxTime        = nTxTime;
        block.nHashCoin      = nHashCoin;
        block.sigchecksum    = sigchecksum;
        block.nBits          = nBits;
        block.nTime          = nTime;
        block.nNonce         = nNonce;
        return block;
    }

    uint320 BuildMerkleTree() const;

    const uint320 &GetTxHash(unsigned int nIndex) const {
        assert(vMerkleTree.size() > 0); // BuildMerkleTree must have been called first
        assert(nIndex < vtx.size());
        return vMerkleTree[nIndex];
    }

    // from peercoin: two types of block: proof-of-work or proof-of-stake
    bool IsProofOfStake() const
    {
        return (vtx.size() > 1 && vtx[1].IsCoinStake());
    }

    bool IsProofOfWork() const
    {
        return !IsProofOfStake();
    }

    std::pair<COutPoint, int64_t> GetProofOfStake() const
    {
        return IsProofOfStake() ? std::make_pair(vtx[1].vin[0].prevout, vtx[1].nTxTime) : std::make_pair(COutPoint(), (int64_t)0);
    }

    std::vector<uint320> GetMerkleBranch(int nIndex) const;
    static uint320 CheckMerkleBranch(uint320 hash, const std::vector<uint320>& vMerkleBranch, int nIndex);
    void print() const;
    int64_t GetMaxTransactionTime() const;
    bool SignBlock(const CKeyStore& keystore);
    bool CheckBlockSignature() const;
};


/** Describes a place in the block chain to another node such that if the
 * other node doesn't have the same branch, it can find a recent common trunk.
 * The further back it is, the further before the fork it may be.
 */
struct CBlockLocator
{
    std::vector<uint320> vHave;

    CBlockLocator() {}

    CBlockLocator(const std::vector<uint320>& vHaveIn)
    {
        vHave = vHaveIn;
    }

    IMPLEMENT_SERIALIZE
    (
        if (!(nType & SER_GETHASH)) {
            READWRITE(nVersion);
        }
        READWRITE(vHave);
    )

    void SetNull()
    {
        vHave.clear();
    }

    bool IsNull()
    {
        return vHave.empty();
    }
};

#endif
