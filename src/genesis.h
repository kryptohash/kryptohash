// Copyright (c) 2014 Kryptohash developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef KRYPTOHASH_GENESIS_H
#define KRYPTOHASH_GENESIS_H

#include <map>
#include <stdint.h>
#include "uint256.h"

/*
 * These are compiled-in genesis blocks for each available region.
 */
namespace Genesis
{
    struct CGenesisData {
        int64_t  nTxTime;
        uint32_t nNonce;
        uint320  hash;
    };

    typedef std::map<int, CGenesisData> MapGenesis;

    // Returns true if region contains a genesis block
    bool GetGenesisData(int nRegion, CGenesisData& data);

}

#endif
