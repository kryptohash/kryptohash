// Copyright (c) 2014 Kryptohash developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "genesis.h"
#include "main.h"
#include "uint256.h"

#include <stdint.h>
#include <map>

namespace Genesis
{

    static MapGenesis mapGenesis {
        { 0, { 0x149ABA00000, 0x0006261B, uint320("0x000000AA3109C4FA8691DDF8F96FCFBBEDBB8B1F3BE7675B875CD1552468A58F4F8997BF6636DB9F") } },
        {-1, { 0, 0, uint320(0) } }
    };

    static MapGenesis mapGenesisTestnet {
        { 0, { 0x149ABA02710, 0x0221FBD1, uint320("0x000000071BFA8530EFDDBF308A70BA52F06402AB2223C95A6FDD21FE64B25128DB9EB171D04F4DB0") } },
        {-1, { 0, 0, uint320(0) } }
    };

    static MapGenesis mapGenesisRegtest {
        { 0, { 0x149ABA04E20, 0x0037AAB9, uint320("0x00000051E60392D4DCEB99C06A62FD23EBE1981D51854DE5614050EAE39ABEBACB770BDDEC466B94") } },
        {-1, { 0, 0, uint320(0) } }
    };

    const MapGenesis &Genesis() {
        if (Params().NetworkID() == CChainParams::TESTNET)
            return mapGenesisTestnet;
        else if (Params().NetworkID() == CChainParams::MAIN)
            return mapGenesis;
        else
            return mapGenesisRegtest;
    }

    bool GetGenesisData(int nRegion, CGenesisData& data)
    {
        const MapGenesis& genesis = Genesis();

        MapGenesis::const_iterator i = genesis.find(nRegion);
        if (i == genesis.end() || i->first == -1)
            return false;

        data = i->second;
        return true;
    }

}
