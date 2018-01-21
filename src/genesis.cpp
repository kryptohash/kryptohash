// Copyright (c) 2014 Kryptohash developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "genesis.h"
#include "main.h"
#include "uint256.h"

#include <stdint.h>
#include <map>

#include <boost/assign/list_of.hpp> // for 'map_list_of()'

namespace Genesis
{
    typedef std::map<int, CGenesis> MapGenesis;

    static MapGenesis mapGenesis =
        boost::assign::map_list_of
        (0, CGenesis(0x15FFB35B590, 0, uint320("0xC7D288CF00294F1837FB82412464CA537AE101EDF1BF40AB7972B9B9BA2EA60DF2EF7FABC10CAA73")))
        ;
    static MapGenesis mapGenesisTestnet =
        boost::assign::map_list_of
        (0, CGenesis(0x15FFB35B600, 0, uint320("0x74F7728492BAD6799FA080EADBF6502484F26DC9683FF9B504C9F0BEFCDF6EF421121541BF29E307")))
        ;
    static MapGenesis mapGenesisRegtest =
        boost::assign::map_list_of
        (0, CGenesis(0x15FFB35F000, 0, uint320("0x41F2B2F31DA7AF5F588A5A7FBD48F09E765D05FB8F1C64CA1155CBC84C6972E601D8FFDCD14DF706")))
        ;

    const MapGenesis &Genesis() {
        if (Params().NetworkID() == CChainParams::TESTNET)
            return mapGenesisTestnet;
        else if (Params().NetworkID() == CChainParams::MAIN)
            return mapGenesis;
        else
            return mapGenesisRegtest;
    }

    bool GetGenesisData(uint8_t nZone, CGenesis& data)
    {
        const MapGenesis& genesis = Genesis();

        MapGenesis::const_iterator i = genesis.find(nZone);
        if (i == genesis.end() || i->first == -1)
            return false;

        data = i->second;
        return true;
    }

}
