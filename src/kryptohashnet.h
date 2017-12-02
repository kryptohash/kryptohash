// Copyright (c) 2014-2017 Kryptohash Developers 
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef _KRYPTOHASHNET_H_
#define _KRYPTOHASHNET_H_ 1

#define MAX_NUM_OF_ZONES         (256)
#define RPC_PORT_BASE            (38912L)
#define P2P_PORT_BASE            (RPC_PORT_BASE + MAX_NUM_OF_ZONES)

#define RPC_PORT(zone)           (RPC_PORT_BASE + (zone % MAX_NUM_OF_ZONES)) // TCP ports 38912 - 39167
#define P2P_PORT(zone)           (P2P_PORT_BASE + (zone % MAX_NUM_OF_ZONES)) // TCP ports 39168 - 39423

#define MAX_NUM_OF_TEST_ZONES    (8)
#define RPC_PORT_TESTNET_BASE    (39424L)
#define P2P_PORT_TESTNET_BASE    (RPC_PORT_TESTNET_BASE + MAX_NUM_OF_TEST_ZONES)

#define RPC_PORT_TESTNET(zone)   (RPC_PORT_TESTNET_BASE + (zone % MAX_NUM_OF_TEST_ZONES)) // TCP ports 39424 - 39431
#define P2P_PORT_TESTNET(zone)   (P2P_PORT_TESTNET_BASE + (zone % MAX_NUM_OF_TEST_ZONES)) // TCP ports 39432 - 39439

#define P2P_PORT_REGRESSION      (39440L)

#endif
