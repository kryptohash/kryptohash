// Copyright (c) 2014-2018 Kryptohash Developers 
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef _KRYPTOHASHNET_H_
#define _KRYPTOHASHNET_H_ 1

#define MAX_NUM_OF_ZONES         (128)
#define RPC_PORT_BASE            (38912L)
#define P2P_PORT_BASE            (RPC_PORT_BASE + MAX_NUM_OF_ZONES)

#define RPC_PORT(zone)           (RPC_PORT_BASE + (zone % MAX_NUM_OF_ZONES)) // TCP ports 38912 - 39039
#define P2P_PORT(zone)           (P2P_PORT_BASE + (zone % MAX_NUM_OF_ZONES)) // TCP ports 39040 - 39167

#define MAX_NUM_OF_TEST_ZONES    (8)
#define RPC_PORT_TESTNET_BASE    (39168L)
#define P2P_PORT_TESTNET_BASE    (RPC_PORT_TESTNET_BASE + MAX_NUM_OF_TEST_ZONES)

#define RPC_PORT_TESTNET(zone)   (RPC_PORT_TESTNET_BASE + (zone % MAX_NUM_OF_TEST_ZONES)) // TCP ports 39168 - 39175
#define P2P_PORT_TESTNET(zone)   (P2P_PORT_TESTNET_BASE + (zone % MAX_NUM_OF_TEST_ZONES)) // TCP ports 39176 - 39183

#define P2P_PORT_REGRESSION      (39184L)

#endif
