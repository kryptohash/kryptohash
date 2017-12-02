// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2013 The Bitcoin developers
// Copyright (c) 2014 Kryptohash developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef __cplusplus
# error This header can only be compiled as C++.
#endif

#ifndef __INCLUDED_PROTOCOL_H__
#define __INCLUDED_PROTOCOL_H__

#include "chainparams.h"
#include "netbase.h"
#include "serialize.h"
#include "uint256.h"

#include <stdint.h>
#include <string>

/** Message header.
 * (4) message start.
 * (4) header version
 * (4) zone
 * (8) sidechain
 *(12) command.
 * (4) size.
 * (4) checksum.
 */
class CMessageHeader
{
    public:
        static const int CURRENT_VERSION = 1;
        static const uint64_t CURRENT_SIDECHAIN = 0;
        CMessageHeader();
        CMessageHeader(const char* pszCommand, unsigned int nMessageSizeIn);
        CMessageHeader(const char* pszCommand, unsigned int nMessageSizeIn, uint64_t nSideChainMaskIn);

        std::string GetCommand() const;
        bool IsValid() const;
        bool IsValidZone(int nZone);

        IMPLEMENT_SERIALIZE
            (
             READWRITE(FLATDATA(pchMessageStart));
             READWRITE(nVersion);
             READWRITE(nZone);
             READWRITE(nSideChain);
             READWRITE(FLATDATA(pchCommand));
             READWRITE(nMessageSize);
             READWRITE(nChecksum);
            )

    // TODO: make private (improves encapsulation)
    public:
        enum {
            VERSION_SIZE      = sizeof(int),
            ZONE_SIZE         = sizeof(int),
            SIDECHAIN_SIZE    = sizeof(uint64_t),
            COMMAND_SIZE      = 12,
            MESSAGE_SIZE_SIZE = sizeof(int),
            CHECKSUM_SIZE     = sizeof(int),

            MESSAGE_SIZE_OFFSET = MESSAGE_START_SIZE + COMMAND_SIZE + VERSION_SIZE + ZONE_SIZE + SIDECHAIN_SIZE,
            CHECKSUM_OFFSET = MESSAGE_SIZE_OFFSET + MESSAGE_SIZE_SIZE,
            HEADER_SIZE = MESSAGE_START_SIZE + VERSION_SIZE + ZONE_SIZE + SIDECHAIN_SIZE + COMMAND_SIZE + MESSAGE_SIZE_SIZE + CHECKSUM_SIZE
        };
        char pchMessageStart[MESSAGE_START_SIZE];
        int nVersion;
        int nZone;
        uint64_t nSideChain;
        char pchCommand[COMMAND_SIZE];
        unsigned int nMessageSize;
        unsigned int nChecksum;
};

/** nServices flags */
enum
{
    NODE_NETWORK = (1 << 0),
};

/** A CService with information about it as peer */
class CAddress : public CService
{
    public:
        CAddress();
        explicit CAddress(CService ipIn, uint64_t nServicesIn=NODE_NETWORK);

        void Init();

        IMPLEMENT_SERIALIZE
            (
             CAddress* pthis = const_cast<CAddress*>(this);
             CService* pip = (CService*)pthis;
             if (fRead)
                 pthis->Init();
             if (nType & SER_DISK)
                 READWRITE(nVersion);
             if ((nType & SER_DISK) ||
                 (nVersion >= CADDR_TIME_VERSION && !(nType & SER_GETHASH)))
                 READWRITE(nTime);
             READWRITE(nServices);
             READWRITE(*pip);
            )

        void print() const;

    // TODO: make private (improves encapsulation)
    public:
        uint64_t nServices;

        // disk and network only
        int64_t nTime;

        // memory only
        int64_t nLastTry;
};

/** inv message data */
class CInv
{
    public:
        CInv();
        CInv(int typeIn, const uint320& hashIn);
        CInv(const std::string& strType, const uint320& hashIn);

        IMPLEMENT_SERIALIZE
        (
            READWRITE(type);
            READWRITE(hash);
        )

        friend bool operator<(const CInv& a, const CInv& b);

        bool IsKnownType() const;
        const char* GetCommand() const;
        std::string ToString() const;
        void print() const;

    // TODO: make private (improves encapsulation)
    public:
        int type;
        uint320 hash;
};

enum
{
    MSG_TX = 1,
    MSG_BLOCK,
    // Nodes may always request a MSG_FILTERED_BLOCK in a getdata, however,
    // MSG_FILTERED_BLOCK should not appear in any invs except as a part of getdata.
    MSG_FILTERED_BLOCK,
};

#endif // __INCLUDED_PROTOCOL_H__
