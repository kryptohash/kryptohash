// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2013 The Bitcoin developers
// Copyright (c) 2014 Kryptohash developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_KEY_H
#define BITCOIN_KEY_H

#include "allocators.h"
#include "hash.h"
#include "serialize.h"
#include "uint256.h"

#include <stdexcept>
#include <vector>

#define USE_ED25519
#ifdef USE_ED25519

const unsigned int Ed25519_Seed_Size = 32;
const unsigned int Ed25519_Priv_Key_Size = 64;
const unsigned int Ed25519_Pub_Key_Size = 32;
const unsigned int Ed25519_Signature_Size = 64;
const unsigned char ed25519_pubkey_header = 0x02;

#endif

// secp256k1:
// const unsigned int PRIVATE_KEY_SIZE = 279;
// const unsigned int PUBLIC_KEY_SIZE  = 65;
// const unsigned int SIGNATURE_SIZE   = 72;
//
// see www.keylength.com
// script supports up to 75 for single byte push

/** A reference to a CKey: the Hash160 of its serialized public key */
class CKeyID : public uint160
{
public:
    CKeyID() : uint160(0) { }
    CKeyID(const uint160 &in) : uint160(in) { }
};

/** A reference to a CScript: the Hash160 of its serialization (see script.h) */
class CScriptID : public uint160
{
public:
    CScriptID() : uint160(0) { }
    CScriptID(const uint160 &in) : uint160(in) { }
};

/** An encapsulated public key. */
class CPubKey {
private:
#ifdef USE_ED25519
    unsigned char vch[Ed25519_Pub_Key_Size+1]; // First byte is a hardcoded to 0x02 

    unsigned int static GetLen(unsigned char chHeader) {
        if (chHeader == 2 || chHeader == 3)
            return Ed25519_Pub_Key_Size+1;
        return 0;
    }
#else
    // Just store the serialized data.
    // Its length can very cheaply be computed from the first byte.
    unsigned char vch[65];

    // Compute the length of a pubkey with a given first byte.
    unsigned int static GetLen(unsigned char chHeader) {
        if (chHeader == 2 || chHeader == 3)
            return 33;
        if (chHeader == 4 || chHeader == 6 || chHeader == 7)
            return 65;
        return 0;
    }
#endif
    // Set this key data to be invalid
    void Invalidate() {
        vch[0] = 0xFF;
    }

public:
    // Construct an invalid public key.
    CPubKey() {
        Invalidate();
    }

    // Initialize a public key using begin/end iterators to byte data.
    template<typename T>
    void Set(const T pbegin, const T pend) {
        int len = pend == pbegin ? 0 : GetLen(pbegin[0]);
        if (len && len == (pend-pbegin))
            memcpy(vch, (unsigned char*)&pbegin[0], len);
        else
            Invalidate();
    }

    // Construct a public key using begin/end iterators to byte data.
    template<typename T>
    CPubKey(const T pbegin, const T pend) {
        Set(pbegin, pend);
    }

    // Construct a public key from a byte vector.
    CPubKey(const std::vector<unsigned char> &vch) {
        Set(vch.begin(), vch.end());
    }

    // Simple read-only vector-like interface to the pubkey data.
    unsigned int size() const { return GetLen(vch[0]); }
    const unsigned char *begin() const { return vch; }
    const unsigned char *end() const { return vch+size(); }
    const unsigned char &operator[](unsigned int pos) const { return vch[pos]; }

    // Comparator implementation.
    friend bool operator==(const CPubKey &a, const CPubKey &b) {
        return a.vch[0] == b.vch[0] &&
               memcmp(a.vch, b.vch, a.size()) == 0;
    }

    friend bool operator!=(const CPubKey &a, const CPubKey &b) {
        return !(a == b);
    }

    friend bool operator<(const CPubKey &a, const CPubKey &b) {
        return a.vch[0] < b.vch[0] ||
               (a.vch[0] == b.vch[0] && memcmp(a.vch, b.vch, a.size()) < 0);
    }

    // Implement serialization, as if this was a byte vector.
    unsigned int GetSerializeSize(int nType, int nVersion) const {
        return size() + 1;
    }

    template<typename Stream> void Serialize(Stream &s, int nType, int nVersion) const {
        unsigned int len = size();
        ::WriteCompactSize(s, len);
        s.write((char*)vch, len);
    }

    template<typename Stream> void Unserialize(Stream &s, int nType, int nVersion) {
        unsigned int len = ::ReadCompactSize(s);
#ifdef USE_ED25519
        if (len == Ed25519_Pub_Key_Size + 1)
#else
        if (len <= 65)
#endif
        {
            s.read((char*)vch, len);
        } else {
            // invalid pubkey, skip available data
            char dummy;
            while (len--)
                s.read(&dummy, 1);
            Invalidate();
        }
    }

    // Get the KeyID of this public key (hash of its serialization)
    CKeyID GetID() const {
        return CKeyID(Shake160(vch, vch + size()));
    }

    // Get the 256-bit hash of this public key.
    uint256 GetHash() const {
        return Hash256(vch, vch+size());
    }

    // Check syntactic correctness.
    //
    // Note that this is consensus critical as CheckSig() calls it!
    bool IsValid() const {
        return size() > 0;
    }

    // fully validate whether this is a valid public key (more expensive than IsValid())
    bool IsFullyValid() const;

    // If this public key is not fully valid, the return value will be false.
    bool Verify(const uint256 &hash, const std::vector<unsigned char>& vchSig) const;

#ifndef USE_ED25519
    // Check whether this is a compressed public key.
    bool IsCompressed() const {
        return size() == 33;
    }

    // Verify a compact signature (~65 bytes).
    // See CKey::SignCompact.
    bool VerifyCompact(const uint256 &hash, const std::vector<unsigned char>& vchSig) const;

    // Recover a public key from a compact signature.
    bool RecoverCompact(const uint256 &hash, const std::vector<unsigned char>& vchSig);

    // Derive BIP32 child pubkey.
    bool Derive(CPubKey& pubkeyChild, unsigned char ccChild[32], unsigned int nChild, const unsigned char cc[32]) const;

    // Turn this public key into an uncompressed public key.
    bool Decompress();

#endif
};


// secure_allocator is defined in allocators.h
// CPrivKey is a serialized private key, with all parameters included (279 bytes)
typedef std::vector<unsigned char, secure_allocator<unsigned char> > CPrivKey;

/** An encapsulated private key. */
class CKey {
private:
    // Whether this private key is valid. We check for correctness when modifying the key
    // data, so fValid should always correspond to the actual state.
    bool fValid;

#ifdef USE_ED25519
    // The actual byte data
    unsigned char EdSeed[Ed25519_Seed_Size];
#else
    // Whether the public key corresponding to this private key is (to be) compressed.
    bool fCompressed;

    // The actual byte data
    unsigned char vch[32];
#endif

    // Check whether the 32-byte array pointed to be vch is valid keydata.
    bool static Check(const unsigned char *vch);
public:

    // Construct an invalid private key.
    CKey() : fValid(false) {
#ifdef USE_ED25519
        LockObject(EdSeed);
#else
        LockObject(vch);
#endif
    }

#ifdef USE_ED25519
    // Copy constructor. This is necessary because of memlocking.
    CKey(const CKey &secret) : fValid(secret.fValid) {
        LockObject(EdSeed);
        memcpy(EdSeed, secret.EdSeed, sizeof(EdSeed));
    }

    // Destructor (again necessary because of memlocking).
    ~CKey() {
        UnlockObject(EdSeed);
    }

    friend bool operator==(const CKey &a, const CKey &b) {
        return a.size() == b.size() &&
            memcmp(&a.EdSeed[0], &b.EdSeed[0], a.size()) == 0;
    }

    // Initialize using begin and end iterators to byte data.
    template<typename T>
    void Set(const T pbegin, const T pend) {
        if ((pend - pbegin) != Ed25519_Seed_Size) {
            fValid = false;
            return;
        }
        if (Check(&pbegin[0])) {
            memcpy(EdSeed, (unsigned char*)&pbegin[0], Ed25519_Seed_Size);
            fValid = true;
        } else {
            fValid = false;
        }
    }

#else
    // Copy constructor. This is necessary because of memlocking.
    CKey(const CKey &secret) : fValid(secret.fValid), fCompressed(secret.fCompressed) {
        LockObject(vch);
        memcpy(vch, secret.vch, sizeof(vch));
    }

    // Destructor (again necessary because of memlocking).
    ~CKey() {
        UnlockObject(vch);
    }

    friend bool operator==(const CKey &a, const CKey &b) {
        return a.fCompressed == b.fCompressed && a.size() == b.size() &&
               memcmp(&a.vch[0], &b.vch[0], a.size()) == 0;
    }

    // Initialize using begin and end iterators to byte data.
    template<typename T>
    void Set(const T pbegin, const T pend, bool fCompressedIn) {
        if (pend - pbegin != 32) {
            fValid = false;
            return;
        }
        if (Check(&pbegin[0])) {
            memcpy(vch, (unsigned char*)&pbegin[0], 32);
            fValid = true;
            fCompressed = fCompressedIn;
        } else {
            fValid = false;
        }
    }

#endif
    // Simple read-only vector-like interface.
    unsigned int size() const { return (fValid ? 32 : 0); }

    // Check whether this private key is valid.
    bool IsValid() const { return fValid; }

    // Initialize from a CPrivKey (serialized OpenSSL private key data).
#ifdef USE_ED25519
    bool SetPrivKey(const CPrivKey &vchPrivKey);
    const unsigned char *begin() const { return EdSeed; }
    const unsigned char *end() const { return EdSeed + size(); }
    CPrivKey GetEdSeed() const;
    void MakeNewKey();

#else
    bool SetPrivKey(const CPrivKey &vchPrivKey, bool fCompressed);

    // Check whether the public key corresponding to this private key is (to be) compressed.
    bool IsCompressed() const { return fCompressed; }
    const unsigned char *begin() const { return vch; }
    const unsigned char *end() const { return vch + size(); }
    // Generate a new private key using a cryptographic PRNG.
    void MakeNewKey(bool fCompressed);
#endif

    // Convert the private key to a CPrivKey (serialized OpenSSL private key data).
    // This is expensive.
    CPrivKey GetPrivKey() const;

    // Compute the public key from a private key.
    // This is expensive.
    CPubKey GetPubKey() const;

#ifdef USE_ED25519
    // Kryptohash uses ed25519 signatures encoded with one of the following two serial structures: 
    //
    // ** First Structure.  104 bytes long **
    //
    // ** Signature prefix (4 Bytes) **
    //  Offset  Name         Data Type       Description
    //    0  Magic/nZeroByte   uchar      The 5 most significant bits must be equal to '10100' for ed25519 signatures.
    //                                    The 3 least significant bits indicate if the signature includes a checksum or the number of leading zero bytes of a proof of work. 
    //                                    '000' Signature suffix is a Checksum of first n-bytes of SHA3-256(SHA3-256(prefix+signature+privkey)).
    //                                    '001' Signature suffix is a Nonce that produces a hash with 1 leading zero byte when calculating SHA3-256(SHA3-256(payload)).
    //                                    '010' Signature suffix is a Nonce that produces a hash with 2 leading zero bytes when calculating SHA3-256(SHA3-256(payload)).
    //                                      ..
    //                                      ..
    //                                    '111' Signature suffix is a Nonce that produces a hash with 7 leading zero bytes when calculating SHA3-256(SHA3-256(payload)).
    //              
    //    1  SignatureLen      uchar      Length of the signature field (Fixed to 64 bytes for ed25519)
    //
    //    2  PubkeyLen         uchar      Length of the Public Key field (Fixed to 32 bytes for ed25519)
    //
    //    3  Checksum/Nonce    uchar      Length of the Checksum or Nonce field (Fixed to 4 bytes for ed25119)
    //
    //
    // ** Signature (64 bytes for ed25519) **
    //   Offset          Name             Data Type
    //  4 to 67        signature          uchar[64] 
    //
    // ** PublicKey (32 bytes for ed25519) **
    //   Offset          Name             Data Type
    //  68 to 99      public key          uchar[32]
    //
    // ** Signature Suffix (4 bytes for ed25519) **
    //   Offset          Name             Data Type
    //  100 to 103   Checksum/Nonce       uint32_t
    //
    //
    // ** Second Structure.  108 bytes long **
    //
    // ** Signature prefix (4 Bytes) **
    //  Offset  Name         Data Type        Description
    //    0  Magic             uchar      Value must be equal to '10101000' (or 0xA8) for ed25519 signatures with Proof of Work.
    //              
    //    1  SignatureLen      uchar      Length of the signature field (Fixed to 64 bytes for ed25519)
    //
    //    2  PubkeyLen         uchar      Length of the Public Key field (Fixed to 32 bytes for ed25519)
    //
    //    3  Difficulty/Nonce  uchar      Length of the Difficulty and Nonce fields (Fixed to 8 bytes for ed25119)
    //
    //
    // ** Signature (64 bytes for ed25519) **
    //   Offset          Name             Data Type
    //  4 to 67        signature          uchar[64] 
    //
    // ** PublicKey (32 bytes for ed25519) **
    //   Offset          Name             Data Type
    //  68 to 99      public key          uchar[32]
    //
    // ** Signature Suffix (8 bytes for ed25519) **
    //   Offset          Name             Data Type
    //  100 to 103    Difficulty          uint32_t
    //  104 to 107       Nonce            uint32_t
    //

    // Create a serialized signature with checksum. (104 bytes)
    bool Sign(const uint256 &hash, std::vector<unsigned char>& vchSig) const;

    // Create a serialized signature with proof of work using the first serial structure (104 bytes).
    bool Sign(const uint256 &hash, std::vector<unsigned char>& vchSig, const int nZeroBytes) const;

    // Create a serialized signature with proof of work using the second serial structure (108 bytes).
    bool Sign(const uint256 &hash, std::vector<unsigned char>& vchSig, const unsigned int nDiff) const;
#else
    // Create a DER-serialized signature.
    bool Sign(const uint256 &hash, std::vector<unsigned char>& vchSig) const;
#endif

    // Create a compact signature (65 bytes), which allows reconstructing the used public key.
    // The format is one header byte, followed by two times 32 bytes for the serialized r and s values.
    // The header byte: 0x1B = first key with even y, 0x1C = first key with odd y,
    //                  0x1D = second key with even y, 0x1E = second key with odd y,
    //                  add 0x04 for compressed keys.
    bool SignCompact(const uint256 &hash, std::vector<unsigned char>& vchSig) const;

    // Derive BIP32 child key.
    bool Derive(CKey& keyChild, unsigned char ccChild[32], unsigned int nChild, const unsigned char cc[32]) const;

    // Load private key and check that public key matches.
    bool Load(CPrivKey &privkey, CPubKey &vchPubKey, bool fSkipCheck);
};

struct CExtPubKey {
    unsigned char nDepth;
    unsigned char vchFingerprint[4];
    unsigned int nChild;
    unsigned char vchChainCode[32];
    CPubKey pubkey;

    friend bool operator==(const CExtPubKey &a, const CExtPubKey &b) {
        return a.nDepth == b.nDepth && memcmp(&a.vchFingerprint[0], &b.vchFingerprint[0], 4) == 0 && a.nChild == b.nChild &&
               memcmp(&a.vchChainCode[0], &b.vchChainCode[0], 32) == 0 && a.pubkey == b.pubkey;
    }

    void Encode(unsigned char code[74]) const;
    void Decode(const unsigned char code[74]);
    bool Derive(CExtPubKey &out, unsigned int nChild) const;
};

struct CExtKey {
    unsigned char nDepth;
    unsigned char vchFingerprint[4];
    unsigned int nChild;
    unsigned char vchChainCode[32];
    CKey key;

    friend bool operator==(const CExtKey &a, const CExtKey &b) {
        return a.nDepth == b.nDepth && memcmp(&a.vchFingerprint[0], &b.vchFingerprint[0], 4) == 0 && a.nChild == b.nChild &&
               memcmp(&a.vchChainCode[0], &b.vchChainCode[0], 32) == 0 && a.key == b.key;
    }

    void Encode(unsigned char code[74]) const;
    void Decode(const unsigned char code[74]);
    bool Derive(CExtKey &out, unsigned int nChild) const;
    CExtPubKey Neuter() const;
    void SetMaster(const unsigned char *seed, unsigned int nSeedLen);
};

/** Check that required EC support is available at runtime */
bool ECC_InitSanityCheck(void);

#endif
