// Copyright (c) 2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_MERKLE
#define BITCOIN_MERKLE

#include <stdint.h>
#include <vector>

#include "core.h"
#include "uint256.h"

uint320 ComputeMerkleRoot(const std::vector<uint320>& leaves, bool* mutated = nullptr);
std::vector<uint320> ComputeMerkleBranch(const std::vector<uint320>& leaves, uint32_t position);
uint320 ComputeMerkleRootFromBranch(const uint320& leaf, const std::vector<uint320>& branch, uint32_t position);

/*
 * Compute the Merkle root of the transactions in a block.
 * *mutated is set to true if a duplicated subtree was found.
 */
uint320 BlockMerkleRoot(const CBlock& block, bool* mutated = nullptr);

/*
 * Compute the Merkle root of the witness transactions in a block.
 * *mutated is set to true if a duplicated subtree was found.
 */
uint320 BlockWitnessMerkleRoot(const CBlock& block, bool* mutated = nullptr);

/*
 * Compute the Merkle branch for the tree of transactions in a block, for a
 * given position.
 * This can be verified using ComputeMerkleRootFromBranch.
 */
std::vector<uint320> BlockMerkleBranch(const CBlock& block, uint32_t position);

#endif
