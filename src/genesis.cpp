#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <thread>
#include <vector>
#include <mutex>
#include <atomic>
#include "crypto/scrypt.h"
#include "uint256.h"
#include "arith_uint256.h"
#include "primitives/block.h"
#include "primitives/pureheader.h"
#include "consensus/merkle.h"
#include "util.h"
#include "utilstrencodings.h"

std::mutex mtx;
std::atomic<bool> found{false};
CBlock result;

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, 
                               uint32_t nTime, uint32_t nNonce, uint32_t nBits, 
                               int32_t nVersion, const CAmount& genesisReward) {
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) 
        << std::vector<unsigned char>((const unsigned char*)pszTimestamp, 
           (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}


bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params& params)
{
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(params.powLimit)) {
        LogPrintf("CheckProofOfWork(): target invalid (negative=%d, zero=%d, overflow=%d, exceeds limit=%d)\n",
                  fNegative, bnTarget == 0, fOverflow, bnTarget > UintToArith256(params.powLimit));
        return false;
    }

    // Check proof of work matches claimed amount
    arith_uint256 bnHash = UintToArith256(hash);
    if (bnHash > bnTarget) {
        LogPrintf("CheckProofOfWork(): hash does not meet target\n");
        LogPrintf("  hash:   %s\n  target: %s\n", bnHash.ToString(), bnTarget.ToString());
        return false;
    }

    return true;
}

void mine_range(CBlock genesis, uint32_t start, uint32_t end, const arith_uint256& hashTarget, const Consensus::Params& params) {
    uint32_t counter = 0;
    genesis.nNonce = start;
    
    // Pre-calculate parts that don't change during mining
    const uint256 powLimit = params.powLimit;
    
    while (!found && genesis.nNonce < end) {
        // Get PoW hash using scrypt
        uint256 hash = genesis.GetPoWHash();
        
        // Quick comparison before doing full check
        if (UintToArith256(hash) <= hashTarget) {
            std::lock_guard<std::mutex> lock(mtx);
            if (!found) {
                // Verify the proof of work meets difficulty target
                if (CheckProofOfWork(hash, genesis.nBits, params)) {
                    found = true;
                    result = genesis;
                    printf("\nBlock found!\n");
                    printf("Nonce: %u\n", genesis.nNonce);
                    printf("Hash: %s\n", hash.ToString().c_str());
                    return;
                }
            }
        }
        
        // Increment nonce and counter
        ++genesis.nNonce;
        
        // Print status every million attempts
        if (++counter % 1000000 == 0) {
            std::lock_guard<std::mutex> lock(mtx);
            printf("\rNonce: %u (%.2f%%) - Hash: %s", 
                   genesis.nNonce,
                   (float)(genesis.nNonce - start) / (end - start) * 100.0,
                   hash.ToString().c_str());
            fflush(stdout);
        }
    }
}

int main() {
    // Configuration
    uint32_t nTime = time(nullptr);
    uint32_t nBits = 0x1e0ffff0;  // Easier initial mining difficulty
    const char* pszTimestamp = "Much Currency Such Coin - 2024 - 1 Second Blocks";
    
    // Genesis output script (public key)
    const CScript genesisOutputScript = CScript() 
        << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f") 
        << OP_CHECKSIG;

    printf("Creating genesis block...\n");
    printf("Timestamp: %u\n", nTime);
    printf("Target bits: 0x%08x\n", nBits);
    printf("Message: %s\n", pszTimestamp);
    printf("Genesis Output Script: %s\n", HexStr(genesisOutputScript).c_str());
    
    // Create genesis block template with 60x initial reward
    CBlock genesis = CreateGenesisBlock(pszTimestamp, genesisOutputScript, 
                                      nTime, 0, nBits, 1, 5280 * COIN);
    // Initialize consensus parameters
    Consensus::Params params;
    params.powLimit = uint256S("00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    params.nPowTargetTimespan = 240;  // 4 minutes
    params.nPowTargetSpacing = 1;     // 1 second blocks
    params.fPowAllowMinDifficultyBlocks = false;
    params.fPowNoRetargeting = false;
    params.nSubsidyHalvingInterval = 6000000;
    params.nAuxpowChainId = 0x0062; // 98 - Dogecoin's chain ID
    params.fStrictChainId = true;
    params.fSimplifiedRewards = true;
    // Calculate target hash
    arith_uint256 hashTarget;
    hashTarget.SetCompact(0x1e0ffff0); // Changed from 0x1f00ffff to match file_context_0
    printf("Target: %s\n", hashTarget.ToString().c_str());

    // Start mining threads
    std::vector<std::thread> threads;
    const int num_threads = std::thread::hardware_concurrency();
    const uint32_t range_per_thread = UINT32_MAX / num_threads;
    
    printf("Starting mining with %d threads...\n", num_threads);
    time_t start_time = time(nullptr);

    for (int i = 0; i < num_threads; i++) {
        uint32_t start = i * range_per_thread;
        uint32_t end = (i == num_threads - 1) ? UINT32_MAX : (i + 1) * range_per_thread;
        threads.emplace_back(mine_range, genesis, start, end, std::ref(hashTarget), params);
    }

    // Wait for mining to complete
    for (auto& thread : threads) {
        thread.join();
    }

    time_t end_time = time(nullptr);
    double elapsed = difftime(end_time, start_time);

    if (found) {
        printf("\n\nGenesis block found!\n");
        printf("Nonce: %u\n", result.nNonce);
        printf("Time: %u\n", result.nTime);
        printf("Block hash: %s\n", result.GetHash().ToString().c_str());
        printf("PoW hash: %s\n", result.GetPoWHash().ToString().c_str());
        printf("Merkle root: %s\n", result.hashMerkleRoot.ToString().c_str());
        printf("Mining time: %.1f seconds\n", elapsed);
        
        // Verify the proof of work one final time
        if (!CheckProofOfWork(result.GetPoWHash(), result.nBits, params)) {
            printf("\nERROR: Proof of work verification failed!\n");
            return 1;
        }
        
        // Output in format ready for chainparams.cpp
        printf("\nAdd to chainparams.cpp:\n");
        printf("genesis = CreateGenesisBlock(%u, %u, 0x%08x, 1, %d * COIN);\n",
               result.nTime, result.nNonce, result.nBits, 5280);
        printf("consensus.hashGenesisBlock = uint256S(\"%s\");\n", 
               result.GetHash().ToString().c_str());
        
        return 0;
    }

    printf("\nFailed to find genesis block after %.1f seconds\n", elapsed);
    return 1;
}
