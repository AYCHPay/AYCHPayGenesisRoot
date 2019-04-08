// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pow.h>

#include <arith_uint256.h>
#include <chain.h>
#include <chainparams.h>
#include <crypto/equihash/equihash.h>
#include <primitives/block.h>
#include <streams.h>
#include <uint256.h>
#include <util.h>
#include <blake2.h>

// LWMA for BTC clones
// Copyright (c) 2017-2018 The Bitcoin Gold developers
// Copyright (c) 2018 Zawy (M.I.T license continued)
// Algorithm by zawy, a modification of WT-144 by Tom Harding
// Code by h4x3rotab of BTC Gold, modified/updated by zawy
// https://github.com/zawy12/difficulty-algorithms/issues/3#issuecomment-388386175
//  FTL must be changed to 300 or N*T/20 whichever is higher.
//  FTL in BTC clones is MAX_FUTURE_BLOCK_TIME in chain.h.
//  FTL in Ignition, Numus, and others can be found in main.h as DRIFT.
//  FTL in Zcash & Dash clones need to change the 2*60*60 here:
//  if (block.GetBlockTime() > nAdjustedTime + 2 * 60 * 60)
//  which is around line 3450 in main.cpp in ZEC and validation.cpp in Dash

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{
    assert(pindexLast != nullptr);
    return LwmaGetNextWorkRequired(pindexLast, pblock, params);
}

unsigned int LwmaGetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{
    // Special difficulty rule for testnet:
    // If the new block's timestamp is more than 2 * 10 minutes
    // then allow mining of a min-difficulty block.
    if (params.fPowAllowMinDifficultyBlocks && pblock->GetBlockTime() > pindexLast->GetBlockTime() + params.nPowTargetSpacing * 2) 
    {
        //LogPrintG(BCLogLevel::LOG_NOTICE, BCLog::POW, "[ProofOfWork] Using minimum diff (%d), because we are in testnet and the last block was a long time ago \n", UintToArith256(params.powLimit).GetCompact());
        return UintToArith256(params.powLimit).GetCompact();
    }
    // Special difficulty rule for if we don't have enough blocks:
    if (pindexLast->nHeight <= params.nZawyLwmaAveragingWindow )
    {
        //LogPrintG(BCLogLevel::LOG_NOTICE, BCLog::POW, "[ProofOfWork] Using minimum diff (%d), because we don't have more than %d blocks yet %d to go... \n", UintToArith256(params.powLimit).GetCompact(), params.nZawyLwmaAveragingWindow, pindexLast->nHeight - params.nZawyLwmaAveragingWindow);
        return UintToArith256(params.powLimit).GetCompact();
    }
    return LwmaCalculateNextWorkRequired(pindexLast, params);
}

unsigned int LwmaCalculateNextWorkRequired(const CBlockIndex* pindexLast, const Consensus::Params& params)
{   
    const int64_t T = params.nPowTargetSpacing;
    // N=45 for T=600.  N=60 for T=150.  N=90 for T=60. 
    const int64_t N = params.nZawyLwmaAveragingWindow; 
    const int64_t k = N*(N+1)*T/2; // BTG's code has a missing N here. They inserted it in the loop
    const int height = pindexLast->nHeight;
    assert(height > N);

    arith_uint256 sum_target;
    int64_t t = 0, j = 0, solvetime;

    // Loop through N most recent blocks. 
    for (int i = height - N+1; i <= height; i++) {
        const CBlockIndex* block = pindexLast->GetAncestor(i);
        const CBlockIndex* block_Prev = block->GetAncestor(i - 1);
        solvetime = block->GetBlockTime() - block_Prev->GetBlockTime();
        solvetime = std::max(-6*T, std::min(solvetime, 6*T));
        j++;
        t += solvetime * j;  // Weighted solvetime sum.
        arith_uint256 target;
        target.SetCompact(block->nBits);
        sum_target += target / (k * N); // BTG added the missing N back here.
    }
    // Keep t reasonable to >= 1/10 of expected t.
    if (t < k/10 ) 
    {
        //LogPrintG(BCLogLevel::LOG_NOTICE, BCLog::POW, "[ProofOfWork] t adjusted from %d to %d, as it was too low \n", t, k/10);
        t = k/10;  
    }
    arith_uint256 next_target = t * sum_target;

    //LogPrintG(BCLogLevel::LOG_NOTICE, BCLog::POW, "[ProofOfWork] LWMA diff: %d \n", next_target.GetCompact());
    return next_target.GetCompact();
}

bool CheckEquihashSolution(const CBlockHeader *pblock, const CChainParams& params, std::string personalizationString)
{
    unsigned int n = params.EquihashN();
    unsigned int k = params.EquihashK();

    // Hash state
    blake2b_state state;
    EhInitialiseState(n, k, state, personalizationString);

    // I = the block header minus nonce and solution.
    CEquihashInput I{*pblock};
    // I||V
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << I;
    ss << pblock->nNonce;

    // H(I||V||...
    blake2b_update(&state, (unsigned char*)&ss[0], ss.size());

    bool isValid;
    EhIsValidSolution(n, k, state, pblock->nSolution, isValid);
    if (!isValid)
        return false;

    return true;
}

bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params& params)
{
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(params.powLimit))
    {
        LogPrintG(BCLogLevel::LOG_WARNING, BCLog::POW, "[ProofOfWork] CheckProofOfWork failed the first check: \n");
        if (fNegative)
        {
            LogPrintG(BCLogLevel::LOG_NOTICE, BCLog::POW, "[ProofOfWork] fNegative is true \n");
        }
        else if (bnTarget == 0)
        {
            LogPrintG(BCLogLevel::LOG_NOTICE, BCLog::POW, "[ProofOfWork] bnTarget is zero \n");
        }
        else if (fOverflow)
        {
            LogPrintG(BCLogLevel::LOG_NOTICE, BCLog::POW, "[ProofOfWork] fOverflow is true \n");
        }
        else if (bnTarget > UintToArith256(params.powLimit))
        {
            LogPrintG(BCLogLevel::LOG_NOTICE, BCLog::POW, "[ProofOfWork] bnTarget (%d) is greater than the minimum difficulty (%d) \n", bnTarget.GetCompact(), UintToArith256(params.powLimit).GetCompact());
        }
        return false;
    }

    // Check proof of work matches claimed amount
    if (UintToArith256(hash) > bnTarget)
    {
        LogPrintG(BCLogLevel::LOG_NOTICE, BCLog::POW, "[ProofOfWork] CheckProofOfWork failed the second check: the hash (%d) is greater than the target (%d) \n", UintToArith256(hash).GetCompact(), bnTarget.GetCompact());
        return false;
    }

    //LogPrintG(BCLogLevel::LOG_NOTICE, BCLog::POW, "[ProofOfWork] CheckProofOfWork success! \n");
    return true;
}
