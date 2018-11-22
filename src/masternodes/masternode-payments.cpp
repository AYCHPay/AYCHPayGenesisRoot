// Copyright (c) 2014-2018 The Dash Core developers
// Copyright (c) 2014-2018 The Machinecoin Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <masternodes/activemasternode.h>
#include <chainparams.h>
#include <checkpoints.h>
#include <consensus/validation.h>
#include <masternodes/governance-classes.h>
#include <masternodes/masternode-payments.h>
#include <masternodes/masternode-sync.h>
#include <masternodes/masternodeman.h>
#include <masternodes/messagesigner.h>
#include <masternodes/netfulfilledman.h>
#include <netmessagemaker.h>
#include <util.h>
#include <script/standard.h>
#include <keystore.h>
#include <wallet/wallet.h>

#include <boost/lexical_cast.hpp>

/** Object for who's going to get paid on which blocks */
CMasternodePayments mnpayments;

CCriticalSection cs_vecPayees;
CCriticalSection cs_mapMasternodeBlocks;
CCriticalSection cs_mapMasternodePaymentVotes;

/**
* IsBlockValueValid
*
*   Determine if coinbase outgoing created money is the correct value
*
*   Why is this needed?
*   - In the context of Genesis Masternodes some blocks are governance blocks, which output much higher amounts of coins
*   - Otherblocks are a % lower in outgoing value, so in total, no extra coins are created
*   - When non-governanceblocks are detected, the normal schedule should be maintained
*/

bool IsBlockValueValid(const CBlock& block, int nBlockHeight, CAmount blockReward, std::string& strErrorRet)
{
    strErrorRet = "";

    bool isBlockRewardValueMet = (block.vtx[0]->GetValueOut() <= blockReward);
    LogPrint(BCLog::MN, "block.vtx[0]->GetValueOut() %lld <= blockReward %lld\n", block.vtx[0]->GetValueOut(), blockReward);

    // governanceblocks started

    CAmount nGovernanceBlockMaxValue = blockReward + CGovernanceBlock::GetPaymentsLimit(nBlockHeight);
    bool isGovernanceBlockMaxValueMet = (block.vtx[0]->GetValueOut() <= nGovernanceBlockMaxValue);

    LogPrint(BCLog::GOV, "block.vtx[0]->GetValueOut() %lld <= nGovernanceBlockMaxValue %lld\n", block.vtx[0]->GetValueOut(), nGovernanceBlockMaxValue);

    if (!masternodeSync.IsSynced() || fLiteMode) {
        // not enough data but at least it must NOT exceed governanceblock max value
        if (CGovernanceBlock::IsValidBlockHeight(nBlockHeight)) {
            LogPrint(BCLog::MN, "IsBlockPayeeValid -- WARNING: Not enough data, checking governanceblock max bounds only\n");
            if (!isGovernanceBlockMaxValueMet) {
                strErrorRet = strprintf("coinbase pays too much at height %d (actual=%d vs limit=%d), exceeded governanceblock max value",
                    nBlockHeight, block.vtx[0]->GetValueOut(), nGovernanceBlockMaxValue);
            }
            return isGovernanceBlockMaxValueMet;
        }
        if (!isBlockRewardValueMet) {
            strErrorRet = strprintf("coinbase pays too much at height %d (actual=%d vs limit=%d), exceeded block reward, only regular blocks are allowed at this height",
                                    nBlockHeight, block.vtx[0]->GetValueOut(), blockReward);
        }
        // it MUST be a regular block otherwise
        return isBlockRewardValueMet;
    }

    // we are synced, let's try to check as much data as we can

    if (CGovernanceBlockManager::IsGovernanceBlockTriggered(nBlockHeight)) {
        if (CGovernanceBlockManager::IsValid(block.vtx[0], nBlockHeight, blockReward)) {
            LogPrint(BCLog::GOV, "IsBlockValueValid -- Valid governanceblock at height %d: %s", nBlockHeight, block.vtx[0]->ToString());
            // all checks are done in CGovernanceBlock::IsValid, nothing to do here
            return true;
        }

        // triggered but invalid? that's weird
        LogPrint(BCLog::MN, "IsBlockValueValid -- ERROR: Invalid governanceblock detected at height %d: %s", nBlockHeight, block.vtx[0]->ToString());
        // should NOT allow invalid governanceblocks, when governanceblocks are enabled
        strErrorRet = strprintf("invalid governanceblock detected at height %d", nBlockHeight);
        return false;
    }
    LogPrint(BCLog::GOV, "IsBlockValueValid -- No triggered governanceblock detected at height %d\n", nBlockHeight);
    if (!isBlockRewardValueMet) {
        strErrorRet = strprintf("coinbase pays too much at height %d (actual=%d vs limit=%d), exceeded block reward, no triggered governanceblock detected",
            nBlockHeight, block.vtx[0]->GetValueOut(), blockReward);
    }

    // it MUST be a regular block
    return isBlockRewardValueMet;
}

bool IsBlockPayeeValid(const CTransactionRef& txNew, int nBlockHeight, CAmount blockReward)
{
    if (!masternodeSync.IsSynced() || fLiteMode) {
        //there is no budget data to use to check anything, let's just accept the longest chain
        LogPrint(BCLog::MN, "IsBlockPayeeValid -- WARNING: Not enough data, skipping block payee checks\n");
        return true;
    }

    // governanceblocks started
    // SEE IF THIS IS A VALID GOVERNANCEBLOCK

    if (CGovernanceBlockManager::IsGovernanceBlockTriggered(nBlockHeight)) {
        if (CGovernanceBlockManager::IsValid(txNew, nBlockHeight, blockReward)) {
            return true;
        }

        // should NOT allow such governanceblocks, when governanceblocks are enabled
        return false;
    }
    // continue validation, should pay MN
    LogPrint(BCLog::GOV, "IsBlockPayeeValid -- No triggered governanceblock detected at height %d\n", nBlockHeight);

    // IF THIS ISN'T A GOVERNANCEBLOCK OR GOVERNANCEBLOCK IS INVALID, IT SHOULD PAY A MASTERNODE DIRECTLY
    if (mnpayments.IsTransactionValid(txNew, nBlockHeight, blockReward)) {
        LogPrint(BCLog::MN, "IsBlockPayeeValid -- Valid masternode payment at height %d: %s", nBlockHeight, txNew->ToString());
        return true;
    }
    
    if (EnforceMasternodePayments(nBlockHeight)) {
        LogPrintf("IsBlockPayeeValid -- ERROR: Invalid masternode payment detected at height %d: %s", nBlockHeight, txNew->ToString());
        return false;
    }

    LogPrintf("IsBlockPayeeValid -- WARNING: Masternode payment enforcement is disabled, accepting any payee\n");
    return true;
}

void FillBlockPayments(CMutableTransaction& txNew, int nBlockHeight, CAmount blockReward, std::vector<CTxOut>& vtxoutMasternodeRet, std::vector<CTxOut>& vtxoutGovernanceRet)
{
    // only create governanceblocks if governanceblock is actually triggered
    // (height should be validated inside)
    if (CGovernanceBlockManager::IsGovernanceBlockTriggered(nBlockHeight)) {
        LogPrint(BCLog::GOV, "FillBlockPayments -- triggered governanceblock creation at height %d\n", nBlockHeight);
        CGovernanceBlockManager::CreateGovernanceBlock(txNew, nBlockHeight, vtxoutGovernanceRet);
        return;
    }

    // FILL BLOCK PAYEE WITH PRIMARY MASTERNODE PAYMENT OTHERWISE
    mnpayments.FillBlockPayee(txNew, nBlockHeight, blockReward, vtxoutMasternodeRet);
    //LogPrint(BCLog::MN, "FillBlockPayments -- nBlockHeight %d blockReward %lld vtxoutMasternodeRet %s txNew %s", nBlockHeight, blockReward, vtxoutMasternodeRet.ToString(), txNew.GetHash());
}

std::string GetRequiredPaymentsString(int nBlockHeight)
{
    // IF WE HAVE A ACTIVATED TRIGGER FOR THIS HEIGHT - IT IS A GOVERNANCEBLOCK, GET THE REQUIRED PAYEES
    if (CGovernanceBlockManager::IsGovernanceBlockTriggered(nBlockHeight)) {
        return CGovernanceBlockManager::GetRequiredPaymentsString(nBlockHeight);
    }

    // OTHERWISE, PAY MASTERNODE
    return mnpayments.GetRequiredPaymentsString(nBlockHeight);
}

bool EnforceMasternodePayments(int nHeight)
{
    const CChainParams& params = Params();
    CBlockIndex* pcheckpoint = Checkpoints::GetLastCheckpoint(params.Checkpoints());

    return (pcheckpoint && nHeight > pcheckpoint->nHeight + MN_PAYMENTS_UPDATE_THRESHOLD);
}

void CMasternodePayments::Clear()
{
    LOCK2(cs_mapMasternodeBlocks, cs_mapMasternodePaymentVotes);
    mapMasternodeBlocksPrimary.clear();
    mapMasternodeBlocksSecondary.clear();
    mapMasternodePaymentVotesPrimary.clear();
    mapMasternodePaymentVotesSecondary.clear();
}

bool CMasternodePayments::UpdateLastVote(const CMasternodePaymentVote& vote)
{
    LOCK(cs_mapMasternodePaymentVotes);

    const auto it = mapMasternodesLastVote.find(vote.masternodeOutpoint);
    if (it != mapMasternodesLastVote.end()) {
        if (it->second == vote.nBlockHeight)
            return false;
        it->second = vote.nBlockHeight;
        return true;
    }

    //record this masternode voted
    mapMasternodesLastVote.emplace(vote.masternodeOutpoint, vote.nBlockHeight);
    return true;
}

/**
*   FillBlockPayee
*
*   Fill Masternode ONLY payment block
*/

void CMasternodePayments::FillBlockPayee(CMutableTransaction& txNew, int nBlockHeight, CAmount blockReward, std::vector<CTxOut>& vtxoutMasternodeRet) const
{
    // make sure it's not filled yet
    vtxoutMasternodeRet.clear();
    
    // Primary payee
    CScript payee;
    if (!GetBlockPayee(nBlockHeight, payee)) {
        // no masternode detected...
        int nCount = 0;
        masternode_info_t mnInfo;
        if (!mnodeman.GetNextMasternodeInQueueForPayment(nBlockHeight, true, nCount, mnInfo)) {
            // ...and we can't calculate it on our own
            LogPrint(BCLog::MN, "CMasternodePayments::FillBlockPayee -- Failed to detect masternode to pay\n");
            return;
        }
        // fill payee with locally calculated winner and hope for the best
        payee = GetScriptForDestination(CScriptID(GetScriptForDestination(WitnessV0KeyHash(mnInfo.pubKeyCollateralAddress.GetID()))));
    }

    // Secondary payees


    // GET MASTERNODE PAYMENT VARIABLES SETUP
    CAmount masternodePayment = GetMasternodePayment(nBlockHeight, blockReward);

    // split reward between miner ...
    txNew.vout[0].nValue -= masternodePayment;
    // ... and masternode(s)
    CTxOut masternodePaymentTx = CTxOut(masternodePayment, payee);
    vtxoutMasternodeRet.push_back(masternodePaymentTx);
    txNew.vout.push_back(masternodePaymentTx);

    LogPrint(BCLog::MN, "CMasternodePayments::FillBlockPayee -- Masternode payment %lld to %s\n", masternodePayment, EncodeDestination(CScriptID(payee)));
}

int CMasternodePayments::GetMinMasternodePaymentsProto() const {
    return MIN_MASTERNODE_PAYMENT_PROTO_VERSION;
}

void CMasternodePayments::ProcessMessage(CNode* pfrom, const std::string& strCommand, CDataStream& vRecv, CConnman& connman)
{
    if (fLiteMode) return; // disable all Genesis Masternode specific functionality

    if (strCommand == NetMsgType::MASTERNODEPAYMENTSYNC) { //Masternode Payments Request Sync

        if (pfrom->nVersion < GetMinMasternodePaymentsProto()) {
            LogPrint(BCLog::MN, "MASTERNODEPAYMENTSYNC -- peer=%d using obsolete version %i\n", pfrom->GetId(), pfrom->nVersion);
            connman.PushMessage(pfrom, CNetMsgMaker(pfrom->GetSendVersion()).Make(NetMsgType::REJECT, strCommand, REJECT_OBSOLETE,
                               strprintf("Version must be %d or greater", GetMinMasternodePaymentsProto())));
            return;
        }

        // Ignore such requests until we are fully synced.
        // We could start processing this after masternode list is synced
        // but this is a heavy one so it's better to finish sync first.
        if (!masternodeSync.IsSynced()) return;

        // DEPRECATED, should be removed on next protocol bump
        // if (pfrom->nVersion == BLOCKRESTRUCTURE_AND_MASTERNODES) {
        //     int nCountNeeded;
        //     vRecv >> nCountNeeded;
        // }

        if (netfulfilledman.HasFulfilledRequest(pfrom->addr, NetMsgType::MASTERNODEPAYMENTSYNC)) {
            LOCK(cs_main);
            // Asking for the payments list multiple times in a short period of time is no good
            LogPrint(BCLog::MN, "MASTERNODEPAYMENTSYNC -- peer already asked me for the list, peer=%d\n", pfrom->GetId());
            Misbehaving(pfrom->GetId(), 20);
            return;
        }
        netfulfilledman.AddFulfilledRequest(pfrom->addr, NetMsgType::MASTERNODEPAYMENTSYNC);

        Sync(pfrom, connman);
        LogPrintf("MASTERNODEPAYMENTSYNC -- Sent Masternode payment votes to peer=%d\n", pfrom->GetId());

    } else if (strCommand == NetMsgType::MASTERNODEPAYMENTVOTEPRIMARY) { // Masternode Payments Vote for the Winner

        CMasternodePaymentVote vote;
        vRecv >> vote;

        if (pfrom->nVersion < GetMinMasternodePaymentsProto()) {
            LogPrint(BCLog::MN, "MASTERNODEPAYMENTVOTEPRIMARY -- peer=%d using obsolete version %i\n", pfrom->GetId(), pfrom->nVersion);
            connman.PushMessage(pfrom, CNetMsgMaker(pfrom->GetSendVersion()).Make(NetMsgType::REJECT, strCommand, REJECT_OBSOLETE,
                               strprintf("Version must be %d or greater", GetMinMasternodePaymentsProto())));
            return;
        }

        uint256 nHash = vote.GetHash();

        pfrom->setAskFor.erase(nHash);

        // TODO: clear setAskFor for MSG_MASTERNODE_PAYMENT_BLOCK_PRIMARY too

        // Ignore any payments messages until masternode list is synced
        if (!masternodeSync.IsMasternodeListSynced()) return;

        {
            LOCK(cs_mapMasternodePaymentVotes);
            auto res = mapMasternodePaymentVotesPrimary.emplace(nHash, vote);

            // Avoid processing same vote multiple times if it was already verified earlier
            if (!res.second && res.first->second.IsVerified()) {
                LogPrint(BCLog::MN, "MASTERNODEPAYMENTVOTEPRIMARY -- hash=%s, nBlockHeight=%d/%d seen\n",
                    nHash.ToString(), vote.nBlockHeight, nCachedBlockHeight);
                return;
            }

            // Mark vote as non-verified when it's seen for the first time,
            // AddOrUpdatePaymentVote() below should take care of it if vote is actually ok
            res.first->second.MarkAsNotVerified();
        }

        int nFirstBlock = nCachedBlockHeight - GetStorageLimit();
        if (vote.nBlockHeight < nFirstBlock || vote.nBlockHeight > nCachedBlockHeight + 20) {
            LogPrint(BCLog::MN, "MASTERNODEPAYMENTVOTEPRIMARY -- vote out of range: nFirstBlock=%d, nBlockHeight=%d, nHeight=%d\n", nFirstBlock, vote.nBlockHeight, nCachedBlockHeight);
            return;
        }

        std::string strError = "";
        if (!vote.IsValid(pfrom, nCachedBlockHeight, strError, connman)) {
            LogPrint(BCLog::MN, "MASTERNODEPAYMENTVOTEPRIMARY -- invalid message, error: %s\n", strError);
            return;
        }

        masternode_info_t mnInfo;
        if (!mnodeman.GetMasternodeInfo(vote.masternodeOutpoint, mnInfo)) {
            // mn was not found, so we can't check vote, some info is probably missing
            LogPrintf("MASTERNODEPAYMENTVOTEPRIMARY -- masternode is missing %s\n", vote.masternodeOutpoint.ToStringShort());
            mnodeman.AskForMN(pfrom, vote.masternodeOutpoint, connman);
            return;
        }

        int nDos = 0;
        if (!vote.CheckSignature(mnInfo.pubKeyMasternode, nCachedBlockHeight, nDos)) {
            if (nDos) {
                LOCK(cs_main);
                LogPrint(BCLog::MN, "MASTERNODEPAYMENTVOTEPRIMARY -- ERROR: invalid signature\n");
                Misbehaving(pfrom->GetId(), nDos);
            } else {
                // only warn about anything non-critical (i.e. nDos == 0) in debug mode
                LogPrint(BCLog::MN, "MASTERNODEPAYMENTVOTEPRIMARY -- WARNING: invalid signature\n");
            }
            // Either our info or vote info could be outdated.
            // In case our info is outdated, ask for an update,
            mnodeman.AskForMN(pfrom, vote.masternodeOutpoint, connman);
            // but there is nothing we can do if vote info itself is outdated
            // (i.e. it was signed by a mn which changed its key),
            // so just quit here.
            return;
        }
        
        if (!UpdateLastVote(vote)) {
            LogPrintf("MASTERNODEPAYMENTVOTEPRIMARY -- masternode already voted, masternode=%s\n", vote.masternodeOutpoint.ToStringShort());
            return;
        }

        CTxDestination address1;
        ExtractDestination(vote.payee, address1);

        LogPrint(BCLog::MN, "MASTERNODEPAYMENTVOTEPRIMARY -- vote: address=%s, nBlockHeight=%d, nHeight=%d, prevout=%s, hash=%s new\n",
            EncodeDestination(address1), vote.nBlockHeight, nCachedBlockHeight, vote.masternodeOutpoint.ToStringShort(), nHash.ToString());

        if (AddOrUpdatePaymentVote(vote)){
            vote.Relay(connman);
            masternodeSync.BumpAssetLastTime("MASTERNODEPAYMENTVOTEPRIMARY");
        }
    }
    else if (strCommand == NetMsgType::MASTERNODEPAYMENTVOTESECONDARY){
        // get the secondary masternodes to share in the payments...
    }
}

uint256 CMasternodePaymentVote::GetHash() const
{
    // Note: doesn't match serialization

    CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
    ss << *(CScriptBase*)(&payee);
    ss << nBlockHeight;
    ss << masternodeOutpoint;
    return ss.GetHash();
}

uint256 CMasternodePaymentVote::GetSignatureHash() const
{
    return SerializeHash(*this);
}

bool CMasternodePaymentVote::Sign()
{
    std::string strError;

    if (chainActive.Height() > Params().GetConsensus().nMasternodeSignHashThreshold) {
        uint256 hash = GetSignatureHash();

        if (!CHashSigner::SignHash(hash, activeMasternode.keyMasternode, vchSig)) {
            LogPrintf("CMasternodePaymentVote::Sign -- SignHash() failed\n");
            return false;
        }

        if (!CHashSigner::VerifyHash(hash, activeMasternode.pubKeyMasternode, vchSig, strError)) {
            LogPrintf("CMasternodePaymentVote::Sign -- VerifyHash() failed, error: %s\n", strError);
            return false;
        }
    } else {
        std::string strMessage = masternodeOutpoint.ToStringShort() +
                    boost::lexical_cast<std::string>(nBlockHeight) +
                    ScriptToAsmStr(payee);

        if (!CMessageSigner::SignMessage(strMessage, vchSig, activeMasternode.keyMasternode)) {
            LogPrintf("CMasternodePaymentVote::Sign -- SignMessage() failed\n");
            return false;
        }

        if (!CMessageSigner::VerifyMessage(activeMasternode.pubKeyMasternode, vchSig, strMessage, strError)) {
            LogPrintf("CMasternodePaymentVote::Sign -- VerifyMessage() failed, error: %s\n", strError);
            return false;
        }
    }

    return true;
}

bool CMasternodePayments::GetBlockPayee(int nBlockHeight, CScript& payeeRet) const
{
    LOCK(cs_mapMasternodeBlocks);

    auto it = mapMasternodeBlocksPrimary.find(nBlockHeight);
    return it != mapMasternodeBlocksPrimary.end() && it->second.GetBestPayee(payeeRet);
}

// Is this masternode scheduled to get paid soon?
// -- Only look ahead up to 8 blocks to allow for propagation of the latest 2 blocks of votes
bool CMasternodePayments::IsScheduled(const masternode_info_t& mnInfo, int nNotBlockHeight) const
{
    LOCK(cs_mapMasternodeBlocks);

    if (!masternodeSync.IsMasternodeListSynced()) return false;

    CScript mnpayee;
    mnpayee = GetScriptForDestination(CScriptID(GetScriptForDestination(WitnessV0KeyHash(mnInfo.pubKeyCollateralAddress.GetID()))));

    CScript payee;
    for(int64_t h = nCachedBlockHeight; h <= nCachedBlockHeight + 8; h++){
        if (h == nNotBlockHeight) continue;
        if (GetBlockPayee(h, payee) && mnpayee == payee) {
            return true;
        }
    }

    return false;
}

bool CMasternodePayments::AddOrUpdatePaymentVote(const CMasternodePaymentVote& vote)
{
    uint256 blockHash = uint256();
    if (!GetBlockHash(blockHash, vote.nBlockHeight - 101)) return false;

    uint256 nVoteHash = vote.GetHash();
    
    if (HasVerifiedPaymentVote(nVoteHash)) return false;

    LOCK2(cs_mapMasternodeBlocks, cs_mapMasternodePaymentVotes);

    mapMasternodePaymentVotesPrimary[nVoteHash] = vote;

    auto it = mapMasternodeBlocksPrimary.emplace(vote.nBlockHeight, CMasternodeBlockPayees(vote.nBlockHeight)).first;
    it->second.AddPayee(vote);

    LogPrint(BCLog::MN, "CMasternodePayments::AddOrUpdatePaymentVote -- added, hash=%s\n", nVoteHash.ToString());

    return true;
}

bool CMasternodePayments::HasVerifiedPaymentVote(const uint256& hashIn) const
{
    LOCK(cs_mapMasternodePaymentVotes);
    const auto it = mapMasternodePaymentVotesPrimary.find(hashIn);
    return it != mapMasternodePaymentVotesPrimary.end() && it->second.IsVerified();
}

void CMasternodeBlockPayees::AddPayee(const CMasternodePaymentVote& vote)
{
    LOCK(cs_vecPayees);

    uint256 nVoteHash = vote.GetHash();
    
    for (auto& payee : vecPayees) {
        if (payee.GetPayee() == vote.payee) {
            payee.AddVoteHash(nVoteHash);
            return;
        }
    }
    CMasternodePayee payeeNew(vote.payee, nVoteHash);
    vecPayees.push_back(payeeNew);
}

bool CMasternodeBlockPayees::GetBestPayee(CScript& payeeRet) const
{
    LOCK(cs_vecPayees);

    if (vecPayees.empty()) {
        LogPrint(BCLog::MN, "CMasternodeBlockPayees::GetBestPayee -- ERROR: couldn't find any payee\n");
        return false;
    }

    int nVotes = -1;
    for (const auto& payee : vecPayees) {
        if (payee.GetVoteCount() > nVotes) {
            payeeRet = payee.GetPayee();
            nVotes = payee.GetVoteCount();
        }
    }

    return (nVotes > -1);
}

bool CMasternodeBlockPayees::HasPayeeWithVotes(const CScript& payeeIn, int nVotesReq) const
{
    LOCK(cs_vecPayees);

    for (const auto& payee : vecPayees) {
        if (payee.GetVoteCount() >= nVotesReq &&  payee.GetPayee() == payeeIn) {
            return true;
        }
    }

    LogPrint(BCLog::MN, "CMasternodeBlockPayees::HasPayeeWithVotes -- ERROR: couldn't find any payee with %d+ votes\n", nVotesReq);
    return false;
}

bool CMasternodeBlockPayees::IsTransactionValid(const CTransactionRef& txNew, int nBlockHeight, CAmount blockReward) const
{
    LOCK(cs_vecPayees);

    int nMaxSignatures = 0;
    std::string strPayeesPossible = "";

    CAmount nMasternodePayment = GetMasternodePayment(nBlockHeight, blockReward);

    //require at least MNPAYMENTS_SIGNATURES_REQUIRED signatures

    for (const auto& payee : vecPayees) {
        if (payee.GetVoteCount() >= nMaxSignatures) {
            nMaxSignatures = payee.GetVoteCount();
        }
    }

    // if we don't have at least MNPAYMENTS_SIGNATURES_REQUIRED signatures on a payee, approve whichever is the longest chain
    if (nMaxSignatures < MNPAYMENTS_SIGNATURES_REQUIRED) return true;

    for (const auto& payee : vecPayees) {
        if (payee.GetVoteCount() >= MNPAYMENTS_SIGNATURES_REQUIRED) {
            for (const auto& txout : txNew->vout) {
                if (payee.GetPayee() == txout.scriptPubKey && txout.nValue >= nMasternodePayment && txout.nValue <= (nMasternodePayment + CAmount(10000000))) {
                    LogPrint(BCLog::MN, "CMasternodeBlockPayees::IsTransactionValid -- Found required payment\n");
                    return true;
                }
            }
            
            CTxDestination address;
            ExtractDestination(payee.GetPayee(), address);

            if (strPayeesPossible == "") {
                strPayeesPossible = EncodeDestination(address);
            } else {
                strPayeesPossible += "," + EncodeDestination(address);
            }
        }
    }

    LogPrint(BCLog::MN, "CMasternodeBlockPayees::IsTransactionValid -- ERROR: Missing required payment, possible payees: '%s', amount: %f GENX\n", strPayeesPossible, (float)nMasternodePayment / COIN);
    return false;
}

std::string CMasternodeBlockPayees::GetRequiredPaymentsString() const
{
    LOCK(cs_vecPayees);

    std::string strRequiredPayments = "";

    for (const auto& payee : vecPayees)
    {
        CTxDestination address;
        ExtractDestination(payee.GetPayee(), address);
        if (!strRequiredPayments.empty())
            strRequiredPayments += ", ";

        strRequiredPayments += strprintf("%s:%d", EncodeDestination(address), payee.GetVoteCount());
    }
    
    if (strRequiredPayments.empty())
        return "Unknown";

    return strRequiredPayments;
}

std::string CMasternodePayments::GetRequiredPaymentsString(int nBlockHeight) const
{
    LOCK(cs_mapMasternodeBlocks);

    const auto it = mapMasternodeBlocksPrimary.find(nBlockHeight);
    return it == mapMasternodeBlocksPrimary.end() ? "Unknown" : it->second.GetRequiredPaymentsString();
}

bool CMasternodePayments::IsTransactionValid(const CTransactionRef& txNew, int nBlockHeight, CAmount blockReward) const
{
    LOCK(cs_mapMasternodeBlocks);

    const auto it = mapMasternodeBlocksPrimary.find(nBlockHeight);
    return it == mapMasternodeBlocksPrimary.end() ? true : it->second.IsTransactionValid(txNew, nBlockHeight, blockReward);
}

void CMasternodePayments::CheckAndRemove()
{
    if (!masternodeSync.IsBlockchainSynced()) return;

    LOCK2(cs_mapMasternodeBlocks, cs_mapMasternodePaymentVotes);

    int nLimit = GetStorageLimit();

    std::map<uint256, CMasternodePaymentVote>::iterator it = mapMasternodePaymentVotesPrimary.begin();
    while(it != mapMasternodePaymentVotesPrimary.end()) {
        CMasternodePaymentVote vote = (*it).second;

        if (nCachedBlockHeight - vote.nBlockHeight > nLimit) {
            LogPrint(BCLog::MN, "CMasternodePayments::CheckAndRemove -- Removing old Masternode payment: nBlockHeight=%d\n", vote.nBlockHeight);
            mapMasternodePaymentVotesPrimary.erase(it++);
            mapMasternodeBlocksPrimary.erase(vote.nBlockHeight);
        } else {
            ++it;
        }
    }
    LogPrint(BCLog::MN, "CMasternodePayments::CheckAndRemove -- %s\n", ToString());
}

bool CMasternodePaymentVote::IsValid(CNode* pnode, int nValidationHeight, std::string& strError, CConnman& connman) const
{
    masternode_info_t mnInfo;

    if (!mnodeman.GetMasternodeInfo(masternodeOutpoint, mnInfo)) {
        strError = strprintf("Unknown masternode=%s", masternodeOutpoint.ToStringShort());
        // Only ask if we are already synced and still have no idea about that Masternode
        if (masternodeSync.IsMasternodeListSynced()) {
            mnodeman.AskForMN(pnode, masternodeOutpoint, connman);
        }

        return false;
    }

    int nMinRequiredProtocol;
    nMinRequiredProtocol = mnpayments.GetMinMasternodePaymentsProto();

    if (mnInfo.nProtocolVersion < nMinRequiredProtocol) {
        strError = strprintf("Masternode protocol is too old: nProtocolVersion=%d, nMinRequiredProtocol=%d", mnInfo.nProtocolVersion, nMinRequiredProtocol);
        return false;
    }

    // Only masternodes should try to check masternode rank for old votes - they need to pick the right winner for future blocks.
    // Regular clients (miners included) need to verify masternode rank for future block votes only.
    if (!fMasternodeMode && nBlockHeight < nValidationHeight) return true;

    int nRank;

    if (!mnodeman.GetMasternodeRank(masternodeOutpoint, nRank, nBlockHeight - 101, nMinRequiredProtocol)) {
        LogPrint(BCLog::MN, "CMasternodePaymentVote::IsValid -- Can't calculate rank for masternode %s\n",
            masternodeOutpoint.ToStringShort());
        return false;
    }

    if (nRank > MNPAYMENTS_SIGNATURES_TOTAL) {
        // It's common to have masternodes mistakenly think they are in the top 10
        // We don't want to print all of these messages in normal mode, debug mode should print though
        strError = strprintf("Masternode %s is not in the top %d (%d)", masternodeOutpoint.ToStringShort(), MNPAYMENTS_SIGNATURES_TOTAL, nRank);
        // Only ban for new mnw which is out of bounds, for old mnw MN list itself might be way too much off
        if (nRank > MNPAYMENTS_SIGNATURES_TOTAL*2 && nBlockHeight > nValidationHeight) {
            LOCK(cs_main);
            strError = strprintf("Masternode %s is not in the top %d (%d)", masternodeOutpoint.ToStringShort(), MNPAYMENTS_SIGNATURES_TOTAL * 2, nRank);
            LogPrint(BCLog::MN, "CMasternodePaymentVote::IsValid -- Error: %s\n", strError);
            Misbehaving(pnode->GetId(), 20);
        }
        // Still invalid however
        return false;
    }

    return true;
}

bool CMasternodePayments::ProcessBlock(int nBlockHeight, CConnman& connman)
{
    // DETERMINE IF WE SHOULD BE VOTING FOR THE NEXT PAYEE

    if (fLiteMode || !fMasternodeMode) return false;

    // We have little chances to pick the right winner if winners list is out of sync
    // but we have no choice, so we'll try. However it doesn't make sense to even try to do so
    // if we have not enough data about masternodes.
    if (!masternodeSync.IsMasternodeListSynced()) return false;

    int nRank;

    if (!mnodeman.GetMasternodeRank(activeMasternode.outpoint, nRank, nBlockHeight - 101, GetMinMasternodePaymentsProto())) {
        LogPrint(BCLog::MN, "CMasternodePayments::ProcessBlock -- Unknown Masternode\n");
        return false;
    }

    if (nRank > MNPAYMENTS_SIGNATURES_TOTAL) {
        LogPrint(BCLog::MN, "CMasternodePayments::ProcessBlock -- Masternode not in the top %d (%d)\n", MNPAYMENTS_SIGNATURES_TOTAL, nRank);
        return false;
    }


    // LOCATE THE NEXT MASTERNODE WHICH SHOULD BE PAID

    LogPrint(BCLog::MN, "CMasternodePayments::ProcessBlock -- Start: nBlockHeight=%d, masternode=%s\n", nBlockHeight, activeMasternode.outpoint.ToStringShort());

    // pay to the oldest MN that still had no payment but its input is old enough and it was active long enough
    int nCount = 0;
    masternode_info_t mnInfo;

    if (!mnodeman.GetNextMasternodeInQueueForPayment(nBlockHeight, true, nCount, mnInfo)) {
        LogPrint(BCLog::MN, "CMasternodePayments::ProcessBlock -- ERROR: Failed to find masternode to pay\n");
        return false;
    }

    LogPrintf("CMasternodePayments::ProcessBlock -- Masternode found by GetNextMasternodeInQueueForPayment(): %s\n", mnInfo.outpoint.ToStringShort());

    CScript payee = GetScriptForDestination(CScriptID(GetScriptForDestination(WitnessV0KeyHash(mnInfo.pubKeyCollateralAddress.GetID()))));

    CMasternodePaymentVote voteNew(activeMasternode.outpoint, nBlockHeight, payee);

    CTxDestination address1;
    ExtractDestination(payee, address1);

    LogPrint(BCLog::MN, "CMasternodePayments::ProcessBlock -- vote: payee=%s, nBlockHeight=%d\n", EncodeDestination(address1), nBlockHeight);

    // SIGN MESSAGE TO NETWORK WITH OUR MASTERNODE KEYS

    LogPrint(BCLog::MN, "CMasternodePayments::ProcessBlock -- Signing vote\n");
    if (voteNew.Sign()) {
        LogPrintf("CMasternodePayments::ProcessBlock -- AddOrUpdatePaymentVote()\n");

        if (AddOrUpdatePaymentVote(voteNew)) {
            voteNew.Relay(connman);
            return true;
        }
    }

    return false;
}

void CMasternodePayments::CheckBlockVotes(int nBlockHeight)
{
    if (!masternodeSync.IsWinnersListSynced()) return;

    CMasternodeMan::rank_pair_vec_t mns;
    if (!mnodeman.GetMasternodeRanks(mns, nBlockHeight - 101, GetMinMasternodePaymentsProto())) {
        LogPrintf("CMasternodePayments::CheckBlockVotes -- nBlockHeight=%d, GetMasternodeRanks failed\n", nBlockHeight);
        return;
    }
    
    std::string debugStr;

    debugStr += strprintf("CMasternodePayments::CheckBlockVotes -- nBlockHeight=%d,\n  Expected voting MNs:\n", nBlockHeight);

    LOCK2(cs_mapMasternodeBlocks, cs_mapMasternodePaymentVotes);

    int i{0};
    for (const auto& mn : mns) {
        CScript payee;
        bool found = false;

        const auto it = mapMasternodeBlocksPrimary.find(nBlockHeight);
        if (it != mapMasternodeBlocksPrimary.end()) {
            for (const auto& p : it->second.vecPayees) {
                for (const auto& voteHash : p.GetVoteHashes()) {
                    const auto itVote = mapMasternodePaymentVotesPrimary.find(voteHash);
                    if (itVote == mapMasternodePaymentVotesPrimary.end()) {
                        debugStr += strprintf("    - could not find vote %s\n",
                                              voteHash.ToString());
                        continue;
                    }
                    if (itVote->second.masternodeOutpoint == mn.second.outpoint) {
                        payee = itVote->second.payee;
                        found = true;
                        break;
                    }
                }
            }
        }
        
        if (found) {
            CTxDestination address1;
            ExtractDestination(payee, address1);

            debugStr += strprintf("    - %s - voted for %s\n",
                                  mn.second.outpoint.ToStringShort(), EncodeDestination(address1));
        } else {
            mapMasternodesDidNotVote.emplace(mn.second.outpoint, 0).first->second++;

            debugStr += strprintf("    - %s - no vote received\n",
                                  mn.second.outpoint.ToStringShort());
        }
        
        if (++i >= MNPAYMENTS_SIGNATURES_TOTAL) break;
    }
    if (mapMasternodesDidNotVote.empty()) {
        LogPrint(BCLog::MN, "%s", debugStr);
        return;
    }

    debugStr += "  Masternodes which missed a vote in the past:\n";
    for (const auto& item : mapMasternodesDidNotVote) {
        debugStr += strprintf("    - %s: %d\n", item.first.ToStringShort(), item.second);
    }

    LogPrint(BCLog::MN, "%s", debugStr);
}

void CMasternodePaymentVote::Relay(CConnman& connman) const
{
    // Do not relay until fully synced
    if (!masternodeSync.IsSynced()) {
        LogPrint(BCLog::MN, "CMasternodePayments::Relay -- won't relay until fully synced\n");
        return;
    }

    CInv inv(MSG_MASTERNODE_PAYMENT_VOTE_PRIMARY, GetHash());
    connman.RelayInv(inv);
}

bool CMasternodePaymentVote::CheckSignature(const CPubKey& pubKeyMasternode, int nValidationHeight, int &nDos) const
{
    // do not ban by default
    nDos = 0;

    std::string strError = "";

    if (chainActive.Height() > Params().GetConsensus().nMasternodeSignHashThreshold) {
        uint256 hash = GetSignatureHash();

        if (!CHashSigner::VerifyHash(hash, pubKeyMasternode, vchSig, strError)) {
            // could be a signature in old format
            std::string strMessage = masternodeOutpoint.ToStringShort() +
                        boost::lexical_cast<std::string>(nBlockHeight) +
                        ScriptToAsmStr(payee);
            if (!CMessageSigner::VerifyMessage(pubKeyMasternode, vchSig, strMessage, strError)) {
                // nope, not in old format either
                // Only ban for future block vote when we are already synced.
                // Otherwise it could be the case when MN which signed this vote is using another key now
                // and we have no idea about the old one.
                if (masternodeSync.IsMasternodeListSynced() && nBlockHeight > nValidationHeight) {
                    nDos = 20;
                }
                return error("CMasternodePaymentVote::CheckSignature -- Got bad Masternode payment signature, masternode=%s, error: %s",
                            masternodeOutpoint.ToStringShort(), strError);
            }
        }
    } else {
        std::string strMessage = masternodeOutpoint.ToStringShort() +
                    boost::lexical_cast<std::string>(nBlockHeight) +
                    ScriptToAsmStr(payee);

        if (!CMessageSigner::VerifyMessage(pubKeyMasternode, vchSig, strMessage, strError)) {
            // Only ban for future block vote when we are already synced.
            // Otherwise it could be the case when MN which signed this vote is using another key now
            // and we have no idea about the old one.
            if (masternodeSync.IsMasternodeListSynced() && nBlockHeight > nValidationHeight) {
                nDos = 20;
            }
            return error("CMasternodePaymentVote::CheckSignature -- Got bad Masternode payment signature, masternode=%s, error: %s",
                        masternodeOutpoint.ToStringShort(), strError);
        }
    }

    return true;
}

std::string CMasternodePaymentVote::ToString() const
{
    std::ostringstream info;

    info << masternodeOutpoint.ToStringShort() <<
            ", " << nBlockHeight <<
            ", " << ScriptToAsmStr(payee) <<
            ", " << (int)vchSig.size();

    return info.str();
}

// Send only votes for future blocks, node should request every other missing payment block individually
void CMasternodePayments::Sync(CNode* pnode, CConnman& connman) const
{
    const CNetMsgMaker msgMaker(pnode->GetSendVersion());

    LOCK(cs_mapMasternodeBlocks);

    if (!masternodeSync.IsWinnersListSynced()) return;

    int nInvCount = 0;

    for(int h = nCachedBlockHeight; h < nCachedBlockHeight + 20; h++) {
        const auto it = mapMasternodeBlocksPrimary.find(h);
        if (it != mapMasternodeBlocksPrimary.end()) {
            for (const auto& payee : it->second.vecPayees) {
                std::vector<uint256> vecVoteHashes = payee.GetVoteHashes();
                for (const auto& hash : vecVoteHashes) {
                    if (!HasVerifiedPaymentVote(hash)) continue;
                    pnode->PushInventory(CInv(MSG_MASTERNODE_PAYMENT_VOTE_PRIMARY, hash));
                    nInvCount++;
                }
            }
        }
    }

    LogPrint(BCLog::MN, "CMasternodePayments::Sync -- Sent %d votes to peer=%d\n", nInvCount, pnode->GetId());

    connman.PushMessage(pnode, msgMaker.Make(NetMsgType::SYNCSTATUSCOUNT, MASTERNODE_SYNC_MNW, nInvCount));
}

// Request low data/unknown payment blocks in batches directly from some node instead of/after preliminary Sync.
void CMasternodePayments::RequestLowDataPaymentBlocks(CNode* pnode, CConnman& connman) const
{
    if (!masternodeSync.IsMasternodeListSynced()) return;
    
    const CNetMsgMaker msgMaker(pnode->GetSendVersion());

    LOCK2(cs_main, cs_mapMasternodeBlocks);

    std::vector<CInv> vToFetch;
    int nLimit = GetStorageLimit();

    const CBlockIndex *pindex = chainActive.Tip();

    while(nCachedBlockHeight - pindex->nHeight < nLimit) {
        const auto it = mapMasternodeBlocksPrimary.find(pindex->nHeight);
        if (it == mapMasternodeBlocksPrimary.end()) {
            // We have no idea about this block height, let's ask
            vToFetch.push_back(CInv(MSG_MASTERNODE_PAYMENT_BLOCK_PRIMARY, pindex->GetBlockHash()));
            // We should not violate GETDATA rules
            if (vToFetch.size() == MAX_INV_SZ) {
                LogPrint(BCLog::MN, "CMasternodePayments::RequestLowDataPaymentBlocks -- asking peer=%d for %d blocks\n", pnode->GetId(), MAX_INV_SZ);
                connman.PushMessage(pnode, msgMaker.Make(NetMsgType::GETDATA, vToFetch));
                // connman.PushMessage(pnode, NetMsgType::GETDATA, vToFetch);
                // Start filling new batch
                vToFetch.clear();
            }
        }
        if (!pindex->pprev) break;
        pindex = pindex->pprev;
    }

    auto it = mapMasternodeBlocksPrimary.begin();

    while(it != mapMasternodeBlocksPrimary.end()) {
        int nTotalVotes = 0;
        bool fFound = false;
        for (const auto& payee : it->second.vecPayees) {
            if (payee.GetVoteCount() >= MNPAYMENTS_SIGNATURES_REQUIRED) {
                fFound = true;
                break;
            }
            nTotalVotes += payee.GetVoteCount();
        }
        // A clear winner (MNPAYMENTS_SIGNATURES_REQUIRED+ votes) was found
        // or no clear winner was found but there are at least avg number of votes
        if (fFound || nTotalVotes >= (MNPAYMENTS_SIGNATURES_TOTAL + MNPAYMENTS_SIGNATURES_REQUIRED)/2) {
            // so just move to the next block
            ++it;
            continue;
        }
        // Low data block found, let's try to sync it
        uint256 hash;
        if (GetBlockHash(hash, it->first)) {
            vToFetch.push_back(CInv(MSG_MASTERNODE_PAYMENT_BLOCK_PRIMARY, hash));
        }
        // We should not violate GETDATA rules
        if (vToFetch.size() == MAX_INV_SZ) {
            LogPrint(BCLog::MN, "CMasternodePayments::RequestLowDataPaymentBlocks -- asking peer=%d for %d payment blocks\n", pnode->GetId(), MAX_INV_SZ);
            connman.PushMessage(pnode, msgMaker.Make(NetMsgType::GETDATA, vToFetch));
            // connman.PushMessage(pnode, NetMsgType::GETDATA, vToFetch);
            // Start filling new batch
            vToFetch.clear();
        }
        ++it;
    }
    // Ask for the rest of it
    if (!vToFetch.empty()) {
        LogPrint(BCLog::MN, "CMasternodePayments::RequestLowDataPaymentBlocks -- asking peer=%d for %d payment blocks\n", pnode->GetId(), vToFetch.size());
        connman.PushMessage(pnode, msgMaker.Make(NetMsgType::GETDATA, vToFetch));
        // connman.PushMessage(pnode, NetMsgType::GETDATA, vToFetch);
    }
}

std::string CMasternodePayments::ToString() const
{
    std::ostringstream info;

    info << "Votes: " << (int)mapMasternodePaymentVotesPrimary.size() <<
            ", Blocks: " << (int)mapMasternodeBlocksPrimary.size();

    return info.str();
}

bool CMasternodePayments::IsEnoughData() const
{
    float nAverageVotes = (MNPAYMENTS_SIGNATURES_TOTAL + MNPAYMENTS_SIGNATURES_REQUIRED) / 2;
    int nStorageLimit = GetStorageLimit();
    return GetBlockCount() > nStorageLimit && GetVoteCount() > nStorageLimit * nAverageVotes;
}

int CMasternodePayments::GetStorageLimit() const
{
    return std::max(int(mnodeman.size() * nStorageCoeff), nMinBlocksToStore);
}

void CMasternodePayments::UpdatedBlockTip(const CBlockIndex *pindex, CConnman& connman)
{
    if (!pindex) return;

    nCachedBlockHeight = pindex->nHeight;
    LogPrint(BCLog::MN, "CMasternodePayments::UpdatedBlockTip -- nCachedBlockHeight=%d\n", nCachedBlockHeight);

    int nFutureBlock = nCachedBlockHeight + 10;

    CheckBlockVotes(nFutureBlock - 1);
    ProcessBlock(nFutureBlock, connman);
}
