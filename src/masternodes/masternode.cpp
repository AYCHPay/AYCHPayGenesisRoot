// Copyright (c) 2014-2018 The Dash Core developers
// Copyright (c) 2014-2018 The Machinecoin Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <masternodes/activemasternode.h>
#include <base58.h>
#include <clientversion.h>
#include <init.h>
#include <netbase.h>
#include <masternodes/masternode.h>
#include <masternodes/masternode-payments.h>
#include <masternodes/masternode-sync.h>
#include <masternodes/masternodeman.h>
#include <masternodes/messagesigner.h>
#include <script/standard.h>
#include <util.h>
#include <wallet/wallet.h>

#include <boost/foreach.hpp>
#include <boost/lexical_cast.hpp>


CMasternode::CMasternode() :
    masternode_info_t{ MASTERNODE_ENABLED, PROTOCOL_VERSION, GetAdjustedTime()}
{}

CMasternode::CMasternode(CService addr, COutPoint outpoint, CPubKey pubKeyCollateralAddress, CPubKey pubKeyMasternode, int nProtocolVersionIn) :
    masternode_info_t{ MASTERNODE_ENABLED, nProtocolVersionIn, GetAdjustedTime(),
                       outpoint, addr, pubKeyCollateralAddress, pubKeyMasternode}
{}

CMasternode::CMasternode(const CMasternode& other) :
    masternode_info_t{other},
    lastPing(other.lastPing),
    vchSig(other.vchSig),
    nCollateralMinConfBlockHash(other.nCollateralMinConfBlockHash),
    nBlockLastPaidPrimary(other.nBlockLastPaidPrimary),
    nBlockLastPaidSecondary(other.nBlockLastPaidSecondary),
    nPoSeBanScore(other.nPoSeBanScore),
    nPoSeBanHeight(other.nPoSeBanHeight),
    fUnitTest(other.fUnitTest)
{}

CMasternode::CMasternode(const CMasternodeBroadcast& mnb) :
    masternode_info_t{ mnb.nActiveState, mnb.nProtocolVersion, mnb.sigTime,
                       mnb.outpoint, mnb.addr, mnb.pubKeyCollateralAddress, mnb.pubKeyMasternode },
    lastPing(mnb.lastPing),
    vchSig(mnb.vchSig)
{}

//
// When a new masternode broadcast is sent, update our information
//
bool CMasternode::UpdateFromNewBroadcast(CMasternodeBroadcast& mnb, CConnman& connman)
{
    if (mnb.sigTime <= sigTime && !mnb.fRecovery) return false;

    pubKeyMasternode = mnb.pubKeyMasternode;
    sigTime = mnb.sigTime;
    vchSig = mnb.vchSig;
    nProtocolVersion = mnb.nProtocolVersion;
    addr = mnb.addr;
    nPoSeBanScore = 0;
    nPoSeBanHeight = 0;
    nTimeLastChecked = 0;
    int nDos = 0;
    if (!mnb.lastPing || (mnb.lastPing && mnb.lastPing.CheckAndUpdate(this, true, nDos, connman))) {
        lastPing = mnb.lastPing;
        mnodeman.mapSeenMasternodePing.insert(std::make_pair(lastPing.GetHash(), lastPing));
    }
    // if it matches our Masternode privkey...
    if (fMasternodeMode && pubKeyMasternode == activeMasternode.pubKeyMasternode) {
        nPoSeBanScore = -Params().GetConsensus().nMasternodePoseBanMaxScore;
        if (nProtocolVersion == PROTOCOL_VERSION) {
            // ... and PROTOCOL_VERSION, then we've been remotely activated ...
            activeMasternode.ManageState(connman);
        } else {
            // ... otherwise we need to reactivate our node, do not add it to the list and do not relay
            // but also do not ban the node we get this message from
            LogPrintG(BCLogLevel::LOG_ERROR, BCLog::MN, "[Masternodes] CMasternode::UpdateFromNewBroadcast -- wrong PROTOCOL_VERSION, re-activate your MN: message nProtocolVersion=%d  PROTOCOL_VERSION=%d\n", nProtocolVersion, PROTOCOL_VERSION);
            return false;
        }
    }
    return true;
}

//
// Deterministically calculate a given "score" for a Masternode depending on how close it's hash is to
// the proof of work for that block. The further away they are the better, the furthest will win the election
// and get paid this block
//
arith_uint256 CMasternode::CalculateScore(const uint256& blockHash) const
{
    // Deterministically calculate a "score" for a Masternode based on any given (block)hash
    CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
    ss << outpoint << nCollateralMinConfBlockHash << blockHash;
    return UintToArith256(ss.GetHash());
}

CMasternode::CollateralStatus CMasternode::CheckCollateral(const COutPoint& outpoint, const CPubKey& pubkey)
{
    int nHeight;
    return CheckCollateral(outpoint, pubkey, nHeight);
}

CMasternode::CollateralStatus CMasternode::CheckCollateral(const COutPoint& outpoint, const CPubKey& pubkey, int& nHeightRet)
{
    AssertLockHeld(cs_main);

    Coin coin;
    if (!GetUTXOCoin(outpoint, coin)) {
        return COLLATERAL_UTXO_NOT_FOUND;
    }

    if (coin.out.nValue != Params().GetConsensus().nMasternodeCollateral) {
        return COLLATERAL_INVALID_AMOUNT;
    }

    if (pubkey == CPubKey() || coin.out.scriptPubKey != GetScriptForDestination(CScriptID(GetScriptForDestination(WitnessV0KeyHash(pubkey.GetID()))))) {
        return COLLATERAL_INVALID_PUBKEY;
    }

    nHeightRet = coin.nHeight;
    return COLLATERAL_OK;
}

bool CMasternode::IsPoSeVerified() const
{ 
    return nPoSeBanScore <= -Params().GetConsensus().nMasternodePoseBanMaxScore; 
}

void CMasternode::Check(bool fForce)
{
    AssertLockHeld(cs_main);
    LOCK(cs);

    if (ShutdownRequested()) return;

    if (!fForce && (GetTime() - nTimeLastChecked < Params().GetConsensus().nMasternodeCheckSeconds)) return;
    nTimeLastChecked = GetTime();

    LogPrintG(BCLogLevel::LOG_INFO, BCLog::MN, "[Masternodes] CMasternode::Check -- Masternode %s is in %s state\n", outpoint.ToStringShort(), GetStateString());

    //once spent, stop doing the checks
    if (IsOutpointSpent()) return;

    // int nHeight = 0;
    if (!fUnitTest) {
        Coin coin;
        if (!GetUTXOCoin(outpoint, coin)) {
            nActiveState = MASTERNODE_OUTPOINT_SPENT;
            LogPrintG(BCLogLevel::LOG_NOTICE, BCLog::MN, "[Masternodes] CMasternode::Check -- Failed to find Masternode UTXO, masternode=%s\n", outpoint.ToStringShort());
            return;
        }
        else
        {
            activationBlockHeight = coin.nHeight;
        }       

        // nHeight = chainActive.Height();
    }

    if (IsPoSeBanned()) {
        // Re-enable pose_banned masternodes
        //if (nHeight < nPoSeBanHeight) return; // too early?
        // Otherwise give it a chance to proceed further to do all the usual checks and to change its state.
        // Masternode still will be on the edge and can be banned back easily if it keeps ignoring mnverify
        // or connect attempts. Will require few mnverify messages to strengthen its position in mn list.
        LogPrintG(BCLogLevel::LOG_NOTICE, BCLog::MN, "[Masternodes] CMasternode::Check -- Masternode %s is unbanned and back in list now\n", outpoint.ToStringShort());
        DecreasePoSeBanScore();
    } else if (nPoSeBanScore >= Params().GetConsensus().nMasternodePoseBanMaxScore) {
        // Dont use pose_ban
        //nActiveState = MASTERNODE_POSE_BAN;
        // ban for the whole payment cycle
        //nPoSeBanHeight = nHeight + mnodeman.size();
        //LogPrintG(BCLogLevel::LOG_NOTICE, BCLog::MN, "[Masternodes] CMasternode::Check -- Masternode %s is banned till block %d now\n", outpoint.ToStringShort(), nPoSeBanHeight);
        return;
    }

    int nActiveStatePrev = nActiveState;
    bool fOurMasternode = fMasternodeMode && activeMasternode.pubKeyMasternode == pubKeyMasternode;

    // masternode doesn't meet payment protocol requirements ...
    bool fRequireUpdate = nProtocolVersion < mnpayments.GetMinMasternodePaymentsProto() ||
    // or it's our own node and we just updated it to the new protocol but we are still waiting for activation ...
            (fOurMasternode && nProtocolVersion < PROTOCOL_VERSION);

    if (fRequireUpdate) {
        nActiveState = MASTERNODE_UPDATE_REQUIRED;
        if (nActiveStatePrev != nActiveState) {
            LogPrintG(BCLogLevel::LOG_NOTICE, BCLog::MN, "[Masternodes] CMasternode::Check -- Masternode %s is in %s state now\n", outpoint.ToStringShort(), GetStateString());
        }
        return;
    }

    // keep old masternodes on start, give them a chance to receive updates...
    bool fWaitForPing = !masternodeSync.IsMasternodeListSynced() && !IsPingedWithin(Params().GetConsensus().nMasternodeMinMnpSeconds);

    if (fWaitForPing && !fOurMasternode) {
        // ...but if it was already expired before the initial check - return right away
        if (IsExpired() || IsSentinelPingExpired() || IsNewStartRequired()) {
            LogPrintG(BCLogLevel::LOG_NOTICE, BCLog::MN, "[Masternodes] CMasternode::Check -- Masternode %s is in %s state, waiting for ping\n", outpoint.ToStringShort(), GetStateString());
            return;
        }
    }

    // don't expire if we are still in "waiting for ping" mode unless it's our own masternode
    if (!fWaitForPing || fOurMasternode) {

        if (!IsPingedWithin(Params().GetConsensus().nMasternodeNewStartRequiredSeconds)) {
            nActiveState = MASTERNODE_NEW_START_REQUIRED;
            if (nActiveStatePrev != nActiveState) {
                LogPrintG(BCLogLevel::LOG_NOTICE, BCLog::MN, "[Masternodes] CMasternode::Check -- Masternode %s is in %s state now\n", outpoint.ToStringShort(), GetStateString());
            }
            return;
        }

        if (!IsPingedWithin(Params().GetConsensus().nMasternodeExpirationSeconds)) {
            nActiveState = MASTERNODE_EXPIRED;
            if (nActiveStatePrev != nActiveState) {
                LogPrintG(BCLogLevel::LOG_NOTICE, BCLog::MN, "[Masternodes] CMasternode::Check -- Masternode %s is in %s state now\n", outpoint.ToStringShort(), GetStateString());
            }
            return;
        }

        // part 1: expire based on genesisd ping
        bool fSentinelPingActive = masternodeSync.IsSynced() && mnodeman.IsSentinelPingActive();
        bool fSentinelPingExpired = fSentinelPingActive && !IsPingedWithin(Params().GetConsensus().nMasternodeSentinelPingMaxSeconds);
        LogPrintG(BCLogLevel::LOG_DEBUG, BCLog::MN, "[Masternodes] CMasternode::Check -- outpoint=%s, GetAdjustedTime()=%d, fSentinelPingExpired=%d\n",
                outpoint.ToStringShort(), GetAdjustedTime(), fSentinelPingExpired);

        if (fSentinelPingExpired) {
            nActiveState = MASTERNODE_SENTINEL_PING_EXPIRED;
            if (nActiveStatePrev != nActiveState) {
                LogPrintG(BCLogLevel::LOG_NOTICE, BCLog::MN, "[Masternodes] CMasternode::Check -- Masternode %s is in %s state now\n", outpoint.ToStringShort(), GetStateString());
            }
            return;
        }
    }
    
    // We require MNs to be in PRE_ENABLED until they either start to expire or receive a ping and go into ENABLED state
    // Works on mainnet/testnet only and not the case on regtest.
    if (Params().NetworkIDString() != CBaseChainParams::REGTEST) {
         if (lastPing.sigTime - sigTime < Params().GetConsensus().nMasternodeMinMnpSeconds) {
             nActiveState = MASTERNODE_PRE_ENABLED;
             if (nActiveStatePrev != nActiveState) {
                LogPrintG(BCLogLevel::LOG_NOTICE, BCLog::MN, "[Masternodes] CMasternode::Check -- Masternode %s is in %s state now\n", outpoint.ToStringShort(), GetStateString());
            }
            return;
        }
    }

    if (!fWaitForPing || fOurMasternode) {
        // part 2: expire based on sentinel info
        bool fSentinelPingActive = masternodeSync.IsSynced() && mnodeman.IsSentinelPingActive();
        bool fSentinelPingExpired = fSentinelPingActive && !lastPing.fSentinelIsCurrent;

        LogPrintG(BCLogLevel::LOG_DEBUG, BCLog::MN, "[Masternodes] CMasternode::Check -- outpoint=%s, GetAdjustedTime()=%d, fSentinelPingExpired=%d\n",
                outpoint.ToStringShort(), GetAdjustedTime(), fSentinelPingExpired);

        if (fSentinelPingExpired) {
            nActiveState = MASTERNODE_SENTINEL_PING_EXPIRED;
            if (nActiveStatePrev != nActiveState) {
                LogPrintG(BCLogLevel::LOG_NOTICE, BCLog::MN, "[Masternodes] CMasternode::Check -- Masternode %s is in %s state now\n", outpoint.ToStringShort(), GetStateString());
            }
            return;
        }
    }

    nActiveState = MASTERNODE_ENABLED; // OK
    if (nActiveStatePrev != nActiveState) {
        LogPrintG(BCLogLevel::LOG_NOTICE, BCLog::MN, "[Masternodes] CMasternode::Check -- Masternode %s is in %s state now\n", outpoint.ToStringShort(), GetStateString());
    }
}

bool CMasternode::IsValidNetAddr()
{
    return IsValidNetAddr(addr);
}

bool CMasternode::IsValidNetAddr(CService addrIn)
{
    // TODO: regtest is fine with any addresses for now,
    // should probably be a bit smarter if one day we start to implement tests for this
    return Params().NetworkIDString() == CBaseChainParams::REGTEST ||
            (addrIn.IsIPv4() && IsReachable(addrIn) && addrIn.IsRoutable());
}

void CMasternode::IncreasePoSeBanScore() 
{ 
    if (nPoSeBanScore < Params().GetConsensus().nMasternodePoseBanMaxScore)
    {
        nPoSeBanScore++;
    }  
}

void CMasternode::DecreasePoSeBanScore() 
{ 
    if (nPoSeBanScore > -Params().GetConsensus().nMasternodePoseBanMaxScore)
    {
        nPoSeBanScore--;
    }  
}

void CMasternode::PoSeBan() 
{ 
    nPoSeBanScore = Params().GetConsensus().nMasternodePoseBanMaxScore; 
}


masternode_info_t CMasternode::GetInfo() const
{
    masternode_info_t info{*this};
    info.nTimeLastPing = lastPing.sigTime;
    info.fInfoValid = true;
    return info;
}

std::string CMasternode::StateToString(int nStateIn)
{
    switch(nStateIn) {
        case MASTERNODE_PRE_ENABLED:            return "PRE_ENABLED";
        case MASTERNODE_ENABLED:                return "ENABLED";
        case MASTERNODE_EXPIRED:                return "EXPIRED";
        case MASTERNODE_OUTPOINT_SPENT:         return "OUTPOINT_SPENT";
        case MASTERNODE_UPDATE_REQUIRED:        return "UPDATE_REQUIRED";
        case MASTERNODE_SENTINEL_PING_EXPIRED:  return "SENTINEL_PING_EXPIRED";
        case MASTERNODE_NEW_START_REQUIRED:     return "NEW_START_REQUIRED";
        case MASTERNODE_POSE_BAN:               return "POSE_BAN";
        default:                                return "UNKNOWN";
    }
}

std::string CMasternode::GetStateString() const
{
    return StateToString(nActiveState);
}

std::string CMasternode::GetStatus() const
{
    // TODO: return smth a bit more human readable here
    return GetStateString();
}

void CMasternode::UpdateLastPaid(const CBlockIndex *pindex, int nMaxBlocksToScanBack)
{
    if (!pindex) return;
    
    const CBlockIndex *pindexActive = chainActive.Tip();
    assert(pindexActive);

    CDiskBlockPos blockPos = pindexActive->GetBlockPos();

    CScript mnpayee = GetScriptForDestination(CScriptID(GetScriptForDestination(WitnessV0KeyHash(pubKeyCollateralAddress.GetID()))));
    //LogPrintG(BCLogLevel::LOG_NOTICE, BCLog::MN, "[Masternodes] CMasternode::UpdateLastPaidBlock -- searching for block with payment to %s\n", outpoint.ToStringShort());

    LOCK(cs_mapMasternodeBlocks);

    for (int i = 0; pindexActive->nHeight > nBlockLastPaidPrimary && i < nMaxBlocksToScanBack; i++) {
        size_t checkitOut = mnpayments.mapMasternodeBlocksPrimary.count(pindexActive->nHeight);
        bool hazIt = mnpayments.mapMasternodeBlocksPrimary[pindexActive->nHeight].HasPayeeWithVotes(mnpayee, 2);
        int mnCount = mnodeman.CountMasternodes(-1);

        if ((mnCount > 2 && checkitOut && hazIt) || (mnCount <= 2))
        {
            if (blockPos.IsNull() == true) {
                return;
            }

            CBlock block;
            if (!ReadBlockFromDisk(block, blockPos, Params().GetConsensus()))
            {
                continue;
            }
            
            // Adding this as a sanity check... as we specify the order of the payments:
            // This can be calculated dynamically, but a fixed value is sufficient for now, 
            // as this method is called a lot.
            // 0 = Miner
            // 1-5 = Founders
            // 6 = Primary Masternode
            // 7 = First Secondary Masternode Payment (may receive more than the other secondaries)
            // 8+ = The remainder of the secondaries payments and pool deductions etc.
            int primaryMnPaymentPosition = 6; // starting from 0

            CAmount nMasternodePaymentPrimary = GetMasternodePayments(pindexActive->nHeight, activationBlockHeight, block.vtx[0]->GetValueOut());
            double readableMnPayValue = nMasternodePaymentPrimary / COIN;

            int positionTracker = 0;
            for (const auto& txout : block.vtx[0]->vout)
            {
                CAmount txValue = txout.nValue;
                bool payeeMatch = mnpayee == txout.scriptPubKey;
                bool valueMatch = nMasternodePaymentPrimary == txValue;
                double readableTxValue = txValue / COIN;
                if (payeeMatch)
                {
                    // make debugging easier
                    std::string mnPayeeAddressString = EncodeDestination(CScriptID(GetScriptForDestination(WitnessV0KeyHash(pubKeyCollateralAddress.GetID()))));
                    if (valueMatch)
                    {
                        nBlockLastPaidPrimary = pindexActive->nHeight;
                        nTimeLastPaidPrimary = pindexActive->nTime;
                        LogPrintG(BCLogLevel::LOG_INFO, BCLog::MN, "[Masternodes] CMasternode::UpdateLastPaidBlock -- searching for block with primary payment to %s -- found new %d\n", outpoint.ToStringShort(), nBlockLastPaidPrimary);
                        return;
                    }
                    // Check that we have not missed something...
                    else if (positionTracker == primaryMnPaymentPosition)
                    {
                        // Living the dream... masternode was paid as a primary too recently
                        if (pindexActive->nHeight - nBlockLastPaidPrimary < mnCount)
                        {
                            LogPrintG(BCLogLevel::LOG_WARNING, BCLog::MN, "[Masternodes] CMasternode::UpdateLastPaidBlock -- Bad value in masternode payment. %s -- in block %d was paid in block %d when there are %d masternodes\n", outpoint.ToStringShort(), pindexActive->nHeight, nBlockLastPaidPrimary, mnCount);
                        }
                        // Still mark it as primary paid, even if the value is off :S
                        nBlockLastPaidPrimary = pindexActive->nHeight;
                        nTimeLastPaidPrimary = pindexActive->nTime;
                        // this is badong... let someone know (If you don't know what badong is, watch https://www.youtube.com/watch?v=O6_P_ZWwJ3Q)
                        LogPrintG(BCLogLevel::LOG_ERROR, BCLog::MN, "[Masternodes] CMasternode::UpdateLastPaidBlock -- Bad value in masternode payment. %s -- in block %d pays %f instead of %f\n", outpoint.ToStringShort(), pindexActive->nHeight, readableTxValue, readableMnPayValue);
                        return;
                    }
                    else if (positionTracker > primaryMnPaymentPosition)
                    {
                        // This is a bit fuzzy for my liking, but the logic:
                        // * This is the coinbase transaction
                        // * I am a masternode
                        // * I am being paid in the coinbase tx, as a mn, but it is not as the primary
                        // Should suffice to substantiate the claim that this is a secondary masternode payment to me
                        nBlockLastPaidSecondary = pindexActive->nHeight;
                        nTimeLastPaidSecondary = pindexActive->nTime;
                        LogPrintG(BCLogLevel::LOG_INFO, BCLog::MN, "[Masternodes] CMasternode::UpdateLastPaidBlock -- searching for block with secondary payment to %s -- found new %d\n", outpoint.ToStringShort(), nBlockLastPaidSecondary);
                        return;
                    }
                    else
                    {
                        // Reaching this code means that:
                        // There is a payment in the coinbase, to a masternode address that is:
                        // either a miner address
                        // which is interesting, but not useful (other than for debugging)
                        bool isMasternodeMiner = positionTracker == 0;
                        // or it could be among the founder's payments... which means the block payments are really really broken
                        bool isMasternodePaymentAmongFounders = positionTracker > 0 && positionTracker < primaryMnPaymentPosition;

                        if (isMasternodeMiner)
                        {
                            // Miner and masternode address...
                            LogPrintG(BCLogLevel::LOG_DEBUG, BCLog::MN, "[Masternodes] CMasternode::UpdateLastPaidBlock -- %s is mining to their masternode address\n", outpoint.ToStringShort());
                        }
                        else if (isMasternodePaymentAmongFounders)
                        {
                            // Barring time travel this is not possible
                            LogPrintG(BCLogLevel::LOG_ERROR, BCLog::MN, "[Masternodes] CMasternode::UpdateLastPaidBlock -- %s is is a founder address masternode address\n", outpoint.ToStringShort());
                            // kill it with fire....
                            assert(!isMasternodePaymentAmongFounders);
                        }
                        
                    }
                    
                }    
                positionTracker++;            
            }
        }

        if (pindexActive->pprev == nullptr) { assert(pindexActive); break; }
        pindexActive = pindexActive->pprev;
    }

    // Last payment for this masternode wasn't found in latest mnpayments blocks
    // or it was found in mnpayments blocks but wasn't found in the blockchain.
    LogPrintG(BCLogLevel::LOG_DEBUG, BCLog::MN, "[Masternodes] CMasternode::UpdateLastPaidBlock -- searching for block with payment to %s -- keeping old %d\n", outpoint.ToStringShort(), nBlockLastPaidPrimary);
}

//#ifdef ENABLE_WALLET
bool CMasternodeBroadcast::Create(const std::string& strService, const std::string& strKeyMasternode, const std::string& strTxHash, const std::string& strOutputIndex, std::string& strErrorRet, CMasternodeBroadcast &mnbRet, bool fOffline)
{
    COutPoint outpoint;
    CPubKey pubKeyCollateralAddressNew;
    CKey keyCollateralAddressNew;
    CPubKey pubKeyMasternodeNew;
    CKey keyMasternodeNew;

    auto Log = [&strErrorRet](std::string sErr)->bool
    {
        strErrorRet = sErr;
        return false;
    };

    // Wait for sync to finish because mnb simply won't be relayed otherwise
    if (!fOffline && !masternodeSync.IsSynced())
        return Log("Sync in progress. Must wait until sync is complete to start Masternode");

    if (!CMessageSigner::GetKeysFromSecret(strKeyMasternode, keyMasternodeNew, pubKeyMasternodeNew))
        return Log(strprintf("Invalid masternode key %s", strKeyMasternode));

    const COutPoint outpt(uint256S(strTxHash), std::stoi(strOutputIndex));

    for (CWalletRef pwallet : vpwallets) {
        LOCK2(cs_main, pwallet->cs_wallet);
        pwallet->UnlockCoin(outpt);
        if (pwallet->GetMasternodeOutpointAndKeys(outpoint, pubKeyCollateralAddressNew, keyCollateralAddressNew, strTxHash, strOutputIndex)) {
            pwallet->LockCoin(outpt);
        } else {
            return Log(strprintf("Could not allocate outpoint %s:%s for masternode %s", strTxHash, strOutputIndex, strService));
        }
    }

    CService service;
    if (!Lookup(strService.c_str(), service, 0, false))
        return Log(strprintf("Invalid address %s for masternode.", strService));
    int mainnetDefaultPort = CreateChainParams(CBaseChainParams::MAIN)->GetDefaultPort();
    if (Params().NetworkIDString() == CBaseChainParams::MAIN) {
        if (service.GetPort() != mainnetDefaultPort)
            return Log(strprintf("Invalid port %u for masternode %s, only %d is supported on mainnet.", service.GetPort(), strService, mainnetDefaultPort));
    } else if (service.GetPort() == mainnetDefaultPort)
        return Log(strprintf("Invalid port %u for masternode %s, %d is the only supported on mainnet.", service.GetPort(), strService, mainnetDefaultPort));

    return Create(outpoint, service, keyCollateralAddressNew, pubKeyCollateralAddressNew, keyMasternodeNew, pubKeyMasternodeNew, strErrorRet, mnbRet);
}

bool CMasternodeBroadcast::Create(const COutPoint& outpoint, const CService& service, const CKey& keyCollateralAddressNew, const CPubKey& pubKeyCollateralAddressNew, const CKey& keyMasternodeNew, const CPubKey& pubKeyMasternodeNew, std::string &strErrorRet, CMasternodeBroadcast &mnbRet)
{
    // wait for reindex and/or import to finish
    if (fImporting || fReindex) return false;

    LogPrintG(BCLogLevel::LOG_NOTICE, BCLog::MN, "[Masternodes] CMasternodeBroadcast::Create -- pubKeyCollateralAddressNew = %s, pubKeyMasternodeNew.GetID() = %s\n",
             EncodeDestination(CScriptID(GetScriptForDestination(WitnessV0KeyHash(pubKeyCollateralAddressNew.GetID())))),
             EncodeDestination(CScriptID(GetScriptForDestination(WitnessV0KeyHash(pubKeyMasternodeNew.GetID())))));

    auto Log = [&strErrorRet,&mnbRet](std::string sErr)->bool
    {
        strErrorRet = sErr;
        mnbRet = CMasternodeBroadcast();
        return false;
    };

    CMasternodePing mnp(outpoint);
    if (!mnp.Sign(keyMasternodeNew, pubKeyMasternodeNew))
        return Log(strprintf("Failed to sign ping, masternode=%s", outpoint.ToStringShort()));

    mnbRet = CMasternodeBroadcast(service, outpoint, pubKeyCollateralAddressNew, pubKeyMasternodeNew, PROTOCOL_VERSION);

    if (!mnbRet.IsValidNetAddr())
        return Log(strprintf("Invalid IP address, masternode=%s", outpoint.ToStringShort()));

    mnbRet.lastPing = mnp;
    if (!mnbRet.Sign(keyCollateralAddressNew))
        return Log(strprintf("Failed to sign broadcast, masternode=%s", outpoint.ToStringShort()));

    return true;
}
//#endif // ENABLE_WALLET

bool CMasternodeBroadcast::SimpleCheck(int& nDos)
{
    nDos = 0;
    
    AssertLockHeld(cs_main);

    // make sure addr is valid
    if (!IsValidNetAddr()) {
        LogPrintG(BCLogLevel::LOG_ERROR, BCLog::MN, "[Masternodes] CMasternodeBroadcast::SimpleCheck -- Invalid addr, rejected: masternode=%s  addr=%s\n",
                    outpoint.ToStringShort(), addr.ToString());
        return false;
    }

    // make sure signature isn't in the future (past is OK)
    if (sigTime > GetAdjustedTime() + 60 * 60) {
        LogPrintG(BCLogLevel::LOG_WARNING, BCLog::MN, "[Masternodes] CMasternodeBroadcast::SimpleCheck -- Signature rejected, too far into the future: masternode=%s\n", outpoint.ToStringShort());
        nDos = 1;
        return false;
    }

    // empty ping or incorrect sigTime/unknown blockhash
    if (!lastPing || !lastPing.SimpleCheck(nDos)) {
        // one of us is probably forked or smth, just mark it as expired and check the rest of the rules
        nActiveState = MASTERNODE_EXPIRED;
    }

    if (nProtocolVersion < mnpayments.GetMinMasternodePaymentsProto()) {
        LogPrintG(BCLogLevel::LOG_WARNING, BCLog::MN, "[Masternodes] CMasternodeBroadcast::SimpleCheck -- outdated Masternode: masternode=%s  nProtocolVersion=%d\n", outpoint.ToStringShort(), nProtocolVersion);
        nActiveState = MASTERNODE_UPDATE_REQUIRED;
    }

    CScript pubkeyScript;
    pubkeyScript = GetScriptForDestination(pubKeyCollateralAddress.GetID());

    if (pubkeyScript.size() != 25) {
        LogPrintG(BCLogLevel::LOG_WARNING, BCLog::MN, "[Masternodes] CMasternodeBroadcast::SimpleCheck -- pubKeyCollateralAddress has the wrong size\n");
        nDos = 100;
        return false;
    }

    CScript pubkeyScript2;
    pubkeyScript2 = GetScriptForDestination(pubKeyMasternode.GetID());

    if (pubkeyScript2.size() != 25) {
        LogPrintG(BCLogLevel::LOG_WARNING, BCLog::MN, "[Masternodes] CMasternodeBroadcast::SimpleCheck -- pubKeyMasternode has the wrong size\n");
        nDos = 100;
        return false;
    }

    int mainnetDefaultPort = CreateChainParams(CBaseChainParams::MAIN)->GetDefaultPort();
    if (Params().NetworkIDString() == CBaseChainParams::MAIN) {
        if (addr.GetPort() != mainnetDefaultPort) return false;
    } else if (addr.GetPort() == mainnetDefaultPort) return false;

    return true;
}

bool CMasternodeBroadcast::Update(CMasternode* pmn, int& nDos, CConnman& connman)
{
    nDos = 0;
    
    AssertLockHeld(cs_main);

    if (pmn->sigTime == sigTime && !fRecovery) {
        // mapSeenMasternodeBroadcast in CMasternodeMan::CheckMnbAndUpdateMasternodeList should filter legit duplicates
        // but this still can happen if we just started, which is ok, just do nothing here.
        return false;
    }

    // this broadcast is older than the one that we already have - it's bad and should never happen
    // unless someone is doing something fishy
    if (pmn->sigTime > sigTime) {
        LogPrintG(BCLogLevel::LOG_WARNING, BCLog::MN, "[Masternodes] CMasternodeBroadcast::Update -- Bad sigTime %d (existing broadcast is at %d) for Masternode %s %s\n",
                      sigTime, pmn->sigTime, outpoint.ToStringShort(), addr.ToString());
        return false;
    }

    pmn->Check();

    // masternode is banned by PoSe
    if (pmn->IsPoSeBanned()) {
        LogPrintG(BCLogLevel::LOG_WARNING, BCLog::MN, "[Masternodes] CMasternodeBroadcast::Update -- Banned by PoSe, masternode=%s\n", outpoint.ToStringShort());
        return false;
    }

    // IsVnAssociatedWithPubkey is validated once in CheckOutpoint, after that they just need to match
    if (pmn->pubKeyCollateralAddress != pubKeyCollateralAddress) {
        LogPrintG(BCLogLevel::LOG_WARNING, BCLog::MN, "[Masternodes] CMasternodeBroadcast::Update -- Got mismatched pubKeyCollateralAddress and outpoint\n");
        nDos = 33;
        return false;
    }

    if (!CheckSignature(nDos)) {
        LogPrintG(BCLogLevel::LOG_WARNING, BCLog::MN, "[Masternodes] CMasternodeBroadcast::Update -- CheckSignature() failed, masternode=%s\n", outpoint.ToStringShort());
        return false;
    }

    // if ther was no masternode broadcast recently or if it matches our Masternode privkey...
    if (!pmn->IsBroadcastedWithin(Params().GetConsensus().nMasternodeMinMnbSeconds) || (fMasternodeMode && pubKeyMasternode == activeMasternode.pubKeyMasternode)) {
        // take the newest entry
        LogPrintG(BCLogLevel::LOG_NOTICE, BCLog::MN, "[Masternodes] CMasternodeBroadcast::Update -- Got UPDATED Masternode entry: addr=%s\n", addr.ToString());
        if (pmn->UpdateFromNewBroadcast(*this, connman)) {
            pmn->Check();
            Relay(connman);
        }
        masternodeSync.BumpAssetLastTime("CMasternodeBroadcast::Update");
    }

    return true;
}

bool CMasternodeBroadcast::CheckOutpoint(int& nDos)
{
    // we are a masternode with the same outpoint (i.e. already activated) and this mnb is ours (matches our Masternode privkey)
    // so nothing to do here for us
    if (fMasternodeMode && outpoint == activeMasternode.outpoint && pubKeyMasternode == activeMasternode.pubKeyMasternode) {
        return false;
    }

    AssertLockHeld(cs_main);

    int nHeight;
    CollateralStatus err = CheckCollateral(outpoint, pubKeyCollateralAddress, nHeight);
    if (err == COLLATERAL_UTXO_NOT_FOUND) {
        LogPrintG(BCLogLevel::LOG_ERROR, BCLog::MN, "[Masternodes] CMasternodeBroadcast::CheckOutpoint -- Failed to find Masternode UTXO, masternode=%s\n", outpoint.ToStringShort());
        return false;
    }

    if (err == COLLATERAL_INVALID_AMOUNT) {
        LogPrintG(BCLogLevel::LOG_WARNING, BCLog::MN, "[Masternodes] CMasternodeBroadcast::CheckOutpoint -- Masternode UTXO should have 750000 GENX, masternode=%s\n", outpoint.ToStringShort());
        nDos = 33;
        return false;
    }

    if (err == COLLATERAL_INVALID_PUBKEY) {
        LogPrintG(BCLogLevel::LOG_WARNING, BCLog::MN, "[Masternodes] CMasternodeBroadcast::CheckOutpoint -- Masternode UTXO should match pubKeyCollateralAddress, masternode=%s\n", outpoint.ToStringShort());
        nDos = 33;
        return false;
    }

    if (chainActive.Height() - nHeight + 1 < Params().GetConsensus().nMasternodeMinimumConfirmations) {
        LogPrintG(BCLogLevel::LOG_WARNING, BCLog::MN, "[Masternodes] CMasternodeBroadcast::CheckOutpoint -- Masternode UTXO must have at least %d confirmations, masternode=%s\n",
                Params().GetConsensus().nMasternodeMinimumConfirmations, outpoint.ToStringShort());
        // UTXO is legit but has not enough confirmations.
        // Maybe we miss few blocks, let this mnb be checked again later.
        mnodeman.mapSeenMasternodeBroadcast.erase(GetHash());
        return false;
    }

    LogPrintG(BCLogLevel::LOG_INFO, BCLog::MN, "[Masternodes] CMasternodeBroadcast::CheckOutpoint -- Masternode UTXO verified\n");

    // Verify that sig time is legit, should be at least not earlier than the timestamp of the block
    // at which collateral became nMasternodeMinimumConfirmations blocks deep.
    // NOTE: this is not accurate because block timestamp is NOT guaranteed to be 100% correct one.
    CBlockIndex* pRequiredConfIndex = chainActive[nHeight + Params().GetConsensus().nMasternodeMinimumConfirmations - 1]; // block where tx got nMasternodeMinimumConfirmations
    if (pRequiredConfIndex->GetBlockTime() > sigTime) {
        LogPrintG(BCLogLevel::LOG_NOTICE, BCLog::MN, "[Masternodes] CMasternodeBroadcast::CheckOutpoint -- Bad sigTime %d (%d conf block is at %d) for Masternode %s %s\n",
                  sigTime, Params().GetConsensus().nMasternodeMinimumConfirmations, pRequiredConfIndex->GetBlockTime(), outpoint.ToStringShort(), addr.ToString());
        return false;
    }

    if (!CheckSignature(nDos)) {
        LogPrintG(BCLogLevel::LOG_ERROR, BCLog::MN, "[Masternodes] CMasternodeBroadcast::CheckOutpoint -- CheckSignature() failed, masternode=%s\n", outpoint.ToStringShort());
        return false;
    }

    // remember the block hash when collateral for this masternode had minimum required confirmations
    nCollateralMinConfBlockHash = pRequiredConfIndex->GetBlockHash();
    activationBlockHeight = pRequiredConfIndex->nHeight;

    return true;
}

uint256 CMasternodeBroadcast::GetHash() const
{
    // Note: doesn't match serialization

    CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
    ss << outpoint << uint8_t{} << 0xffffffff; // adding dummy values here to match old hashing format
    ss << pubKeyCollateralAddress;
    ss << sigTime;
    return ss.GetHash();
}

uint256 CMasternodeBroadcast::GetSignatureHash() const
{
    // TODO: replace with "return SerializeHash(*this);" after migration to 70209
    CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
    ss << outpoint;
    ss << addr;
    ss << pubKeyCollateralAddress;
    ss << pubKeyMasternode;
    ss << sigTime;
    ss << nProtocolVersion;
    return ss.GetHash();
}

bool CMasternodeBroadcast::Sign(const CKey& keyCollateralAddress)
{
    std::string strError;

    sigTime = GetAdjustedTime();

    if (chainActive.Height() > Params().GetConsensus().nMasternodeSignHashThreshold) {
        uint256 hash = GetSignatureHash();
        if (!CHashSigner::SignHash(hash, keyCollateralAddress, vchSig)) {
            LogPrintG(BCLogLevel::LOG_ERROR, BCLog::MN, "[Masternodes] CMasternodeBroadcast::Sign -- SignHash() failed\n");
            return false;
        }
        if (!CHashSigner::VerifyHash(hash, pubKeyCollateralAddress, vchSig, strError)) {
            LogPrintG(BCLogLevel::LOG_ERROR, BCLog::MN, "[Masternodes] CMasternodeBroadcast::Sign -- VerifyMessage() failed, error: %s\n", strError);
            return false;
        }
    } else {
        std::string strMessage = addr.ToString() + boost::lexical_cast<std::string>(sigTime) +
                        pubKeyCollateralAddress.GetID().ToString() + pubKeyMasternode.GetID().ToString() +
                        boost::lexical_cast<std::string>(nProtocolVersion);

        if (!CMessageSigner::SignMessage(strMessage, vchSig, keyCollateralAddress)) {
            LogPrintG(BCLogLevel::LOG_ERROR, BCLog::MN, "[Masternodes] CMasternodeBroadcast::Sign -- SignMessage() failed\n");
            return false;
        }

        if (!CMessageSigner::VerifyMessage(pubKeyCollateralAddress, vchSig, strMessage, strError)) {
            LogPrintG(BCLogLevel::LOG_ERROR, BCLog::MN, "[Masternodes] CMasternodeBroadcast::Sign -- VerifyMessage() failed, error: %s\n", strError);
            return false;
        }
    }

    return true;
}

bool CMasternodeBroadcast::CheckSignature(int& nDos) const
{
    std::string strError = "";
    nDos = 0;

    if (chainActive.Height() > Params().GetConsensus().nMasternodeSignHashThreshold) {
        uint256 hash = GetSignatureHash();
        if (!CHashSigner::VerifyHash(hash, pubKeyCollateralAddress, vchSig, strError)) {
            // maybe it's in old format
            std::string strMessage = addr.ToString() + boost::lexical_cast<std::string>(sigTime) +
                            pubKeyCollateralAddress.GetID().ToString() + pubKeyMasternode.GetID().ToString() +
                            boost::lexical_cast<std::string>(nProtocolVersion);

            if (!CMessageSigner::VerifyMessage(pubKeyCollateralAddress, vchSig, strMessage, strError)){
                // nope, not in old format either
                LogPrintG(BCLogLevel::LOG_ERROR, BCLog::MN, "[Masternodes] CMasternodeBroadcast::CheckSignature -- Got bad Masternode announce signature, error: %s\n", strError);
                nDos = 100;
                return false;
            }
        }
    } else {
        std::string strMessage = addr.ToString() + boost::lexical_cast<std::string>(sigTime) +
                        pubKeyCollateralAddress.GetID().ToString() + pubKeyMasternode.GetID().ToString() +
                        boost::lexical_cast<std::string>(nProtocolVersion);

        if (!CMessageSigner::VerifyMessage(pubKeyCollateralAddress, vchSig, strMessage, strError)){
            LogPrintG(BCLogLevel::LOG_ERROR, BCLog::MN, "[Masternodes] CMasternodeBroadcast::CheckSignature -- Got bad Masternode announce signature, error: %s\n", strError);
            nDos = 100;
            return false;
        }
    }

    return true;
}

void CMasternodeBroadcast::Relay(CConnman& connman) const
{
    // Do not relay until fully synced
    if (!masternodeSync.IsSynced()) {
        LogPrintG(BCLogLevel::LOG_WARNING, BCLog::MN, "[Masternodes] CMasternodeBroadcast::Relay -- won't relay until fully synced\n");
        return;
    }

    CInv inv(MSG_MASTERNODE_ANNOUNCE, GetHash());
    connman.RelayInv(inv);
}

uint256 CMasternodePing::GetHash() const
{
    CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
    if (chainActive.Height() > Params().GetConsensus().nMasternodeSignHashThreshold) {
        ss << masternodeOutpoint;
        ss << blockHash;
        ss << sigTime;
        ss << fSentinelIsCurrent;
        ss << nSentinelVersion;
        ss << nDaemonVersion;
    } else {
        // Note: doesn't match serialization

        ss << masternodeOutpoint << uint8_t{} << 0xffffffff; // adding dummy values here to match old hashing format
        ss << sigTime;
    }
    return ss.GetHash();
}

uint256 CMasternodePing::GetSignatureHash() const
{
    return GetHash();
}

bool CMasternodePing::IsExpired() const
{ 
    return GetAdjustedTime() - sigTime > Params().GetConsensus().nMasternodeNewStartRequiredSeconds; 
}

CMasternodePing::CMasternodePing(const COutPoint& outpoint)
{
    LOCK(cs_main);
    if (!chainActive.Tip() || chainActive.Height() < 12) return;

    masternodeOutpoint = outpoint;
    blockHash = chainActive[chainActive.Height() - 12]->GetBlockHash();
    sigTime = GetAdjustedTime();
    nDaemonVersion = CLIENT_VERSION;
}

bool CMasternodePing::Sign(const CKey& keyMasternode, const CPubKey& pubKeyMasternode)
{
    std::string strError;

    sigTime = GetAdjustedTime();

    if (chainActive.Height() > Params().GetConsensus().nMasternodeSignHashThreshold) {
        uint256 hash = GetSignatureHash();
        if (!CHashSigner::SignHash(hash, keyMasternode, vchSig)) {
            LogPrintG(BCLogLevel::LOG_ERROR, BCLog::MN, "[Masternodes] CMasternodePing::Sign -- SignHash() failed\n");
            return false;
        }

        if (!CHashSigner::VerifyHash(hash, pubKeyMasternode, vchSig, strError)) {
            LogPrintG(BCLogLevel::LOG_ERROR, BCLog::MN, "[Masternodes] CMasternodePing::Sign -- VerifyHash() failed, error: %s\n", strError);
            return false;
        }
    } else {
        std::string strMessage = CTxIn(masternodeOutpoint).ToString() + blockHash.ToString() +
                    boost::lexical_cast<std::string>(sigTime);

        if (!CMessageSigner::SignMessage(strMessage, vchSig, keyMasternode)) {
            LogPrintG(BCLogLevel::LOG_ERROR, BCLog::MN, "[Masternodes] CMasternodePing::Sign -- SignMessage() failed\n");
            return false;
        }

        if (!CMessageSigner::VerifyMessage(pubKeyMasternode, vchSig, strMessage, strError)) {
            LogPrintG(BCLogLevel::LOG_ERROR, BCLog::MN, "[Masternodes] CMasternodePing::Sign -- VerifyMessage() failed, error: %s\n", strError);
            return false;
        }
    }

    return true;
}

bool CMasternodePing::CheckSignature(const CPubKey& pubKeyMasternode, int &nDos) const
{
    std::string strError = "";
    nDos = 0;

    if (chainActive.Height() > Params().GetConsensus().nMasternodeSignHashThreshold) {
        uint256 hash = GetSignatureHash();

        if (!CHashSigner::VerifyHash(hash, pubKeyMasternode, vchSig, strError)) {
            std::string strMessage = CTxIn(masternodeOutpoint).ToString() + blockHash.ToString() +
                        boost::lexical_cast<std::string>(sigTime);

            if (!CMessageSigner::VerifyMessage(pubKeyMasternode, vchSig, strMessage, strError)) {
                LogPrintG(BCLogLevel::LOG_ERROR, BCLog::MN, "[Masternodes] CMasternodePing::CheckSignature -- Got bad Masternode ping signature, masternode=%s, error: %s\n", masternodeOutpoint.ToStringShort(), strError);
                nDos = 33;
                return false;
            }
        }
    } else {
        std::string strMessage = CTxIn(masternodeOutpoint).ToString() + blockHash.ToString() +
                    boost::lexical_cast<std::string>(sigTime);

        if (!CMessageSigner::VerifyMessage(pubKeyMasternode, vchSig, strMessage, strError)) {
            LogPrintG(BCLogLevel::LOG_ERROR, BCLog::MN, "[Masternodes] CMasternodePing::CheckSignature -- Got bad Masternode ping signature, masternode=%s, error: %s\n", masternodeOutpoint.ToStringShort(), strError);
            nDos = 33;
            return false;
        }
    }

    return true;
}

bool CMasternodePing::SimpleCheck(int& nDos)
{
    // don't ban by default
    nDos = 0;

    if (sigTime > GetAdjustedTime() + 60 * 60) {
        LogPrintG(BCLogLevel::LOG_ERROR, BCLog::MN, "[Masternodes] CMasternodePing::SimpleCheck -- Signature rejected, too far into the future, masternode=%s\n", masternodeOutpoint.ToStringShort());
        nDos = 1;
        return false;
    }

    {
        AssertLockHeld(cs_main);
        BlockMap::iterator mi = mapBlockIndex.find(blockHash);
        if (mi == mapBlockIndex.end()) {
            LogPrintG(BCLogLevel::LOG_ERROR, BCLog::MN, "[Masternodes] CMasternodePing::SimpleCheck -- Masternode ping is invalid, unknown block hash: masternode=%s blockHash=%s\n", masternodeOutpoint.ToStringShort(), blockHash.ToString());
            // maybe we stuck or forked so we shouldn't ban this node, just fail to accept this ping
            // TODO: or should we also request this block?
            return false;
        }
    }
    LogPrintG(BCLogLevel::LOG_INFO, BCLog::MN, "[Masternodes] CMasternodePing::SimpleCheck -- Masternode ping verified: masternode=%s  blockHash=%s  sigTime=%d\n", masternodeOutpoint.ToStringShort(), blockHash.ToString(), sigTime);
    return true;
}

bool CMasternodePing::CheckAndUpdate(CMasternode* pmn, bool fFromNewBroadcast, int& nDos, CConnman& connman)
{
    AssertLockHeld(cs_main);

    // don't ban by default
    nDos = 0;

    if (!SimpleCheck(nDos)) {
        return false;
    }

    if (pmn == NULL) {
        LogPrintG(BCLogLevel::LOG_ERROR, BCLog::MN, "[Masternodes] CMasternodePing::CheckAndUpdate -- Couldn't find Masternode entry, masternode=%s\n", masternodeOutpoint.ToStringShort());
        return false;
    }

    if (!fFromNewBroadcast) {
        if (pmn->IsUpdateRequired()) {
            LogPrintG(BCLogLevel::LOG_WARNING, BCLog::MN, "[Masternodes] CMasternodePing::CheckAndUpdate -- masternode protocol is outdated, masternode=%s\n", masternodeOutpoint.ToStringShort());
            return false;
        }

        if (pmn->IsNewStartRequired()) {
            LogPrintG(BCLogLevel::LOG_WARNING, BCLog::MN, "[Masternodes] CMasternodePing::CheckAndUpdate -- masternode is completely expired, new start is required, masternode=%s\n", masternodeOutpoint.ToStringShort());
            return false;
        }
    }

    {
        BlockMap::iterator mi = mapBlockIndex.find(blockHash);
        if ((*mi).second && (*mi).second->nHeight < chainActive.Height() - 24) {
            LogPrintG(BCLogLevel::LOG_WARNING, BCLog::MN, "[Masternodes] CMasternodePing::CheckAndUpdate -- Masternode ping is invalid, block hash is too old: masternode=%s  blockHash=%s\n", masternodeOutpoint.ToStringShort(), blockHash.ToString());
            // nDos = 1;
            return false;
        }
    }

    LogPrintG(BCLogLevel::LOG_NOTICE, BCLog::MN, "[Masternodes] CMasternodePing::CheckAndUpdate -- New ping: masternode=%s  blockHash=%s  sigTime=%d\n", masternodeOutpoint.ToStringShort(), blockHash.ToString(), sigTime);

    //LogPrintG(BCLogLevel::LOG_NOTICE, BCLog::MN, "[Masternodes] mnping - Found corresponding mn for outpoint: %s\n", masternodeOutpoint.ToStringShort());
    // update only if there is no known ping for this masternode or
    // last ping was more then Params().GetConsensus().nMasternodeMinMnpSeconds-60 ago comparing to this one
    if (pmn->IsPingedWithin(Params().GetConsensus().nMasternodeMinMnpSeconds - 60, sigTime)) {
        LogPrintG(BCLogLevel::LOG_WARNING, BCLog::MN, "[Masternodes] CMasternodePing::CheckAndUpdate -- Masternode ping arrived too early, masternode=%s\n", masternodeOutpoint.ToStringShort());
        //nDos = 1; //disable, this is happening frequently and causing banned peers
        return false;
    }

    if (!CheckSignature(pmn->pubKeyMasternode, nDos)) return false;

    // so, ping seems to be ok

    // if we are still syncing and there was no known ping for this mn for quite a while
    // (NOTE: assuming that Params().GetConsensus().nMasternodeExpirationSeconds/2 should be enough to finish mn list sync)
    if (!masternodeSync.IsMasternodeListSynced() && !pmn->IsPingedWithin(Params().GetConsensus().nMasternodeExpirationSeconds/2)) {
        // let's bump sync timeout
        LogPrintG(BCLogLevel::LOG_NOTICE, BCLog::MN, "[Masternodes] CMasternodePing::CheckAndUpdate -- bumping sync timeout, masternode=%s\n", masternodeOutpoint.ToStringShort());
        masternodeSync.BumpAssetLastTime("CMasternodePing::CheckAndUpdate");
    }

    // let's store this ping as the last one
    LogPrintG(BCLogLevel::LOG_NOTICE, BCLog::MN, "[Masternodes] CMasternodePing::CheckAndUpdate -- Masternode ping accepted, masternode=%s\n", masternodeOutpoint.ToStringShort());
    pmn->lastPing = *this;

    // and update mnodeman.mapSeenMasternodeBroadcast.lastPing which is probably outdated
    CMasternodeBroadcast mnb(*pmn);
    uint256 hash = mnb.GetHash();
    if (mnodeman.mapSeenMasternodeBroadcast.count(hash)) {
        mnodeman.mapSeenMasternodeBroadcast[hash].second.lastPing = *this;
    }

    // force update, ignoring cache
    pmn->Check(true);
    // relay ping for nodes in ENABLED/EXPIRED/SENTINEL_PING_EXPIRED state only, skip everyone else
    if (!pmn->IsEnabled() && !pmn->IsExpired() && !pmn->IsSentinelPingExpired()) return false;

    LogPrintG(BCLogLevel::LOG_NOTICE, BCLog::MN, "[Masternodes] CMasternodePing::CheckAndUpdate -- Masternode ping acceepted and relayed, masternode=%s\n", masternodeOutpoint.ToStringShort());
    Relay(connman);

    return true;
}

void CMasternodePing::Relay(CConnman& connman)
{
    // Do not relay until fully synced
    if (!masternodeSync.IsSynced()) {
        LogPrintG(BCLogLevel::LOG_WARNING, BCLog::MN, "[Masternodes] CMasternodePing::Relay -- won't relay until fully synced\n");
        return;
    }

    CInv inv(MSG_MASTERNODE_PING, GetHash());
    connman.RelayInv(inv);
}

void CMasternode::AddGovernanceVote(uint256 nGovernanceObjectHash)
{
    if (mapGovernanceObjectsVotedOn.count(nGovernanceObjectHash)) {
        mapGovernanceObjectsVotedOn[nGovernanceObjectHash]++;
    } else {
        mapGovernanceObjectsVotedOn.insert(std::make_pair(nGovernanceObjectHash, 1));
    }
}

void CMasternode::RemoveGovernanceObject(uint256 nGovernanceObjectHash)
{
    std::map<uint256, int>::iterator it = mapGovernanceObjectsVotedOn.find(nGovernanceObjectHash);
    if (it == mapGovernanceObjectsVotedOn.end()) {
        return;
    }
    mapGovernanceObjectsVotedOn.erase(it);
}

/**
*   FLAG GOVERNANCE ITEMS AS DIRTY
*
*   - When masternode come and go on the network, we must flag the items they voted on to recalc it's cached flags
*
*/
void CMasternode::FlagGovernanceItemsAsDirty()
{
    std::vector<uint256> vecDirty;
    {
        std::map<uint256, int>::iterator it = mapGovernanceObjectsVotedOn.begin();
        while(it != mapGovernanceObjectsVotedOn.end()) {
            vecDirty.push_back(it->first);
            ++it;
        }
    }
    for(size_t i = 0; i < vecDirty.size(); ++i) {
        mnodeman.AddDirtyGovernanceObjectHash(vecDirty[i]);
    }
}
