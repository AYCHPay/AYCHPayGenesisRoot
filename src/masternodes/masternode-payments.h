﻿// Copyright (c) 2014-2018 The Dash Core developers
// Copyright (c) 2014-2018 The Machinecoin Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef MASTERNODE_PAYMENTS_H
#define MASTERNODE_PAYMENTS_H

#include <util.h>
#include <core_io.h>
#include <key.h>
#include <masternodes/masternode.h>
#include <net_processing.h>
#include <utilstrencodings.h>

class CMasternodePayments;
class CMasternodePaymentVote;
class CMasternodeBlockPayees;
class CChainParams;

static const int MNPAYMENTS_SIGNATURES_REQUIRED         = 6;
static const int MNPAYMENTS_SIGNATURES_TOTAL            = 10;
static const int MN_PAYMENTS_UPDATE_THRESHOLD           = 4000;

//! minimum peer version that can receive and send masternode payment messages,
//  vote for masternode and be elected as a payment winner
// V1 - Last protocol version before update
// V2 - Newest protocol version
static const int MIN_MASTERNODE_PAYMENT_PROTO_VERSION = MASTERNODE_BLOCK_VALIDATION;

extern CCriticalSection cs_vecPayees;
extern CCriticalSection cs_mapMasternodeBlocks;
extern CCriticalSection cs_mapMasternodePayeeVotes;

extern CMasternodePayments mnpayments;

/// TODO: all 4 functions do not belong here really, they should be refactored/moved somewhere (main.cpp ?)
bool IsBlockValueValid(const CBlock& block, int nBlockHeight, CAmount blockReward, std::string& strErrorRet);
bool IsBlockPayeeValid(const CTransactionRef& txNew, int nBlockHeight, CAmount blockReward);
void FillBlockPayments(CMutableTransaction& txNew, int nBlockHeight, CAmount blockReward, std::vector<CTxOut>& vtxoutMasternodeRet, std::vector<CTxOut>& vtxoutGovernanceRet);
std::string GetRequiredPaymentsString(int nBlockHeight);
// EnforceMasternodePayments (nHeight)
// in case of a hardfork, this will prevent rejected blocks due to missing masternode payees
//
// return true, if the current checkpoint + update threshold is less than the current height
// return false, if the current checkpoint + update threshold is greater than the current height
bool EnforceMasternodePayments(int nHeight);

class CMasternodePayee
{
private:
    CScript scriptPubKey;
    std::vector<uint256> vecVoteHashes;
    int reservedForFuture = 0; 

public:
    CMasternodePayee() :
        scriptPubKey(),
        vecVoteHashes()
        {}

    CMasternodePayee(CScript payee, uint256 hashIn) :
        scriptPubKey(payee),
        vecVoteHashes()
    {
        vecVoteHashes.push_back(hashIn);
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(*(CScriptBase*)(&scriptPubKey));
        READWRITE(reservedForFuture);
        READWRITE(vecVoteHashes);
    }

    CScript GetPayee() const { return scriptPubKey; }
    void AddVoteHash(uint256 hashIn) { vecVoteHashes.push_back(hashIn); }
    std::vector<uint256> GetVoteHashes() const { return vecVoteHashes; }
    int GetVoteCount() const { return vecVoteHashes.size(); }
};

// Keep track of votes for payees from masternodes
class CMasternodeBlockPayees
{
public:
    int nBlockHeight;
    std::vector<CMasternodePayee> vecPayees;

    CMasternodeBlockPayees() :
        nBlockHeight(0),
        vecPayees()
        {}
    CMasternodeBlockPayees(int nBlockHeightIn) :
        nBlockHeight(nBlockHeightIn),
        vecPayees()
        {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nBlockHeight);
        READWRITE(vecPayees);
    }

    void AddPayee(const CMasternodePaymentVote& vote);
    bool GetBestPayee(CScript& payeeRet, int& activationBlockHeightRet) const;
    bool HasPayeeWithVotes(const CScript& payeeIn, int nVotesReq) const;

    bool IsTransactionValid(const CTransactionRef& txNew, int nBlockHeight, CAmount blockReward) const;

    std::string GetRequiredPaymentsString() const;
};

// vote for the winning payment
class CMasternodePaymentVote
{
public:
    COutPoint masternodeOutpoint;

    int nBlockHeight;
    CScript payee;
    int activationBlockHeight;
    std::vector<unsigned char> vchSig;

    CMasternodePaymentVote() :
        masternodeOutpoint(),
        nBlockHeight(0),
        payee(),
        activationBlockHeight(0),
        vchSig()
        {}

    CMasternodePaymentVote(COutPoint outpoint, int nBlockHeight, CScript payee, int activationHeight) :
        masternodeOutpoint(outpoint),
        nBlockHeight(nBlockHeight),
        payee(payee),
        activationBlockHeight(activationHeight),
        vchSig()
        {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        // using new format directly
        READWRITE(masternodeOutpoint);
        READWRITE(nBlockHeight);
        READWRITE(activationBlockHeight);
        READWRITE(*(CScriptBase*)(&payee));
        if (!(s.GetType() & SER_GETHASH)) {
            READWRITE(vchSig);
        }
    }

    uint256 GetHash() const;
    uint256 GetSignatureHash() const;

    bool Sign();
    bool CheckSignature(const CPubKey& pubKeyMasternode, int nValidationHeight, int &nDos) const;

    bool IsValid(CNode* pnode, int nValidationHeight, std::string& strError, CConnman& connman) const;
    void Relay(CConnman& connman) const;

    bool IsVerified() const { return !vchSig.empty(); }
    void MarkAsNotVerified() { vchSig.clear(); }

    std::string ToString() const;
};

class CMasternodePaymentVotes
{
public:
    int nBlockHeight;
    std::vector<CMasternodePaymentVote> vecVotes;

    CMasternodePaymentVotes() :
        nBlockHeight(0),
        vecVotes()
        {}
    CMasternodePaymentVotes(int nBlockHeightIn) :
        nBlockHeight(nBlockHeightIn),
        vecVotes()
        {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nBlockHeight);
        READWRITE(vecVotes);
    }

    void AddVote(const CMasternodePaymentVote& vote);
    // bool GetBestPayee(CScript& payeeRet) const;
    // bool HasPayeeWithVotes(const CScript& payeeIn, int nVotesReq) const;

    // bool IsTransactionValid(const CTransactionRef& txNew, int nBlockHeight, CAmount blockReward) const;

    // std::string GetRequiredPaymentsString() const;
};


//
// Masternode Payments Class
// Keeps track of who should get paid for which blocks
//

class CMasternodePayments
{
private:
    // masternode count times nStorageCoeff payments blocks should be stored ...
    const float nStorageCoeff;
    // ... but at least nMinBlocksToStore (payments blocks)
    const int nMinBlocksToStore;

    // Keep track of current block height
    int nCachedBlockHeight;

public:
    std::map<uint256, CMasternodePaymentVote> mapMasternodePaymentVotesPrimary;
    std::map<uint256, CMasternodePaymentVotes> mapMasternodePaymentVotesSecondary;
    std::map<int, CMasternodeBlockPayees> mapMasternodeBlocksPrimary;
    std::map<int, CMasternodeBlockPayees> mapMasternodeBlocksSecondary;
    std::map<COutPoint, int> mapMasternodesLastVote;
    std::map<COutPoint, int> mapMasternodesDidNotVote;

    CMasternodePayments() : nStorageCoeff(1.25), nMinBlocksToStore(6000) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(mapMasternodePaymentVotesPrimary);
        READWRITE(mapMasternodePaymentVotesSecondary);
        READWRITE(mapMasternodeBlocksPrimary);
        READWRITE(mapMasternodeBlocksSecondary);
    }

    void Clear();

    bool AddOrUpdatePaymentVote(const CMasternodePaymentVote& vote);
    bool HasVerifiedPaymentVote(const uint256& hashIn) const;
    bool ProcessBlock(int nBlockHeight, CConnman& connman);
    void CheckBlockVotes(int nBlockHeight);

    void Sync(CNode* node, CConnman& connman) const;
    void RequestLowDataPaymentBlocks(CNode* pnode, CConnman& connman) const;
    void CheckAndRemove();

    bool GetBlockPayees(int nBlockHeight, CScript& payeeRet, int& activationHeightRet) const;
    bool IsTransactionValid(const CTransactionRef& txNew, int nBlockHeight, CAmount blockReward) const;
    bool IsScheduled(const masternode_info_t& mnInfo, int nNotBlockHeight) const;

    bool UpdateLastVote(const CMasternodePaymentVote& vote);

    int GetMinMasternodePaymentsProto() const;
    void ProcessMessage(CNode* pfrom, const std::string& strCommand, CDataStream& vRecv, CConnman& connman);
    std::string GetRequiredPaymentsString(int nBlockHeight) const;
    void FillBlockPayees(CMutableTransaction& txNew, int nBlockHeight, CAmount blockReward, std::vector<CTxOut>& vtxoutMasternodeRet) const;
    std::string ToString() const;

    int GetBlockCount() const { return mapMasternodeBlocksPrimary.size(); }
    int GetVoteCount() const { return mapMasternodePaymentVotesPrimary.size(); }

    bool IsEnoughData() const;
    int GetStorageLimit() const;

    void UpdatedBlockTip(const CBlockIndex *pindex, CConnman& connman);
};

#endif
