// Copyright (c) 2014-2018 The Dash Core developers
// Copyright (c) 2014-2018 The Machinecoin Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef GOVERNANCE_CLASSES_H
#define GOVERNANCE_CLASSES_H

#include <base58.h>
#include <masternodes/governance.h>
#include <key.h>
#include <script/standard.h>
#include <util.h>

#include <boost/shared_ptr.hpp>

class CGovernanceBlock;
class CGovernanceTrigger;
class CGovernanceTriggerManager;
class CGovernanceBlockManager;

static const int TRIGGER_UNKNOWN = -1;
static const int TRIGGER_GOVERNANCEBLOCK = 1000;

typedef boost::shared_ptr<CGovernanceBlock> CGovernanceBlock_sptr;

// DECLARE GLOBAL VARIABLES FOR GOVERNANCE CLASSES
extern CGovernanceTriggerManager triggerman;

/**
*   Trigger Mananger
*
*   - Track governance objects which are triggers
*   - After triggers are activated and executed, they can be removed
*/

class CGovernanceTriggerManager
{
    friend class CGovernanceBlockManager;
    friend class CGovernanceManager;

private:
    typedef std::map<uint256, CGovernanceBlock_sptr> trigger_m_t;
    typedef trigger_m_t::iterator trigger_m_it;
    typedef trigger_m_t::const_iterator trigger_m_cit;

    trigger_m_t mapTrigger;

    std::vector<CGovernanceBlock_sptr> GetActiveTriggers();
    bool AddNewTrigger(uint256 nHash);
    void CleanAndRemove();

public:
    CGovernanceTriggerManager() : mapTrigger() {}
};

/**
*   GovernanceBlock Manager
*
*   Class for querying governanceblock information
*/

class CGovernanceBlockManager
{
private:
    static bool GetBestGovernanceBlock(CGovernanceBlock_sptr& pGovernanceBlockRet, int nBlockHeight);

public:

    static bool IsGovernanceBlockTriggered(int nBlockHeight);

    static void CreateGovernanceBlock(CMutableTransaction& txNewRet, int nBlockHeight, std::vector<CTxOut>& vtxoutGovernanceRet);
    static void ExecuteBestGovernanceBlock(int nBlockHeight);

    static std::string GetRequiredPaymentsString(int nBlockHeight);
    static bool IsValid(const CTransactionRef& txNew, int nBlockHeight, CAmount blockReward);
};

/**
*   Governance Object Payment
*
*/

class CGovernancePayment
{
private:
    bool fValid;

public:
    CScript script;
    CAmount nAmount;

    CGovernancePayment()
        :fValid(false),
        script(),
        nAmount(0)
    {}

    CGovernancePayment(std::string addrIn, CAmount nAmountIn)
        :fValid(false),
        script(),
        nAmount(0)
    {
        try
        {
            CTxDestination dest = DecodeDestination(addrIn);
            script = GetScriptForDestination(dest);
            nAmount = nAmountIn;
            fValid = true;
        }
        catch (std::exception& e)
        {
            LogPrintf("CGovernancePayment Payment not valid: addrIn = %s, nAmountIn = %d, what = %s\n",
                addrIn, nAmountIn, e.what());
        }
        catch (...)
        {
            LogPrintf("CGovernancePayment Payment not valid: addrIn = %s, nAmountIn = %d\n",
                addrIn, nAmountIn);
        }
    }

    bool IsValid() { return fValid; }
};


/**
*   Trigger : GovernanceBlock
*
*   - Create payments on the network
*
*   object structure:
*   {
*       "governance_object_id" : last_id,
*       "type" : govtypes.trigger,
*       "subtype" : "governanceblock",
*       "governanceblock_name" : governanceblock_name,
*       "start_epoch" : start_epoch,
*       "payment_addresses" : "addr1|addr2|addr3",
*       "payment_amounts"   : "amount1|amount2|amount3"
*   }
*/

class CGovernanceBlock : public CGovernanceObject
{
private:
    uint256 nGovObjHash;

    int nBlockHeight;
    int nStatus;
    std::vector<CGovernancePayment> vecPayments;

    void ParsePaymentSchedule(const std::string& strPaymentAddresses, const std::string& strPaymentAmounts);

public:

    CGovernanceBlock();
    CGovernanceBlock(uint256& nHash);

    static bool IsValidBlockHeight(int nBlockHeight);
    static void GetNearestGovernanceBlocksHeights(int nBlockHeight, int& nLastGovernanceBlockRet, int& nNextGovernanceBlockRet);
    static CAmount GetPaymentsLimit(int nBlockHeight);

    int GetStatus() { return nStatus; }
    void SetStatus(int nStatusIn) { nStatus = nStatusIn; }

    // IS THIS TRIGGER ALREADY EXECUTED?
    bool IsExecuted() { return nStatus == SEEN_OBJECT_EXECUTED; }
    // TELL THE ENGINE WE EXECUTED THIS EVENT
    void SetExecuted() { nStatus = SEEN_OBJECT_EXECUTED; }

    CGovernanceObject* GetGovernanceObject()
    {
        AssertLockHeld(governance.cs);
        CGovernanceObject* pObj = governance.FindGovernanceObject(nGovObjHash);
        return pObj;
    }

    int GetBlockHeight()
    {
        return nBlockHeight;
    }

    int CountPayments() { return (int)vecPayments.size(); }
    bool GetPayment(int nPaymentIndex, CGovernancePayment& paymentRet);
    CAmount GetPaymentsTotalAmount();

    bool IsValid(const CTransactionRef& txNew, int nBlockHeight, CAmount blockReward);
    bool IsExpired();
};

#endif
