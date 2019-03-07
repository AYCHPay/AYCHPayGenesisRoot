// Copyright (c) 2014-2018 The Dash Core developers
// Copyright (c) 2014-2018 The Machinecoin Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <core_io.h>
#include <masternodes/governance-classes.h>
#include <init.h>
#include <validation.h>
#include <utilstrencodings.h>

#include <boost/algorithm/string.hpp>

#include <univalue.h>

// DECLARE GLOBAL VARIABLES FOR GOVERNANCE CLASSES
CGovernanceTriggerManager triggerman;

// SPLIT UP STRING BY DELIMITER
// http://www.boost.org/doc/libs/1_58_0/doc/html/boost/algorithm/split_idp202406848.html
std::vector<std::string> SplitBy(const std::string& strCommand, const std::string& strDelimit)
{
    std::vector<std::string> vParts;
    boost::split(vParts, strCommand, boost::is_any_of(strDelimit));

    for (int q = 0; q < (int)vParts.size(); q++) {
        if (strDelimit.find(vParts[q]) != std::string::npos) {
            vParts.erase(vParts.begin() + q);
            --q;
        }
    }

    return vParts;
}

CAmount ParsePaymentAmount(const std::string& strAmount)
{
    CAmount nAmount = 0;
    if (strAmount.empty()) {
        std::ostringstream ostr;
        ostr << "ParsePaymentAmount: Amount is empty";
        throw std::runtime_error(ostr.str());
    }
    if (strAmount.size() > 20) {
        // String is much too long, the functions below impose stricter
        // requirements
        std::ostringstream ostr;
        ostr << "ParsePaymentAmount: Amount string too long";
        throw std::runtime_error(ostr.str());
    }
    // Make sure the string makes sense as an amount
    // Note: No spaces allowed
    // Also note: No scientific notation
    size_t pos = strAmount.find_first_not_of("0123456789.");
    if (pos != std::string::npos) {
        std::ostringstream ostr;
        ostr << "ParsePaymentAmount: Amount string contains invalid character";
        throw std::runtime_error(ostr.str());
    }

    pos = strAmount.find(".");
    if (pos == 0) {
        // JSON doesn't allow values to start with a decimal point
        std::ostringstream ostr;
        ostr << "ParsePaymentAmount: Invalid amount string, leading decimal point not allowed";
        throw std::runtime_error(ostr.str());
    }

    // Make sure there's no more than 1 decimal point
    if ((pos != std::string::npos) && (strAmount.find(".", pos + 1) != std::string::npos)) {
        std::ostringstream ostr;
        ostr << "ParsePaymentAmount: Invalid amount string, too many decimal points";
        throw std::runtime_error(ostr.str());
    }

    // Note this code is taken from AmountFromValue in rpcserver.cpp
    // which is used for parsing the amounts in createrawtransaction.
    if (!ParseFixedPoint(strAmount, 8, &nAmount)) {
        nAmount = 0;
        std::ostringstream ostr;
        ostr << "ParsePaymentAmount: ParseFixedPoint failed for string: " << strAmount;
        throw std::runtime_error(ostr.str());
    }
    if (!MoneyRange(nAmount)) {
        nAmount = 0;
        std::ostringstream ostr;
        ostr << "ParsePaymentAmount: Invalid amount string, value outside of valid money range";
        throw std::runtime_error(ostr.str());
    }

    return nAmount;
}

/**
*   Add Governance Object
*/

bool CGovernanceTriggerManager::AddNewTrigger(uint256 nHash)
{
    AssertLockHeld(governance.cs);

    // IF WE ALREADY HAVE THIS HASH, RETURN
    if (mapTrigger.count(nHash)) {
        return false;
    }

    CGovernanceBlock_sptr pGovernanceBlock;
    try {
        CGovernanceBlock_sptr pGovernanceBlockTmp(new CGovernanceBlock(nHash));
        pGovernanceBlock = pGovernanceBlockTmp;
    }
    catch (std::exception& e) {
        LogPrint(BCLog::GOV, "[Governance] CGovernanceTriggerManager::AddNewTrigger -- Error creating governance block: %s\n", e.what());
        return false;
    }
    catch (...) {
        LogPrint(BCLog::GOV, "[Governance] CGovernanceTriggerManager::AddNewTrigger: Unknown Error creating governance block\n");
        return false;
    }

    pGovernanceBlock->SetStatus(SEEN_OBJECT_IS_VALID);

    mapTrigger.insert(std::make_pair(nHash, pGovernanceBlock));

    return true;
}

/**
*
*   Clean And Remove
*
*/

void CGovernanceTriggerManager::CleanAndRemove()
{
    LogPrint(BCLog::GOV, "[Governance] CGovernanceTriggerManager::CleanAndRemove -- Start\n");
    AssertLockHeld(governance.cs);

    // Remove triggers that are invalid or expired
    LogPrint(BCLog::GOV, "[Governance] CGovernanceTriggerManager::CleanAndRemove -- mapTrigger.size() = %d\n", mapTrigger.size());

    trigger_m_it it = mapTrigger.begin();
    while(it != mapTrigger.end()) {
        bool remove = false;
        CGovernanceObject* pObj = nullptr;
        CGovernanceBlock_sptr& pGovernanceBlock = it->second;
        if (!pGovernanceBlock) {
            LogPrint(BCLog::GOV, "[Governance] CGovernanceTriggerManager::CleanAndRemove -- NULL governance block marked for removal\n");
            remove = true;
        } else {
            pObj = governance.FindGovernanceObject(it->first);
            if (!pObj || pObj->GetObjectType() != GOVERNANCE_OBJECT_TRIGGER) {
                LogPrint(BCLog::GOV, "[Governance] CGovernanceTriggerManager::CleanAndRemove -- Unknown or non-trigger governance block\n");
                pGovernanceBlock->SetStatus(SEEN_OBJECT_ERROR_INVALID);
            }
            LogPrint(BCLog::GOV, "[Governance] CGovernanceTriggerManager::CleanAndRemove -- governance block status = %d\n", pGovernanceBlock->GetStatus());
            switch (pGovernanceBlock->GetStatus()) {
            case SEEN_OBJECT_ERROR_INVALID:
            case SEEN_OBJECT_UNKNOWN:
                LogPrint(BCLog::GOV, "[Governance] CGovernanceTriggerManager::CleanAndRemove -- Unknown or invalid trigger found\n");
                remove = true;
                break;
            case SEEN_OBJECT_IS_VALID:
            case SEEN_OBJECT_EXECUTED:
                remove = pGovernanceBlock->IsExpired();
                break;
            default:
                break;
            }
        }
        LogPrint(BCLog::GOV, "[Governance] CGovernanceTriggerManager::CleanAndRemove -- %smarked for removal\n", remove ? "" : "NOT ");

        if (remove) {
            LogPrint(BCLog::GOV, "[Governance] CGovernanceTriggerManager::CleanAndRemove -- Removing trigger object\n");
            // mark corresponding object for deletion
            if (pObj) {
                pObj->fCachedDelete = true;
                if (pObj->nDeletionTime == 0) {
                    pObj->nDeletionTime = GetAdjustedTime();
                }
            }
            // delete the trigger
            mapTrigger.erase(it++);
        }
        else  {
            ++it;
        }
    }
}

/**
*   Get Active Triggers
*
*   - Look through triggers and scan for active ones
*   - Return the triggers in a list
*/

std::vector<CGovernanceBlock_sptr> CGovernanceTriggerManager::GetActiveTriggers()
{
    AssertLockHeld(governance.cs);
    std::vector<CGovernanceBlock_sptr> vecResults;

    // LOOK AT THESE OBJECTS AND COMPILE A VALID LIST OF TRIGGERS
    trigger_m_it it = mapTrigger.begin();
    while(it != mapTrigger.end()) {

        CGovernanceObject* pObj = governance.FindGovernanceObject((*it).first);

        if (pObj) {
            vecResults.push_back(it->second);
        }
        ++it;
    }

    return vecResults;
}

/**
*   Is GovernanceBlock Triggered
*
*   - Does this block have a non-executed and actived trigger?
*/

bool CGovernanceBlockManager::IsGovernanceBlockTriggered(int nBlockHeight)
{
    LogPrint(BCLog::GOV, "[Governance] CGovernanceBlockManager::IsGovernanceBlockTriggered -- Start nBlockHeight = %d\n", nBlockHeight);
    if (!CGovernanceBlock::IsValidBlockHeight(nBlockHeight)) {
        return false;
    }

    LOCK(governance.cs);
    // GET ALL ACTIVE TRIGGERS
    std::vector<CGovernanceBlock_sptr> vecTriggers = triggerman.GetActiveTriggers();

    LogPrint(BCLog::GOV, "[Governance] CGovernanceBlockManager::IsGovernanceBlockTriggered -- vecTriggers.size() = %d\n", vecTriggers.size());

    for (const auto& pGovernanceBlock : vecTriggers)
    {
        if (!pGovernanceBlock) {
            LogPrint(BCLog::GOV, "[Governance] CGovernanceBlockManager::IsGovernanceBlockTriggered -- Non-governance block found, continuing\n");
            continue;
        }

        CGovernanceObject* pObj = pGovernanceBlock->GetGovernanceObject();

        if (!pObj) {
            LogPrint(BCLog::GOV, "[Governance] CGovernanceBlockManager::IsGovernanceBlockTriggered -- pObj == NULL, continuing\n");
            continue;
        }

        LogPrint(BCLog::GOV, "[Governance] CGovernanceBlockManager::IsGovernanceBlockTriggered -- data = %s\n", pObj->GetDataAsPlainString());

        // note : 12.1 - is epoch calculation correct?

        if (nBlockHeight != pGovernanceBlock->GetBlockHeight()) {
            LogPrint(BCLog::GOV, "[Governance] CGovernanceBlockManager::IsGovernanceBlockTriggered -- block height doesn't match nBlockHeight = %d, blockStart = %d, continuing\n",
                     nBlockHeight,
                     pGovernanceBlock->GetBlockHeight());
            continue;
        }

        // MAKE SURE THIS TRIGGER IS ACTIVE VIA FUNDING CACHE FLAG

        pObj->UpdateSentinelVariables();

        if (pObj->IsSetCachedFunding()) {
            LogPrint(BCLog::GOV, "[Governance] CGovernanceBlockManager::IsGovernanceBlockTriggered -- fCacheFunding = true, returning true\n");
            return true;
        }
        else  {
            LogPrint(BCLog::GOV, "[Governance] CGovernanceBlockManager::IsGovernanceBlockTriggered -- fCacheFunding = false, continuing\n");
        }
    }

    return false;
}


bool CGovernanceBlockManager::GetBestGovernanceBlock(CGovernanceBlock_sptr& pGovernanceBlockRet, int nBlockHeight)
{
    if (!CGovernanceBlock::IsValidBlockHeight(nBlockHeight)) {
        return false;
    }

    AssertLockHeld(governance.cs);
    std::vector<CGovernanceBlock_sptr> vecTriggers = triggerman.GetActiveTriggers();
    int nYesCount = 0;

    for (const auto& pGovernanceBlock : vecTriggers) {
        if (!pGovernanceBlock) {
            continue;
        }

        CGovernanceObject* pObj = pGovernanceBlock->GetGovernanceObject();

        if (!pObj) {
            continue;
        }

        if (nBlockHeight != pGovernanceBlock->GetBlockHeight()) {
            continue;
        }

        // DO WE HAVE A NEW WINNER?

        int nTempYesCount = pObj->GetAbsoluteYesCount(VOTE_SIGNAL_FUNDING);
        if (nTempYesCount > nYesCount) {
            nYesCount = nTempYesCount;
            pGovernanceBlockRet = pGovernanceBlock;
        }
    }

    return nYesCount > 0;
}

/**
*   Create GovernanceBlock Payments
*
*   - Create the correct payment structure for a given governance block
*/

void CGovernanceBlockManager::CreateGovernanceBlock(CMutableTransaction& txNewRet, int nBlockHeight, std::vector<CTxOut>& vtxoutGovernanceRet)
{
    LOCK(governance.cs);

    // GET THE BEST GOVERNANCEBLOCK FOR THIS BLOCK HEIGHT

    CGovernanceBlock_sptr pGovernanceBlock;
    if (!CGovernanceBlockManager::GetBestGovernanceBlock(pGovernanceBlock, nBlockHeight)) {
        LogPrint(BCLog::GOV, "[Governance] CGovernanceBlockManager::CreateGovernanceBlock -- Can't find governance block for height %d\n", nBlockHeight);
        return;
    }

    // make sure it's empty, just in case
    vtxoutGovernanceRet.clear();

    // CONFIGURE GOVERNANCEBLOCK OUTPUTS

    // TODO: How many payments can we add before things blow up?
    //       Consider at least following limits:
    //          - max coinbase tx size
    //          - max "budget" available
    for (int i = 0; i < pGovernanceBlock->CountPayments(); i++) {
        CGovernancePayment payment;
        if (pGovernanceBlock->GetPayment(i, payment)) {
            // SET COINBASE OUTPUT TO GOVERNANCEBLOCK SETTING

            CTxOut txout = CTxOut(payment.nAmount, payment.script);
            txNewRet.vout.push_back(txout);
            vtxoutGovernanceRet.push_back(txout);

            // PRINT NICE LOG OUTPUT FOR GOVERNANCEBLOCK PAYMENT

            CTxDestination address1;
            ExtractDestination(payment.script, address1);

            // TODO: PRINT NICE N.N MAC OUTPUT

            LogPrint(BCLog::GOV, "[Governance] NEW GovernanceBlock : output %d (addr %s, amount %d)\n", i, EncodeDestination(address1), payment.nAmount);
        }
    }
}

bool CGovernanceBlockManager::IsValid(const CTransactionRef& txNew, int nBlockHeight, CAmount blockReward)
{
    // GET BEST GOVERNANCEBLOCK, SHOULD MATCH
    LOCK(governance.cs);

    CGovernanceBlock_sptr pGovernanceBlock;
    if (CGovernanceBlockManager::GetBestGovernanceBlock(pGovernanceBlock, nBlockHeight)) {
        return pGovernanceBlock->IsValid(txNew, nBlockHeight, blockReward);
    }

    return false;
}

void CGovernanceBlockManager::ExecuteBestGovernanceBlock(int nBlockHeight)
{
    LOCK(governance.cs);

    CGovernanceBlock_sptr pGovernanceBlock;
    if (GetBestGovernanceBlock(pGovernanceBlock, nBlockHeight)) {
        // All checks are done in CGovernanceBlock::IsValid via IsBlockValueValid and IsBlockPayeeValid,
        // tip wouldn't be updated if anything was wrong. Mark this trigger as executed.
        pGovernanceBlock->SetExecuted();
    }
}

CGovernanceBlock::
CGovernanceBlock()
    : nGovObjHash(),
      nBlockHeight(0),
      nStatus(SEEN_OBJECT_UNKNOWN),
      vecPayments()
{}

CGovernanceBlock::
CGovernanceBlock(uint256& nHash)
    : nGovObjHash(nHash),
      nBlockHeight(0),
      nStatus(SEEN_OBJECT_UNKNOWN),
      vecPayments()
{
    CGovernanceObject* pGovObj = GetGovernanceObject();

    if (!pGovObj) {
        throw std::runtime_error("CGovernanceBlock: Failed to find Governance Object");
    }

    if (pGovObj->GetObjectType() != GOVERNANCE_OBJECT_TRIGGER) {
        throw std::runtime_error("CGovernanceBlock: Governance Object not a trigger");
    }

    UniValue obj = pGovObj->GetJSONObject();

    // FIRST WE GET THE START HEIGHT, THE BLOCK HEIGHT AT WHICH THE PAYMENT SHALL OCCUR
    nBlockHeight = obj["event_block_height"].get_int();

    // NEXT WE GET THE PAYMENT INFORMATION AND RECONSTRUCT THE PAYMENT VECTOR
    std::string strAddresses = obj["payment_addresses"].get_str();
    std::string strAmounts = obj["payment_amounts"].get_str();
    ParsePaymentSchedule(strAddresses, strAmounts);

    LogPrint(BCLog::GOV, "[Governance] CGovernanceBlock -- nBlockHeight = %d, strAddresses = %s, strAmounts = %s, vecPayments.size() = %d\n",
        nBlockHeight, strAddresses, strAmounts, vecPayments.size());
}

/**
 *   Is Valid Governance Block Height
 *
 *   - See if a block at this height can be a governance block
 */

bool CGovernanceBlock::IsValidBlockHeight(int nBlockHeight)
{
    // GOVERNANCEBLOCKS CAN HAPPEN ONLY after hardfork and only ONCE PER CYCLE to be Params().GetConsensus().nGovernanceBlockOffset 
    // blocks after the bonus block
    return nBlockHeight >= Params().GetConsensus().nMasternodePaymentsStartBlock &&
        ((nBlockHeight % Params().GetConsensus().GetMegaBlockInterval()) == Params().GetConsensus().nGovernanceBlockOffset);
}

void CGovernanceBlock::GetNearestGovernanceBlocksHeights(int nBlockHeight, int& nLastGovernanceBlockRet, int& nNextGovernanceBlockRet)
{
    const Consensus::Params& consensusParams = Params().GetConsensus();
    int nMasternodePaymentsStartBlock = consensusParams.nMasternodePaymentsStartBlock;
    int nGovernanceBlockCycle = consensusParams.GetMegaBlockInterval();
    int nGovernanceBlockOffset = consensusParams.nGovernanceBlockOffset;

    // Get first governance block
    int nFirstGovernanceBlockOffset = ((nGovernanceBlockCycle - nMasternodePaymentsStartBlock % nGovernanceBlockCycle) % nGovernanceBlockCycle) + nGovernanceBlockOffset;
    int nFirstGovernanceBlock = nMasternodePaymentsStartBlock + nFirstGovernanceBlockOffset;

    if (nBlockHeight < nFirstGovernanceBlock) {
        nLastGovernanceBlockRet = 0;
        nNextGovernanceBlockRet = nFirstGovernanceBlock;
    }
    else {
        nLastGovernanceBlockRet = (nBlockHeight - nBlockHeight % nGovernanceBlockCycle) + nGovernanceBlockOffset;
        nNextGovernanceBlockRet = (nLastGovernanceBlockRet + nGovernanceBlockCycle) + nGovernanceBlockOffset;
    }
}

CAmount CGovernanceBlock::GetPaymentsLimit(int nBlockHeight)
{
    const Consensus::Params& consensusParams = Params().GetConsensus();

    if (!IsValidBlockHeight(nBlockHeight)) {
        return 0;
    }

    // As we are calculating the amount in the same way as the bonus blocks, we can simply get the appropriate value for the current block
    CAmount nPaymentsLimit = GetBlockSubsidy(nBlockHeight, consensusParams, true);
    LogPrint(BCLog::GOV, "[Governance] CGovernanceBlock::GetPaymentsLimit -- Valid governance block height %d, payments max %lld\n", nBlockHeight, nPaymentsLimit);

    return nPaymentsLimit;
}

void CGovernanceBlock::ParsePaymentSchedule(const std::string& strPaymentAddresses, const std::string& strPaymentAmounts)
{
    // SPLIT UP ADDR/AMOUNT STRINGS AND PUT IN VECTORS

    std::vector<std::string> vecParsed1;
    std::vector<std::string> vecParsed2;
    vecParsed1 = SplitBy(strPaymentAddresses, "|");
    vecParsed2 = SplitBy(strPaymentAmounts, "|");

    // IF THESE DONT MATCH, SOMETHING IS WRONG

    if (vecParsed1.size() != vecParsed2.size()) {
        std::ostringstream ostr;
        ostr << "CGovernanceBlock::ParsePaymentSchedule -- Mismatched payments and amounts";
        LogPrint(BCLog::GOV, "[Governance] %s\n", ostr.str());
        throw std::runtime_error(ostr.str());
    }

    if (vecParsed1.size() == 0) {
        std::ostringstream ostr;
        ostr << "CGovernanceBlock::ParsePaymentSchedule -- Error no payments";
        LogPrint(BCLog::GOV, "[Governance] %s\n", ostr.str());
        throw std::runtime_error(ostr.str());
    }

    // LOOP THROUGH THE ADDRESSES/AMOUNTS AND CREATE PAYMENTS
    /*
      ADDRESSES = [ADDR1|2|3|4|5|6]
      AMOUNTS = [AMOUNT1|2|3|4|5|6]
    */

    for (int i = 0; i < (int)vecParsed1.size(); i++) {
        CTxDestination address = DecodeDestination(vecParsed1[i]);
        if (!IsValidDestinationString(vecParsed1[i])) {
            std::ostringstream ostr;
            ostr << "CGovernanceBlock::ParsePaymentSchedule -- Invalid Genesis Masternode Address : " << vecParsed1[i];
            LogPrint(BCLog::GOV, "[Governance] %s\n", ostr.str());
            throw std::runtime_error(ostr.str());
        }

        CAmount nAmount = ParsePaymentAmount(vecParsed2[i]);

        CGovernancePayment payment(vecParsed1[i], nAmount);
        if (payment.IsValid()) {
            vecPayments.push_back(payment);
        }
        else {
            vecPayments.clear();
            std::ostringstream ostr;
            ostr << "CGovernanceBlock::ParsePaymentSchedule -- Invalid payment found: address = " << vecParsed1[i]
                << ", amount = " << nAmount;
            LogPrint(BCLog::GOV, "[Governance] %s\n", ostr.str());
            throw std::runtime_error(ostr.str());
        }
    }
}

bool CGovernanceBlock::GetPayment(int nPaymentIndex, CGovernancePayment& paymentRet)
{
    if ((nPaymentIndex < 0) || (nPaymentIndex >= (int)vecPayments.size())) {
        return false;
    }

    paymentRet = vecPayments[nPaymentIndex];
    return true;
}

CAmount CGovernanceBlock::GetPaymentsTotalAmount()
{
    CAmount nPaymentsTotalAmount = 0;
    int nPayments = CountPayments();

    for (int i = 0; i < nPayments; i++) {
        nPaymentsTotalAmount += vecPayments[i].nAmount;
    }

    return nPaymentsTotalAmount;
}

/**
*   Is Transaction Valid
*
*   - Does this transaction match the governance block?
*/

bool CGovernanceBlock::IsValid(const CTransactionRef& txNew, int nBlockHeight, CAmount blockReward)
{
    // TODO : LOCK(cs);
    // No reason for a lock here now since this method only accesses data
    // internal to *this and since CGovernanceBlock's are accessed only through
    // shared pointers there's no way our object can get deleted while this
    // code is running.
    if (!IsValidBlockHeight(nBlockHeight)) {
        LogPrint(BCLog::GOV, "[Governance] CGovernanceBlock::IsValid -- ERROR: Block invalid, incorrect block height\n");
        return false;
    }

    std::string strPayeesPossible = "";

    // CONFIGURE GOVERNANCEBLOCK OUTPUTS

    int nOutputs = txNew->vout.size();
    int nPayments = CountPayments();
    int nMinerPayments = nOutputs - nPayments;

    LogPrint(BCLog::GOV, "[Governance] CGovernanceBlock::IsValid nOutputs = %d, nPayments = %d, GetDataAsHexString = %s\n",
        nOutputs, nPayments, GetGovernanceObject()->GetDataAsHexString());

    // We require an exact match (including order) between the expected
    // governance block payments and the payments actually in the block.

    if (nMinerPayments < 0) {
        // This means the block cannot have all the governance block payments
        // so it is not valid.
        // TODO: could that be that we just hit coinbase size limit?
        LogPrint(BCLog::GOV, "[Governance] CGovernanceBlock::IsValid -- ERROR: Block invalid, too few governance block payments\n");
        return false;
    }

    // payments should not exceed limit
    CAmount nPaymentsTotalAmount = GetPaymentsTotalAmount();
    CAmount nPaymentsLimit = GetPaymentsLimit(nBlockHeight);
    if (nPaymentsTotalAmount > nPaymentsLimit) {
        LogPrint(BCLog::GOV, "[Governance] CGovernanceBlock::IsValid -- ERROR: Block invalid, payments limit exceeded: payments %lld, limit %lld\n", nPaymentsTotalAmount, nPaymentsLimit);
        return false;
    }

    // miner should not get more than he would usually get
    CAmount nBlockValue = txNew->GetValueOut();
    if (nBlockValue > blockReward + nPaymentsTotalAmount) {
        LogPrint(BCLog::GOV, "[Governance] CGovernanceBlock::IsValid -- ERROR: Block invalid, block value limit exceeded: block %lld, limit %lld\n", nBlockValue, blockReward + nPaymentsTotalAmount);
        return false;
    }

    int nVoutIndex = 0;
    for (int i = 0; i < nPayments; i++) {
        CGovernancePayment payment;
        if (!GetPayment(i, payment)) {
            // This shouldn't happen so log a warning
            LogPrint(BCLog::GOV, "[Governance] CGovernanceBlock::IsValid -- WARNING: Failed to find payment: %d of %d total payments\n", i, nPayments);
            continue;
        }

        bool fPaymentMatch = false;

        for (int j = nVoutIndex; j < nOutputs; j++) {
            // Find governance block payment
            fPaymentMatch = ((payment.script == txNew->vout[j].scriptPubKey) &&
                (payment.nAmount == txNew->vout[j].nValue));

            if (fPaymentMatch) {
                nVoutIndex = j;
                break;
            }
        }

        if (!fPaymentMatch) {
            // GovernanceBlock payment not found!

            CTxDestination address1;
            ExtractDestination(payment.script, address1);
            LogPrint(BCLog::GOV, "[Governance] CGovernanceBlock::IsValid -- ERROR: Block invalid: %d payment %d to %s not found\n", i, payment.nAmount, EncodeDestination(address1));

            return false;
        }
    }

    return true;
}

bool CGovernanceBlock::IsExpired()
{
    bool fExpired{ false };
    int nExpirationBlocks{ 0 };
    // Executed triggers are kept for a month,
    // other valid triggers are kept for ~1 week only, everything else is pruned after ~1 day.
    switch (nStatus) {
        case SEEN_OBJECT_EXECUTED:
            nExpirationBlocks = Params().GetConsensus().GetMegaBlockInterval();
            break;
        case SEEN_OBJECT_IS_VALID:
            nExpirationBlocks = Params().GetConsensus().GetSuperBlockInterval();
            break;
        default:
            nExpirationBlocks = Params().GetConsensus().GetBonusBlockInterval();
            break;
    }

    int nExpirationBlock = nBlockHeight + nExpirationBlocks;

    LogPrint(BCLog::GOV, "[Governance] CGovernanceBlock::IsExpired -- nBlockHeight = %d, nExpirationBlock = %d\n", nBlockHeight, nExpirationBlock);

    if (governance.GetCachedBlockHeight() > nExpirationBlock) {
        LogPrint(BCLog::GOV, "[Governance] CGovernanceBlock::IsExpired -- Outdated trigger found\n");
        fExpired = true;
        CGovernanceObject* pgovobj = GetGovernanceObject();
        if (pgovobj) {
            LogPrint(BCLog::GOV, "[Governance] CGovernanceBlock::IsExpired -- Expiring outdated object: %s\n", pgovobj->GetHash().ToString());
            pgovobj->fExpired = true;
            pgovobj->nDeletionTime = GetAdjustedTime();
        }
    }

    return fExpired;
}

/**
*   Get Required Payment String
*
*   - Get a string representing the payments required for a given governance block
*/

std::string CGovernanceBlockManager::GetRequiredPaymentsString(int nBlockHeight)
{
    LOCK(governance.cs);
    std::string ret = "Unknown";

    // GET BEST GOVERNANCEBLOCK

    CGovernanceBlock_sptr pGovernanceBlock;
    if (!GetBestGovernanceBlock(pGovernanceBlock, nBlockHeight)) {
        LogPrint(BCLog::GOV, "[Governance] CGovernanceBlockManager::GetRequiredPaymentsString -- Can't find governance block for height %d\n", nBlockHeight);
        return "error";
    }

    // LOOP THROUGH GOVERNANCEBLOCK PAYMENTS, CONFIGURE OUTPUT STRING

    for (int i = 0; i < pGovernanceBlock->CountPayments(); i++) {
        CGovernancePayment payment;
        if (pGovernanceBlock->GetPayment(i, payment)) {
            // PRINT NICE LOG OUTPUT FOR GOVERNANCEBLOCK PAYMENT

            CTxDestination address1;
            ExtractDestination(payment.script, address1);

            // RETURN NICE OUTPUT FOR CONSOLE

            if (ret != "Unknown") {
                ret += ", " + EncodeDestination(address1);
            }
            else {
                ret = EncodeDestination(address1);
            }
        }
    }

    return ret;
}
