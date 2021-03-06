﻿// Copyright (c) 2014-2018 The Dash Core developers
// Copyright (c) 2014-2018 The Machinecoin Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <masternodes/activemasternode.h>
#include <base58.h>
#include <clientversion.h>
#include <init.h>
#include <netbase.h>
#include <validation.h>
#include <masternodes/masternode-payments.h>
#include <masternodes/masternode-sync.h>
#include <masternodes/masternodeconfig.h>
#include <masternodes/masternodeman.h>
#include <rpc/server.h>
#include <util.h>
#include <utilmoneystr.h>
#include <wallet/wallet.h>

#include <fstream>
#include <iomanip>
#include <univalue.h>

#include <algorithm>

UniValue masternode(const JSONRPCRequest& request)
{
    std::string strCommand;
    if (request.params.size() >= 1) {
        strCommand = request.params[0].get_str();
    }

#ifdef ENABLE_WALLET
    if (strCommand == "start-many")
        throw JSONRPCError(RPC_INVALID_PARAMETER, "DEPRECATED, please use start-all instead");
#endif // ENABLE_WALLET

    if (request.fHelp  ||
        (
#ifdef ENABLE_WALLET
            strCommand != "start-alias" && strCommand != "start-all" && strCommand != "start-missing" &&
         strCommand != "start-disabled" && strCommand != "outputs" &&
#endif // ENABLE_WALLET
         strCommand != "list" && strCommand != "list-conf" && strCommand != "count" && strCommand != "maturity" &&
         strCommand != "debug" && strCommand != "current" && strCommand != "winner" && strCommand != "winners" && strCommand != "genkey" &&
         strCommand != "connect" && strCommand != "status"))
            throw std::runtime_error(
                "masternode \"command\"...\n"
                "Set of commands to execute masternode related actions\n"
                "\nArguments:\n"
                "1. \"command\"        (string or set of strings, required) The command to execute\n"
                "\nAvailable commands:\n"
                "  count        - Get information about number of masternodes (DEPRECATED options: 'total', 'enabled', 'qualify', 'all')\n"
                "  current      - Print info on current masternode winner to be paid the next block (calculated locally)\n"
                "  genkey       - Generate new masternodeprivkey\n"
                "  list         - Print list of all known masternodes (see masternodelist for more info)\n"
                "  list-conf    - Print masternode.conf in JSON format\n"
                "  maturity     - Calculate the maturity stats for a masternode\n"
#ifdef ENABLE_WALLET
                "  outputs      - Print masternode compatible outputs\n"
                "  start-alias  - Start single remote masternode by assigned alias configured in masternode.conf\n"
                "  start-<mode> - Start remote masternodes configured in masternode.conf (<mode>: 'all', 'missing', 'disabled')\n"
#endif // ENABLE_WALLET
                "  status       - Print masternode status information\n"
                "  winner       - Print info on next masternode winner to vote for\n"
                "  winners      - Print list of masternode winners\n"
                );

    if (strCommand == "list")
    {
        UniValue newParams(UniValue::VARR);
        // forward params but skip "list"
        for (unsigned int i = 1; i < request.params.size(); i++) {
            newParams.push_back(request.params[i]);
        }
        
        JSONRPCRequest request_;
        request_.fHelp = request.fHelp;
        request_.params = newParams;

        return masternodelist(request_);
    }

    if (strCommand == "connect")
    {
        if (request.params.size() < 2)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Masternode address required");

        std::string strAddress = request.params[1].get_str();

        CService addr;
        if (!Lookup(strAddress.c_str(), addr, 0, false))
            throw JSONRPCError(RPC_INTERNAL_ERROR, strprintf("Incorrect masternode address %s", strAddress));

        // TODO: Pass CConnman instance somehow and don't use global variable.
        g_connman->OpenMasternodeConnection(CAddress(addr, NODE_NETWORK));
        if (!g_connman->IsConnected(CAddress(addr, NODE_NETWORK), CConnman::AllNodes))
            throw JSONRPCError(RPC_INTERNAL_ERROR, strprintf("Couldn't connect to masternode %s", strAddress));

        return "successfully connected";
    }

    if (strCommand == "count")
    {
        if (request.params.size() > 2)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Too many parameters");

        int nCount;
        masternode_info_t mnInfo;
        std::vector<masternode_info_t> secondaryMnInfoRet;

        mnodeman.GetNextMasternodesInQueueForPayment(true, nCount, mnInfo, secondaryMnInfoRet);

        int total = mnodeman.size();
        int enabled = mnodeman.CountEnabled();

        if (request.params.size() == 1) {
            UniValue obj(UniValue::VOBJ);

            obj.push_back(Pair("total", total));
            obj.push_back(Pair("enabled", enabled));
            obj.push_back(Pair("qualify", nCount));

            return obj;
        }
    }

    if (strCommand == "current" || strCommand == "winner")
    {
        int nCount;
        int nHeight;
        masternode_info_t mnInfo;
        CBlockIndex* pindex = NULL;
        {
            LOCK(cs_main);
            pindex = chainActive.Tip();
        }
        nHeight = pindex->nHeight + (strCommand == "current" ? 1 : 10);
        mnodeman.UpdateLastPaid(pindex);
        std::vector<masternode_info_t> secondaryMnInfoRet;

        if (!mnodeman.GetNextMasternodesInQueueForPayment(nHeight, true, nCount, mnInfo, secondaryMnInfoRet))
            return "unknown";

        
        UniValue obj(UniValue::VOBJ);

        obj.push_back(Pair("height",                nHeight));
        obj.push_back(Pair("ip",                    mnInfo.addr.ToStringIP()));
        obj.push_back(Pair("port",                  mnInfo.addr.ToStringPort()));
        obj.push_back(Pair("protocol",              mnInfo.nProtocolVersion));
        obj.push_back(Pair("outpoint",              mnInfo.outpoint.ToStringShort()));
        obj.push_back(Pair("payee",                 EncodeDestination(CScriptID(GetScriptForDestination(WitnessV0KeyHash(mnInfo.pubKeyCollateralAddress.GetID()))))));
        obj.push_back(Pair("lastseen",              mnInfo.nTimeLastPing));
        obj.push_back(Pair("activeseconds",         mnInfo.nTimeLastPing - mnInfo.sigTime));
        obj.push_back(Pair("activationblockheight", mnInfo.activationBlockHeight));
        obj.push_back(Pair("lastpaidprimary",       mnInfo.nTimeLastPaidPrimary));
        obj.push_back(Pair("lastpaidsecondary",     mnInfo.nTimeLastPaidSecondary));
        return obj;
    }

    if (strCommand == "maturity")
    {
        if (request.params.size() < 2)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Please specify a masternode");

        for (CWalletRef pwallet : vpwallets) {
            EnsureWalletIsUnlocked(pwallet);
            LOCK(pwallet->cs_wallet);
        }

        // needed parameter(s):
        // masternode identifier either a genx address or outpoint
        // block at which to calculate (optional) if not specified, will calculate at the current block height
        // show manual calc vs. using call

        // A local list of masternodes
        CMasternode node;
        std::map<COutPoint, CMasternode> mapMasternodes = mnodeman.GetFullMasternodeMap();
        bool fFound = false;
        int nHeight = 0;

        // format: masternode maturity address
        if (request.params.size() == 2 || request.params.size() == 3)
        {
            std::string strAddress = request.params[1].get_str();
            if (strAddress.length() == 0)
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Please specify a masternode");
            }
            else if (strAddress.length() == 34)
            {
                // genx address
                for (const auto& mnpair : mapMasternodes) {
                    CTxDestination address = CScriptID(GetScriptForDestination(WitnessV0KeyHash(mnpair.second.pubKeyCollateralAddress.GetID())));
                    std::string strCompare = EncodeDestination(address);
                    if (strCompare == strAddress)
                    {
                        node = mnpair.second;
                        fFound = true;
                    }
                    // else
                    // {
                    //     fprintf(stdout, "%s is not %s \n", strCompare.c_str(), strAddress.c_str());
                    // }
                }
            }
            else if (strAddress.length() == 46)
            {
                // script
                for (const auto& mnpair : mapMasternodes) {
                    std::string strOutpoint = mnpair.first.ToStringShort();
                    std::string strCompare = HexStr(mnpair.second.pubKeyMasternode);
                    if (strOutpoint.find(strAddress) != std::string::npos || strAddress == strCompare)
                    {
                        node = mnpair.second;
                        fFound = true;
                    }
                }
            }
            else if (strAddress.length() == 66)
            {
                // outpoint
                // e.g.: 7611ef05f9666c8b6698042674dd079f002b558dd9e851ecb6dda84d84c16239-1 
                for (const auto& mnpair : mapMasternodes) {
                    std::string strCompare = mnpair.first.ToStringShort();
                    if (strCompare == strAddress)
                    {
                        node = mnpair.second;
                        fFound = true;
                    }
                }
            }
            else if (std::count(strAddress.begin(), strAddress.end(), '.') == 3)
            {
                // looks kinda like an ip address - yes, I know this is not a great solution...
                for (const auto& mnpair : mapMasternodes) {
                    std::string strCompare = mnpair.second.addr.ToStringIP();
                    if (strCompare == strAddress)
                    {
                        node = mnpair.second;
                        fFound = true;
                    }
                }
            }
        }

        if (request.params.size() == 2)
        {
            // Use the current chain height
            LOCK(cs_main);
            CBlockIndex* pindex = chainActive.Tip();
            if (!pindex) return NullUniValue;
            nHeight = pindex->nHeight;
        }
        else if (request.params.size() == 3)
        {
            // use the specified height
            nHeight = atoi(request.params[2].get_str());
        }

        int activationHeight = node.activationBlockHeight;

        // Some basic validation
        if (nHeight < Params().GetConsensus().nMasternodePaymentsStartBlock || nHeight < activationHeight)
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Please specify a valid block height");
        }

        // Establish base values
        CAmount totalReward = Params().GetConsensus().nBlockRewardMasternode * COIN;
        int thresholdAge = Params().GetConsensus().nMasternodeMaturityThreshold * Params().GetConsensus().nMasternodeMaturityBlockMultiplier;
        CAmount maxSecondaryCount = Params().GetConsensus().nMasternodeMaturitySecondariesMaxCount;
        CAmount minimumSecondaryDeduction = (maxSecondaryCount * Params().GetConsensus().aMasternodeMaturiySecondariesMinAmount) * COIN;
        CAmount minimumPrimaryPayment = Params().GetConsensus().aMasternodeMaturiySecondariesMinAmount * COIN;
        CAmount blockRewardBase = GetBlockSubsidy(nHeight, Params().GetConsensus());
        CAmount allowedPayment = totalReward - minimumSecondaryDeduction;
        int blockAge = nHeight - activationHeight;

        // Using Calls...
        CAmount maxMasternodePayment = GetMasternodePayments(nHeight, activationHeight, blockRewardBase);
        CAmount actualMasternodePayment = 0;

        if (blockAge >= thresholdAge)
        {
            actualMasternodePayment = allowedPayment;
        }
        else
        {
            actualMasternodePayment = ceil((allowedPayment / (double)thresholdAge) * (double)blockAge);
        }

        UniValue obj(UniValue::VOBJ);
        if (!fFound) {
            obj.push_back(Pair("result", "failed"));
            obj.push_back(Pair("errorMessage", "Could not find the masternode"));
        }
        else
        {
            // Base
            obj.push_back(Pair("height", nHeight));
            obj.push_back(Pair("block_subsidy", blockRewardBase));
            obj.push_back(Pair("masternode_subsidy_total", totalReward));
            // Thresholds
            obj.push_back(Pair("threshold_block_age", thresholdAge));
            obj.push_back(Pair("max_secondary_masternode_count", maxSecondaryCount));
            obj.push_back(Pair("min_masternode_payment", minimumPrimaryPayment));
            obj.push_back(Pair("max_masternode_payment", allowedPayment));
            // Metrics
            obj.push_back(Pair("activation_block_height", activationHeight));
            obj.push_back(Pair("block_age", blockAge));
            obj.push_back(Pair("matured_amount_actual", actualMasternodePayment));
            obj.push_back(Pair("matured_amount_reported", maxMasternodePayment));
        }

        return obj;
    }

#ifdef ENABLE_WALLET
    if (strCommand == "start-alias")
    {
        if (request.params.size() < 2)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Please specify an alias");

        for (CWalletRef pwallet : vpwallets) {
            EnsureWalletIsUnlocked(pwallet);
            LOCK(pwallet->cs_wallet);
        }

        std::string strAlias = request.params[1].get_str();

        bool fFound = false;

        UniValue statusObj(UniValue::VOBJ);
        statusObj.push_back(Pair("alias", strAlias));

        for (const auto& mne : masternodeConfig.getEntries()) {
            if (mne.getAlias() == strAlias) {
                fFound = true;
                std::string strError;
                CMasternodeBroadcast mnb;

                bool fResult = CMasternodeBroadcast::Create(mne.getIp(), mne.getPrivKey(), mne.getTxHash(), mne.getOutputIndex(), strError, mnb);
                
                int nDoS;
                if (fResult && !mnodeman.CheckMnbAndUpdateMasternodeList(NULL, mnb, nDoS, *g_connman)) {
                    strError = "Failed to verify MNB";
                    fResult = false;
                }

                statusObj.push_back(Pair("result", fResult ? "successful" : "failed"));
                if (!fResult) {
                    statusObj.push_back(Pair("errorMessage", strError));
                }
                mnodeman.NotifyMasternodeUpdates(*g_connman);
                break;
            }
        }

        if (!fFound) {
            statusObj.push_back(Pair("result", "failed"));
            statusObj.push_back(Pair("errorMessage", "Could not find alias in config. Verify with list-conf."));
        }

        return statusObj;

    }

    if (strCommand == "start-all" || strCommand == "start-missing" || strCommand == "start-disabled")
    {
        for (CWalletRef pwallet : vpwallets) {
            EnsureWalletIsUnlocked(pwallet);
            LOCK(pwallet->cs_wallet);
        }

        if ((strCommand == "start-missing" || strCommand == "start-disabled") && !masternodeSync.IsMasternodeListSynced()) {
            throw JSONRPCError(RPC_CLIENT_IN_INITIAL_DOWNLOAD, "You can't use this command until masternode list is synced");
        }

        int nSuccessful = 0;
        int nFailed = 0;

        UniValue resultsObj(UniValue::VOBJ);

        for (const auto& mne : masternodeConfig.getEntries()) {
            std::string strError;

            COutPoint outpoint = COutPoint(uint256S(mne.getTxHash()), (uint32_t)atoi(mne.getOutputIndex()));
            CMasternode mn;
            bool fFound = mnodeman.Get(outpoint, mn);
            CMasternodeBroadcast mnb;

            if (strCommand == "start-missing" && fFound) continue;
            if (strCommand == "start-disabled" && fFound && mn.IsEnabled()) continue;

            bool fResult = CMasternodeBroadcast::Create(mne.getIp(), mne.getPrivKey(), mne.getTxHash(), mne.getOutputIndex(), strError, mnb);

            int nDoS;
            if (fResult && !mnodeman.CheckMnbAndUpdateMasternodeList(NULL, mnb, nDoS, *g_connman)) {
                strError = "Failed to verify MNB";
                fResult = false;
            }

            UniValue statusObj(UniValue::VOBJ);
            statusObj.push_back(Pair("alias", mne.getAlias()));
            statusObj.push_back(Pair("result", fResult ? "successful" : "failed"));

            if (fResult) {
                nSuccessful++;
            } else {
                nFailed++;
                statusObj.push_back(Pair("errorMessage", strError));
            }

            resultsObj.push_back(Pair("status", statusObj));
        }
        mnodeman.NotifyMasternodeUpdates(*g_connman);

        UniValue returnObj(UniValue::VOBJ);
        returnObj.push_back(Pair("overall", strprintf("Successfully started %d masternodes, failed to start %d, total %d", nSuccessful, nFailed, nSuccessful + nFailed)));
        returnObj.push_back(Pair("detail", resultsObj));

        return returnObj;
    }
#endif // ENABLE_WALLET

    if (strCommand == "genkey")
    {
        CKey secret;
        secret.MakeNewKey(false);

        return CGenesisSecret(secret).ToString();
    }

    if (strCommand == "list-conf")
    {
        UniValue resultObj(UniValue::VOBJ);

        for (const auto& mne : masternodeConfig.getEntries()) {
            COutPoint outpoint = COutPoint(uint256S(mne.getTxHash()), (uint32_t)atoi(mne.getOutputIndex()));
            CMasternode mn;
            bool fFound = mnodeman.Get(outpoint, mn);

            std::string strStatus = fFound ? mn.GetStatus() : "MISSING";

            // Better formatting for network address (only for IPV4)
            std::string s = mne.getIp();
            std::string delimiter = ":";
            size_t pos = 0;
            std::string mnip = "";
            std::string mnport = "";
            std::string token;
            while ((pos = s.find(delimiter)) != std::string::npos) {
                token = s.substr(0, pos);
                mnip = token;
                s.erase(0, pos + delimiter.length());
            }
            mnport = s;

            UniValue mnObj(UniValue::VOBJ);
            mnObj.push_back(Pair("alias", mne.getAlias()));
            mnObj.push_back(Pair("ip", mnip));
            mnObj.push_back(Pair("port", mnport));
            mnObj.push_back(Pair("privateKey", mne.getPrivKey()));
            mnObj.push_back(Pair("txHash", mne.getTxHash()));
            mnObj.push_back(Pair("outputIndex", mne.getOutputIndex()));
            mnObj.push_back(Pair("status", strStatus));
            mnObj.push_back(Pair("activationBlockHeight", mn.activationBlockHeight));
            mnObj.push_back(Pair("lastPaidBlockPrimary", mn.nBlockLastPaidPrimary));
            mnObj.push_back(Pair("lastPaidBlockSecondary", mn.nBlockLastPaidSecondary));
            resultObj.push_back(Pair(mne.getAlias(), mnObj));
        }

        return resultObj;
    }

#ifdef ENABLE_WALLET
    if (strCommand == "outputs") {
        // Find possible candidates
        std::vector<COutput> vPossibleCoins;
        
        for (CWalletRef pwallet : vpwallets) {
            pwallet->AvailableMNCoins(vPossibleCoins, true, NULL, false);
        }

        UniValue obj(UniValue::VOBJ);
        for (const auto& out : vPossibleCoins) {
            obj.push_back(Pair(out.tx->GetHash().ToString(), strprintf("%d", out.i)));
        }

        return obj;
    }
#endif // ENABLE_WALLET

    if (strCommand == "status")
    {
        if (!fMasternodeMode)
            throw JSONRPCError(RPC_INTERNAL_ERROR, "This is not a masternode");

        UniValue mnObj(UniValue::VOBJ);

        mnObj.push_back(Pair("outpoint", activeMasternode.outpoint.ToStringShort()));
        mnObj.push_back(Pair("service", activeMasternode.service.ToString()));

        CMasternode mn;
        if (mnodeman.Get(activeMasternode.outpoint, mn)) {
            mnObj.push_back(Pair("payee", EncodeDestination(CScriptID(GetScriptForDestination(WitnessV0KeyHash(mn.pubKeyCollateralAddress.GetID()))))));
        }

        mnObj.push_back(Pair("status", activeMasternode.GetStatus()));
        mnObj.push_back(Pair("activation_block_height", activeMasternode.activationBlockHeight));

        return mnObj;
    }

    if (strCommand == "winners")
    {
        int nHeight;
        {
            LOCK(cs_main);
            CBlockIndex* pindex = chainActive.Tip();
            if (!pindex) return NullUniValue;

            nHeight = pindex->nHeight;
        }

        int nLast = 10;
        std::string strFilter = "";

        if (request.params.size() >= 2) {
            nLast = atoi(request.params[1].get_str());
        }

        if (request.params.size() == 3) {
            strFilter = request.params[2].get_str();
        }

        if (request.params.size() > 3)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Correct usage is 'masternode winners ( \"count\" \"filter\" )'");

        UniValue obj(UniValue::VOBJ);

        for(int i = nHeight - nLast; i < nHeight + 20; i++) {
            std::string strPayment = GetRequiredPaymentsString(i);
            if (strFilter !="" && strPayment.find(strFilter) == std::string::npos) continue;
            obj.push_back(Pair(strprintf("%d", i), strPayment));
        }

        return obj;
    }

    return NullUniValue;
}

UniValue masternodelist(const JSONRPCRequest& request)
{
    std::string strMode = "json";
    std::string strFilter = "";

    if (request.params.size() >= 1) strMode = request.params[0].get_str();
    if (request.params.size() == 2) strFilter = request.params[1].get_str();

    if (request.fHelp || (
                strMode != "activeseconds" && strMode != "addr" && strMode != "daemon" && strMode != "full" && strMode != "info" && strMode != "json" &&
                strMode != "lastseen" && 
                strMode != "lastpaidtime"  && strMode != "lastpaidtimes"  && strMode != "lastpaidtimeprimary"  && strMode != "lastpaidtimesecondary" && 
                strMode != "lastpaidblock" && strMode != "lastpaidblocks" && strMode != "lastpaidblockprimary" && strMode != "lastpaidblocksecondary" &&
                strMode != "protocol" && strMode != "payee" && strMode != "pubkey" && strMode != "posebanscore" &&
                strMode != "rank" && strMode != "sentinel" && strMode != "status"))
    {
        throw std::runtime_error(
                "masternodelist ( \"mode\" \"filter\" )\n"
                "Get a list of masternodes in different modes\n"
                "\nArguments:\n"
                "1. \"mode\"      (string, optional/required to use filter, defaults = json) The mode to run list in\n"
                "2. \"filter\"    (string, optional) Filter results. Partial match by outpoint by default in all modes,\n"
                "                                    additional matches in some modes are also available\n"
                "\nAvailable modes:\n"
                "  activation_block_height  - Print the block height at which a masternode was activated\n"
                "  activeseconds            - Print number of seconds masternode recognized by the network as enabled\n"
                "                               (since latest issued \"masternode start/start-many/start-alias\")\n"
                "  addr                     - Print ip address associated with a masternode (can be additionally filtered, partial match)\n"
                "  daemon                   - Print daemon version of a masternode (can be additionally filtered, exact match)\n"
                "  full                     - Print info in format 'status protocol payee lastseen activeseconds lastpaidtime lastpaidblock IP'\n"
                "                               (can be additionally filtered, partial match)\n"
                "  info                     - Print info in format 'status protocol payee lastseen activeseconds sentinelversion sentinelstate IP'\n"
                "                             (can be additionally filtered, partial match)\n"
                "  json                     - Print info in JSON format (can be additionally filtered, partial match)\n"
                "  lastpaidblockprimary     - Print the last block height a node was paid on the network as a primary\n"
                "  lastpaidblock            - alias for lastpaidblock\n"
                "  lastpaidblocksecondary   - Print the last block height a node was paid on the network as a secondary\n"
                "  lastpaidblocks           - Print the last block heights a node was paid on the network as either a primary or secondary\n"
                "  lastpaidtimeprimary      - Print the last time a node was paid on the network as a primary\n"
                "  lastpaidtime             - Alias for lastpaidtimeprimary\n"
                "  lastpaidtimesecondary    - Print the last time a node was paid on the network as a secondary\n"
                "  lastpaidtimes            - Print the last times a node was paid on the network as either a primary or secondary\n"
                "  lastseen                 - Print timestamp of when a masternode was last seen on the network\n"
                "  payee                    - Print Genesis address associated with a masternode (can be additionally filtered,\n"
                "                               partial match)\n"
                "  posebanscore             - Print PoSeBan score of a masternode\n"
                "  protocol                 - Print protocol of a masternode (can be additionally filtered, exact match)\n"
                "  pubkey                   - Print the masternode (not collateral) public key\n"
                "  rank                     - Print rank of a masternode based on current block\n"
                "  sentinel                 - Print sentinel version of a masternode (can be additionally filtered, exact match)\n"
                "  status                   - Print masternode status: PRE_ENABLED / ENABLED / EXPIRED / SENTINEL_PING_EXPIRED / NEW_START_REQUIRED /\n"
                "                               UPDATE_REQUIRED / POSE_BAN / OUTPOINT_SPENT (can be additionally filtered, partial match)\n"
                );
    }

    if (
        strMode == "full" || 
        strMode == "json" || 
        strMode == "lastpaidtime" || 
        strMode == "lastpaidtimes" || 
        strMode == "lastpaidtimeprimary" || 
        strMode == "lastpaidtimesecondary" || 
        strMode == "lastpaidblock" ||
        strMode == "lastpaidblocks" ||
        strMode == "lastpaidblockprimary" ||
        strMode == "lastpaidblocksecondary"
        ) {
        CBlockIndex* pindex = NULL;
        {
            LOCK(cs_main);
            pindex = chainActive.Tip();
        }
        mnodeman.UpdateLastPaid(pindex);
    }

    UniValue obj(UniValue::VOBJ);
    if (strMode == "rank") {
        CMasternodeMan::rank_pair_vec_t vMasternodeRanks;
        mnodeman.GetMasternodeRanks(vMasternodeRanks);
        for (const auto& rankpair : vMasternodeRanks) {
            std::string strOutpoint = rankpair.second.outpoint.ToStringShort();
            if (strFilter !="" && strOutpoint.find(strFilter) == std::string::npos) continue;
            obj.push_back(Pair(strOutpoint, rankpair.first));
        }
    } else {
        std::map<COutPoint, CMasternode> mapMasternodes = mnodeman.GetFullMasternodeMap();
        for (const auto& mnpair : mapMasternodes) {
            CMasternode mn = mnpair.second;
            std::string strOutpoint = mnpair.first.ToStringShort();
            if (strMode == "activeseconds") {
                if (strFilter !="" && strOutpoint.find(strFilter) == std::string::npos) continue;
                obj.push_back(Pair(strOutpoint, (int64_t)(mn.lastPing.sigTime - mn.sigTime)));
            } else if (strMode == "addr") {
                std::string strAddress = mn.addr.ToString();
                if (strFilter !="" && strAddress.find(strFilter) == std::string::npos &&
                    strOutpoint.find(strFilter) == std::string::npos) continue;
                obj.push_back(Pair(strOutpoint, strAddress));
            } else if (strMode == "daemon") {
                std::string strDaemon = mn.lastPing.nDaemonVersion > DEFAULT_DAEMON_VERSION ? FormatVersion(mn.lastPing.nDaemonVersion) : "Unknown";
                if (strFilter !="" && strDaemon.find(strFilter) == std::string::npos &&
                    strOutpoint.find(strFilter) == std::string::npos) continue;
                obj.push_back(Pair(strOutpoint, strDaemon));
            } else if (strMode == "sentinel") {
                std::string strSentinel = mn.lastPing.nSentinelVersion > DEFAULT_SENTINEL_VERSION ? SafeIntVersionToString(mn.lastPing.nSentinelVersion) : "Unknown";
                if (strFilter !="" && strSentinel.find(strFilter) == std::string::npos &&
                    strOutpoint.find(strFilter) == std::string::npos) continue;
                obj.push_back(Pair(strOutpoint, strSentinel));
            } else if (strMode == "full") {
                std::ostringstream streamFull;
                streamFull << std::setw(18) <<
                               mn.GetStatus() << " " <<
                               mn.nProtocolVersion << " " <<
                               EncodeDestination(CScriptID(GetScriptForDestination(WitnessV0KeyHash(mn.pubKeyCollateralAddress.GetID())))) << " " <<
                               (int64_t)mn.lastPing.sigTime << " " << std::setw(8) <<
                               (int64_t)(mn.lastPing.sigTime - mn.sigTime) << " " << std::setw(10) <<
                               mn.GetLastPaidTimePrimary() << " "  << std::setw(6) <<
                               mn.GetLastPaidBlockPrimary() << " " <<
                               mn.GetLastPaidTimeSecondary() << " "  << std::setw(6) <<
                               mn.GetLastPaidBlockSecondary() << " " <<
                               mn.addr.ToString();
                std::string strFull = streamFull.str();
                if (strFilter !="" && strFull.find(strFilter) == std::string::npos &&
                    strOutpoint.find(strFilter) == std::string::npos) continue;
                obj.push_back(Pair(strOutpoint, strFull));
            } else if (strMode == "info") {
                std::ostringstream streamInfo;
                streamInfo << std::setw(18) <<
                               mn.GetStatus() << " " <<
                               mn.nProtocolVersion << " " <<
                               EncodeDestination(CScriptID(GetScriptForDestination(WitnessV0KeyHash(mn.pubKeyCollateralAddress.GetID())))) << " " <<
                               (int64_t)mn.lastPing.sigTime << " " << std::setw(8) <<
                               (int64_t)(mn.lastPing.sigTime - mn.sigTime) << " " <<
                               SafeIntVersionToString(mn.lastPing.nSentinelVersion) << " "  <<
                               (mn.lastPing.fSentinelIsCurrent ? "current" : "expired") << " " <<
                               mn.addr.ToString();
                std::string strInfo = streamInfo.str();
                if (strFilter !="" && strInfo.find(strFilter) == std::string::npos &&
                    strOutpoint.find(strFilter) == std::string::npos) continue;
                obj.push_back(Pair(strOutpoint, strInfo));
            } else if (strMode == "json") {
                std::ostringstream streamInfo;
                streamInfo <<  mn.addr.ToStringIP() << " " <<
                               mn.addr.ToStringPort() << " " <<
                               EncodeDestination(mn.pubKeyCollateralAddress.GetID()) << " " <<
                               EncodeDestination(CScriptID(GetScriptForDestination(WitnessV0KeyHash(mn.pubKeyCollateralAddress.GetID())))) << " " <<
                               mn.GetStatus() << " " <<
                               mn.nProtocolVersion << " " <<
                               mn.lastPing.nDaemonVersion << " " <<
                               SafeIntVersionToString(mn.lastPing.nSentinelVersion) << " " <<
                               (mn.lastPing.fSentinelIsCurrent ? "current" : "expired") << " " <<
                               (int64_t)mn.lastPing.sigTime << " " <<
                               (int64_t)(mn.lastPing.sigTime - mn.sigTime) << " " <<
                               mn.GetLastPaidTimePrimary() << " " <<
                               mn.GetLastPaidBlockPrimary() << " " <<
                               mn.GetLastPaidTimeSecondary() << " " <<
                               mn.GetLastPaidBlockSecondary() << " " <<
                               mn.nPoSeBanScore <<
                               mn.activationBlockHeight;
                std::string strInfo = streamInfo.str();
                if (strFilter !="" && strInfo.find(strFilter) == std::string::npos &&
                    strOutpoint.find(strFilter) == std::string::npos) continue;
                UniValue objMN(UniValue::VOBJ);
                objMN.push_back(Pair("ip", mn.addr.ToStringIP()));
                objMN.push_back(Pair("port", mn.addr.ToStringPort()));
                objMN.push_back(Pair("payee", EncodeDestination(CScriptID(GetScriptForDestination(WitnessV0KeyHash(mn.pubKeyCollateralAddress.GetID()))))));
                objMN.push_back(Pair("status", mn.GetStatus()));
                objMN.push_back(Pair("protocol", mn.nProtocolVersion));
                objMN.push_back(Pair("daemonversion", mn.lastPing.nDaemonVersion > DEFAULT_DAEMON_VERSION ? FormatVersion(mn.lastPing.nDaemonVersion) : "Unknown"));
                objMN.push_back(Pair("sentinelversion", mn.lastPing.nSentinelVersion > DEFAULT_SENTINEL_VERSION ? SafeIntVersionToString(mn.lastPing.nSentinelVersion) : "Unknown"));
                objMN.push_back(Pair("sentinelstate", (mn.lastPing.fSentinelIsCurrent ? "current" : "expired")));
                objMN.push_back(Pair("lastseen", (int64_t)mn.lastPing.sigTime));
                objMN.push_back(Pair("activeseconds", (int64_t)(mn.lastPing.sigTime - mn.sigTime)));
                objMN.push_back(Pair("lastpaidtimeprimary", mn.GetLastPaidTimePrimary()));
                objMN.push_back(Pair("lastpaidblockprimary", mn.GetLastPaidBlockPrimary()));
                objMN.push_back(Pair("lastpaidtimesecondary", mn.GetLastPaidTimeSecondary()));
                objMN.push_back(Pair("lastpaidblocksecondary", mn.GetLastPaidBlockSecondary()));
                objMN.push_back(Pair("posebanscore", mn.nPoSeBanScore));
                objMN.push_back(Pair("activation_block_height", mn.activationBlockHeight));
                obj.push_back(Pair(strOutpoint, objMN));
            } else if (strMode == "lastpaidblock" || strMode == "lastpaidblockprimary") {
                if (strFilter !="" && strOutpoint.find(strFilter) == std::string::npos) continue;
                obj.push_back(Pair(strOutpoint, mn.GetLastPaidBlockPrimary()));
            } else if (strMode == "lastpaidblocksecondary") {
                if (strFilter !="" && strOutpoint.find(strFilter) == std::string::npos) continue;
                obj.push_back(Pair(strOutpoint, mn.GetLastPaidBlockSecondary()));
            } else if (strMode == "lastpaidblocks") {
                if (strFilter !="" && strOutpoint.find(strFilter) == std::string::npos) continue;
                UniValue lpbObj(UniValue::VOBJ);
                lpbObj.push_back(Pair("primary", mn.GetLastPaidBlockPrimary()));
                lpbObj.push_back(Pair("secondary", mn.GetLastPaidBlockSecondary()));
                obj.push_back(Pair(strOutpoint, lpbObj));
            } else if (strMode == "lastpaidtime" || strMode == "lastpaidtimeprimary") {
                if (strFilter !="" && strOutpoint.find(strFilter) == std::string::npos) continue;
                obj.push_back(Pair(strOutpoint, mn.GetLastPaidTimePrimary()));
            } else if (strMode == "lastpaidtimesecondary") {
                if (strFilter !="" && strOutpoint.find(strFilter) == std::string::npos) continue;
                obj.push_back(Pair(strOutpoint, mn.GetLastPaidTimeSecondary()));
            } else if (strMode == "lastpaidtimes") {
                if (strFilter !="" && strOutpoint.find(strFilter) == std::string::npos) continue;
                UniValue lptObj(UniValue::VOBJ);
                lptObj.push_back(Pair("primary", mn.GetLastPaidTimePrimary()));
                lptObj.push_back(Pair("secondary", mn.GetLastPaidTimeSecondary()));
                obj.push_back(Pair(strOutpoint, lptObj));
            } else if (strMode == "lastseen") {
                if (strFilter !="" && strOutpoint.find(strFilter) == std::string::npos) continue;
                obj.push_back(Pair(strOutpoint, (int64_t)mn.lastPing.sigTime));
            } else if (strMode == "payee") {
                CTxDestination address = CScriptID(GetScriptForDestination(WitnessV0KeyHash(mn.pubKeyCollateralAddress.GetID())));
                std::string strPayee = EncodeDestination(address);
                if (strFilter !="" && strPayee.find(strFilter) == std::string::npos &&
                    strOutpoint.find(strFilter) == std::string::npos) continue;
                obj.push_back(Pair(strOutpoint, strPayee));
            } else if (strMode == "posebanscore") {
                if (strFilter !="" && strOutpoint.find(strFilter) == std::string::npos) continue;
                obj.push_back(Pair(strOutpoint, mn.nPoSeBanScore));
            } else if (strMode == "protocol") {
                if (strFilter !="" && strFilter != strprintf("%d", mn.nProtocolVersion) &&
                    strOutpoint.find(strFilter) == std::string::npos) continue;
                obj.push_back(Pair(strOutpoint, mn.nProtocolVersion));
            } else if (strMode == "pubkey") {
                if (strFilter !="" && strOutpoint.find(strFilter) == std::string::npos) continue;
                obj.push_back(Pair(strOutpoint, HexStr(mn.pubKeyMasternode)));
            } else if (strMode == "status") {
                std::string strStatus = mn.GetStatus();
                if (strFilter !="" && strStatus.find(strFilter) == std::string::npos &&
                    strOutpoint.find(strFilter) == std::string::npos) continue;
                obj.push_back(Pair(strOutpoint, strStatus));
            } else if (strMode == "activation_block_height") {
                if (strFilter !="" && strOutpoint.find(strFilter) == std::string::npos) continue;
                obj.push_back(Pair(strOutpoint, mn.activationBlockHeight));
            }
        }
    }
    return obj;
}

bool DecodeHexVecMnb(std::vector<CMasternodeBroadcast>& vecMnb, std::string strHexMnb) {

    if (!IsHex(strHexMnb))
        return false;

    std::vector<unsigned char> mnbData(ParseHex(strHexMnb));
    CDataStream ssData(mnbData, SER_NETWORK, PROTOCOL_VERSION);
    try {
        ssData >> vecMnb;
    }
    catch (const std::exception&) {
        return false;
    }

    return true;
}

UniValue masternodebroadcast(const JSONRPCRequest& request)
{
    std::string strCommand;
    if (request.params.size() >= 1)
        strCommand = request.params[0].get_str();

    if (request.fHelp  ||
        (
#ifdef ENABLE_WALLET
            strCommand != "create-alias" && strCommand != "create-all" &&
#endif // ENABLE_WALLET
            strCommand != "decode" && strCommand != "relay"))
        throw std::runtime_error(
                "masternodebroadcast \"command\"...\n"
                "Set of commands to create and relay masternode broadcast messages\n"
                "\nArguments:\n"
                "1. \"command\"        (string or set of strings, required) The command to execute\n"
                "\nAvailable commands:\n"
#ifdef ENABLE_WALLET
                "  create-alias  - Create single remote masternode broadcast message by assigned alias configured in masternode.conf\n"
                "  create-all    - Create remote masternode broadcast messages for all masternodes configured in masternode.conf\n"
#endif // ENABLE_WALLET
                "  decode        - Decode masternode broadcast message\n"
                "  relay         - Relay masternode broadcast message to the network\n"
                );

#ifdef ENABLE_WALLET
    if (strCommand == "create-alias")
    {
        // wait for reindex and/or import to finish
        if (fImporting || fReindex)
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Wait for reindex and/or import to finish");

        if (request.params.size() < 2)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Please specify an alias");

        for (CWalletRef pwallet : vpwallets) {
            EnsureWalletIsUnlocked(pwallet);
            LOCK(pwallet->cs_wallet);
        }

        bool fFound = false;
        std::string strAlias = request.params[1].get_str();

        UniValue statusObj(UniValue::VOBJ);
        std::vector<CMasternodeBroadcast> vecMnb;

        statusObj.push_back(Pair("alias", strAlias));

        for (const auto& mne : masternodeConfig.getEntries()) {
            if (mne.getAlias() == strAlias) {
                fFound = true;
                std::string strError;
                CMasternodeBroadcast mnb;

                bool fResult = CMasternodeBroadcast::Create(mne.getIp(), mne.getPrivKey(), mne.getTxHash(), mne.getOutputIndex(), strError, mnb, true);

                statusObj.push_back(Pair("result", fResult ? "successful" : "failed"));
                if (fResult) {
                    vecMnb.push_back(mnb);
                    CDataStream ssVecMnb(SER_NETWORK, PROTOCOL_VERSION);
                    ssVecMnb << vecMnb;
                    statusObj.push_back(Pair("hex", HexStr(ssVecMnb)));
                } else {
                    statusObj.push_back(Pair("errorMessage", strError));
                }
                break;
            }
        }

        if (!fFound) {
            statusObj.push_back(Pair("result", "not found"));
            statusObj.push_back(Pair("errorMessage", "Could not find alias in config. Verify with list-conf."));
        }

        return statusObj;

    }

    if (strCommand == "create-all")
    {
        // wait for reindex and/or import to finish
        if (fImporting || fReindex)
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Wait for reindex and/or import to finish");

        for (CWalletRef pwallet : vpwallets) {
            EnsureWalletIsUnlocked(pwallet);
            LOCK(pwallet->cs_wallet);
        }

        int nSuccessful = 0;
        int nFailed = 0;

        UniValue resultsObj(UniValue::VOBJ);
        std::vector<CMasternodeBroadcast> vecMnb;

        for (const auto& mne : masternodeConfig.getEntries()) {
            std::string strError;
            CMasternodeBroadcast mnb;

            bool fResult = CMasternodeBroadcast::Create(mne.getIp(), mne.getPrivKey(), mne.getTxHash(), mne.getOutputIndex(), strError, mnb, true);

            UniValue statusObj(UniValue::VOBJ);
            statusObj.push_back(Pair("alias", mne.getAlias()));
            statusObj.push_back(Pair("result", fResult ? "successful" : "failed"));

            if (fResult) {
                nSuccessful++;
                vecMnb.push_back(mnb);
            } else {
                nFailed++;
                statusObj.push_back(Pair("errorMessage", strError));
            }

            resultsObj.push_back(Pair("status", statusObj));
        }

        CDataStream ssVecMnb(SER_NETWORK, PROTOCOL_VERSION);
        ssVecMnb << vecMnb;
        UniValue returnObj(UniValue::VOBJ);
        returnObj.push_back(Pair("overall", strprintf("Successfully created broadcast messages for %d masternodes, failed to create %d, total %d", nSuccessful, nFailed, nSuccessful + nFailed)));
        returnObj.push_back(Pair("detail", resultsObj));
        returnObj.push_back(Pair("hex", HexStr(ssVecMnb.begin(), ssVecMnb.end())));

        return returnObj;
    }
#endif // ENABLE_WALLET

    if (strCommand == "decode")
    {
        if (request.params.size() != 2)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Correct usage is 'masternodebroadcast decode \"hexstring\"'");

        std::vector<CMasternodeBroadcast> vecMnb;

        if (!DecodeHexVecMnb(vecMnb, request.params[1].get_str()))
            throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Masternode broadcast message decode failed");

        int nSuccessful = 0;
        int nFailed = 0;
        int nDos = 0;
        UniValue returnObj(UniValue::VOBJ);

        for (const auto& mnb : vecMnb) {
            UniValue resultObj(UniValue::VOBJ);

            if (mnb.CheckSignature(nDos)) {
                nSuccessful++;
                resultObj.push_back(Pair("outpoint", mnb.outpoint.ToStringShort()));
                resultObj.push_back(Pair("addr", mnb.addr.ToString()));
                resultObj.push_back(Pair("pubKeyCollateralAddress", EncodeDestination(CScriptID(GetScriptForDestination(WitnessV0KeyHash(mnb.pubKeyCollateralAddress.GetID()))))));
                resultObj.push_back(Pair("pubKeyMasternode", EncodeDestination(CScriptID(GetScriptForDestination(WitnessV0KeyHash(mnb.pubKeyMasternode.GetID()))))));
                resultObj.push_back(Pair("vchSig", EncodeBase64(&mnb.vchSig[0], mnb.vchSig.size())));
                resultObj.push_back(Pair("sigTime", mnb.sigTime));
                resultObj.push_back(Pair("protocolVersion", mnb.nProtocolVersion));
                resultObj.push_back(Pair("nLastDsq", mnb.nLastDsq));

                UniValue lastPingObj(UniValue::VOBJ);
                lastPingObj.push_back(Pair("outpoint", mnb.lastPing.masternodeOutpoint.ToStringShort()));
                lastPingObj.push_back(Pair("blockHash", mnb.lastPing.blockHash.ToString()));
                lastPingObj.push_back(Pair("sigTime", mnb.lastPing.sigTime));
                lastPingObj.push_back(Pair("vchSig", EncodeBase64(&mnb.lastPing.vchSig[0], mnb.lastPing.vchSig.size())));

                resultObj.push_back(Pair("lastPing", lastPingObj));
            } else {
                nFailed++;
                resultObj.push_back(Pair("errorMessage", "Masternode broadcast signature verification failed"));
            }

            returnObj.push_back(Pair(mnb.GetHash().ToString(), resultObj));
        }

        returnObj.push_back(Pair("overall", strprintf("Successfully decoded broadcast messages for %d masternodes, failed to decode %d, total %d", nSuccessful, nFailed, nSuccessful + nFailed)));

        return returnObj;
    }

    if (strCommand == "relay")
    {
        if (request.params.size() < 2 || request.params.size() > 3)
            throw JSONRPCError(RPC_INVALID_PARAMETER,   "masternodebroadcast relay \"hexstring\"\n"
                                                        "\nArguments:\n"
                                                        "1. \"hex\"      (string, required) Broadcast messages hex string\n");

        std::vector<CMasternodeBroadcast> vecMnb;

        if (!DecodeHexVecMnb(vecMnb, request.params[1].get_str()))
            throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Masternode broadcast message decode failed");

        int nSuccessful = 0;
        int nFailed = 0;
        UniValue returnObj(UniValue::VOBJ);

        // verify all signatures first, bailout if any of them broken
        for (const auto& mnb : vecMnb) {
            UniValue resultObj(UniValue::VOBJ);

            resultObj.push_back(Pair("outpoint", mnb.outpoint.ToStringShort()));
            resultObj.push_back(Pair("addr", mnb.addr.ToString()));

            int nDos = 0;
            bool fResult;
            if (mnb.CheckSignature(nDos)) {
                fResult = mnodeman.CheckMnbAndUpdateMasternodeList(NULL, mnb, nDos, *g_connman);
                mnodeman.NotifyMasternodeUpdates(*g_connman);
            } else fResult = false;

            if (fResult) {
                nSuccessful++;
                resultObj.push_back(Pair(mnb.GetHash().ToString(), "successful"));
            } else {
                nFailed++;
                resultObj.push_back(Pair("errorMessage", "Masternode broadcast signature verification failed"));
            }

            returnObj.push_back(Pair(mnb.GetHash().ToString(), resultObj));
        }

        returnObj.push_back(Pair("overall", strprintf("Successfully relayed broadcast messages for %d masternodes, failed to relay %d, total %d", nSuccessful, nFailed, nSuccessful + nFailed)));

        return returnObj;
    }

    return NullUniValue;
}

UniValue sentinelping(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1) {
        throw std::runtime_error(
            "sentinelping version\n"
            "\nSentinel ping.\n"
            "\nArguments:\n"
            "1. version           (string, required) Sentinel version in the form \"x.x.x\"\n"
            "\nResult:\n"
            "state                (boolean) Ping result\n"
            "\nExamples:\n"
            + HelpExampleCli("sentinelping", "1.0.2")
            + HelpExampleRpc("sentinelping", "1.0.2")
        );
    }

    activeMasternode.UpdateSentinelPing(StringVersionToInt(request.params[0].get_str()));
    return true;
}

UniValue mnsync(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "mnsync [status|next|reset]\n"
            "Returns the sync status, updates to the next step or resets it entirely.\n"
        );

    std::string strMode = request.params[0].get_str();

    if (strMode == "status") {
        UniValue objStatus(UniValue::VOBJ);
        objStatus.push_back(Pair("AssetID", masternodeSync.GetAssetID()));
        objStatus.push_back(Pair("AssetName", masternodeSync.GetAssetName()));
        objStatus.push_back(Pair("AssetStartTime", masternodeSync.GetAssetStartTime()));
        objStatus.push_back(Pair("Attempt", masternodeSync.GetAttempt()));
        objStatus.push_back(Pair("IsBlockchainSynced", masternodeSync.IsBlockchainSynced()));
        objStatus.push_back(Pair("IsMasternodeListSynced", masternodeSync.IsMasternodeListSynced()));
        objStatus.push_back(Pair("IsWinnersListSynced", masternodeSync.IsWinnersListSynced()));
        objStatus.push_back(Pair("IsSynced", masternodeSync.IsSynced()));
        objStatus.push_back(Pair("IsFailed", masternodeSync.IsFailed()));
        return objStatus;
    }

    if (strMode == "next")
    {
        masternodeSync.SwitchToNextAsset(*g_connman);
        return "sync updated to " + masternodeSync.GetAssetName();
    }

    if (strMode == "reset")
    {
        masternodeSync.Reset();
        masternodeSync.SwitchToNextAsset(*g_connman);
        return "success";
    }
    return "failure";
}

static const CRPCCommand commands[] =
{ //  category              name                      actor (function)         argNames
  //  --------------------- ------------------------  -----------------------  ----------
    { "masternodes",        "masternode",             &masternode,             {"args"} },
    { "masternodes",        "masternodelist",         &masternodelist,         {"args"} },
    { "masternodes",        "masternodebroadcast",    &masternodebroadcast,    {"args"} },
    { "masternodes",        "sentinelping",           &sentinelping,           {"args"} },
    { "masternodes",        "mnsync",                 &mnsync,                 {"args"} },
};

void RegisterMNRPCCommands(CRPCTable &t)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        t.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
