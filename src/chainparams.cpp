// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <consensus/merkle.h>

#include <uint256.h>
#include <arith_uint256.h>
#include <tinyformat.h>
#include <util.h>
#include <utilstrencodings.h>

// For equihash_parameters_acceptable.
#include <crypto/equihash/equihash.h>
#include <net.h>
#include <validation.h>
#define equihash_parameters_acceptable(N, K) \
    ((CBlockHeader::HEADER_SIZE + equihash_solution_size(N, K))*MAX_HEADERS_RESULTS < \
     MAX_PROTOCOL_MESSAGE_LENGTH-1000)

#include <base58.h>
#include <assert.h>
#include <memory>
#include <boost/assign/list_of.hpp>
#include <limits>

#include <chainparamsseeds.h>

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, const uint256& nNonce, const std::vector<unsigned char>& nSolution, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 520617983 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nSolution = nSolution;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.nHeight  = 0;
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database.
 *
 * CBlock(hash=000000000019d6, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=4a5e1e, nTime=1231006505, nBits=1d00ffff, nNonce=2083236893, vtx=1)
 *   CTransaction(hash=4a5e1e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
 *     CTxOut(nValue=50.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
 *   vMerkleTree: 4a5e1e
 */

// "Genesis was bootstrapped on Fri 17 Aug 2018 at 12:55:30 UTC BTC#537037 0000000000000000000b3e0d43c120e5b2f841500dffc89a4c2fc6027261b15a ZEC#377019 00000000053833a50c63d02a71581c668a800a5921b6086d068cc64f16ff32b6"
static CBlock CreateGenesisBlock(uint32_t nTime, const uint256& nNonce, const std::vector<unsigned char>& nSolution, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "SafeCashe317c686ae26fbaee438e3ae5a78f58409e22da083841c907be34c36977219ca";
    const CScript genesisOutputScript = CScript() << ParseHex("0405cd1787ffcf6d5b59b0f70fff5cb0946b06eea488b812cb5062b8940cb729cfbaad51729064b14465e8c4ccddae18131f4440acefdefc82a708d22208182f4f") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nSolution, nBits, nVersion, genesisReward);
}

void CChainParams::UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
{
    consensus.vDeployments[d].nStartTime = nStartTime;
    consensus.vDeployments[d].nTimeout = nTimeout;
}

/**
 * Main network
 */
/**
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 *   (no blocks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 */

const arith_uint256 maxUint = UintToArith256(uint256S("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));
class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";
        consensus.nSubsidyHalvingInterval = 210000;
        consensus.BIP16Height = 0; 
        consensus.BIP34Height = 0;
        consensus.BIP34Hash = uint256S("00015cb28cab26f2d4385a4bc261d3c88d6cafbc489dc26e6e752456f90dd26b");
        consensus.BIP65Height = 0; 
        consensus.BIP66Height = 0; 
        consensus.powLimit = uint256S("007fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; 
        consensus.nPowTargetSpacing = 60;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1916; 
        consensus.nMinerConfirmationWindow = 2016; 
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // LWMA
        consensus.nZawyLwmaAveragingWindow = 90;

        // Maturity
        consensus.nCoinbaseMaturity = 100;
        consensus.nTxMinConfirmations = 6;

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000000000000000000ac2050bc0");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00000d375549a032c60f9a857da1cbe260dcb53c1d718216f06e897fb2fe3501"); 

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0x6b; // Main 0
        pchMessageStart[1] = 0x17; // Main 1
        pchMessageStart[2] = 0xa4; // Main 2
        pchMessageStart[3] = 0xbf; // Main 3
        nDefaultPort = 7233;
        nPruneAfterHeight = 100000;

	    // Equihash
        const size_t N = 192, K = 7;
        BOOST_STATIC_ASSERT(equihash_parameters_acceptable(N, K));
        nEquihashN = N;
        nEquihashK = K;
        consensus.nPowAveragingWindow = 17;
        assert(maxUint/UintToArith256(consensus.powLimit) >= consensus.nPowAveragingWindow);
        consensus.nPowMaxAdjustDown = 32; // 32% adjustment down
        consensus.nPowMaxAdjustUp = 16; // 16% adjustment up
        // Genesis PoW
        consensus.nSuperBlockInterval = 1440; // Once a day

        genesis = CreateGenesisBlock(
            // nTime
            1534467330, 
            // nNonce
            uint256S("0x0000000000000000000000000000000000000000000000000000000000001361"), 
            // Solution
            ParseHex("0019545a491b1d80facd55446d2d71a96bb5f28f7e2e6f6da13791fdccaa5c43098e5e31c1f2991d97c20dbdd8b4542091b160dee3a3d9a5204ebb8f585c6817398d72420733a8fd1752cb33b2af84fc3a546ff712bd75cdbda9161774afb1dc953e22d2965c3e94c238fd1e34306ded01f6fea58b046891f2b3a3feb0b520345eddf3552261b2f087725f6d6226c9667fc19f42ad967b99234839938a1594723c034da096fb8c8301970edcaae66cedfda06402ca7a43024632d6a9ad17d0da1f4f57af57fdffc31e99a83f1b57debacb4c0f22fc6640958aeda42539133f7c107274159823b33f288535296e9563b16f266cb74485b1dc529b1df80e6439414d8bd449a1eff5171e32e11242097638fc1ce801cf149f6b2933ff56bd095fbbd5c7e43310e0391c6772c51157c4a3d4c42af6e745feadfa1b5c853facaf67ddda23390c1494745b2c7425922033edd900289daff722e8752d0ec4af1e3f8f0176eef3914710ab8ae932194f3f42a2f885c2486dee7d737c5ffb04c7424ac746bbebaf0473a91aa2aa8206e05ded491e3004ab5766bbddfb5f6368437fc2450d9789b343042122f6754c4783f3cdd532396a73f182a51d0880149650c044c719dd3bff532b565d62454f5dba6d9810d4f9ca3f4d7882bf28a53757cd8d460dc61ffacd129e99e245d9d7d8f339620a475a0418c0563669b6010bea8acc0e1cb5a6e3d03e5f20cce5d56575a807086eb5e19293c8c730649b9191ed721b2f781ff72e028fda53411f9ebba7c0f196554d9a3486dec56d1b09255084611129f541f6d1de1aa6803ec83e38487b0165fc8b21467622d73a2576c5cfb216fa94fb88f50fd51b2a515164812a61e12133621add34c4b3b5510e12ca1da2ed013df80a857537bc926590436fa3012317ae578b62ac5b49c5029cfa1f8d88ab032d46d500970bb27b293bb7cdfa03ad4fe0699689725ad81f0fee73ae3ac6964655fff1e11b1757eade76de3a7d05ab5e3ba0186a0bff04f0d2f3738c3b4f62bb6b773b9f37c3a7959a3dfe26d624d2c2dbe9e26b97ff7f065cf49c0fc77c0f000f11b9c2a560ee552eb67dab255b6297c32bb90fda12436673a3b8e9a0ee2ee9301475331c0217c5c39173fa9920e049833713bcc5421889a0d9b6e9f0ff70b7737998302f24fd49cc1849010c41474e8109f8949ff8207cd15706418a5c08cf1907ee0a8dcca851372c17428c73aa3e869d19179c0b32fa3de591a3a15209a131c866d965c179785139237c85292fe8736f736b025931647672023777b4400401bd91131a5e9370bbd3008dec328684dc7d84c12187d1b3eb1b07b2fde0ada2f973269fbcf63fb8e914d21d84ebd7b83ade7217edec719b6a81931f8d0c23fb9b12276098899b1ab790155d462a286759a1b700de3ae77ca25bd760bc52c424faa5bda2ef5413fc1c2791561cd9b9751471742df4261ec94ae60d1abf02c371e29f8a8610c918fb7a1c5d8acaf8a19bb2210f30dc000e399ad1d39291c91b6aecadd8a4b3511d06c84142a70463bcaff73a4dcedeb4faeec07af80a19df947221e23d53d4ffd2043d3d17399f709e1adb084ac5b58444f5243db223faa1cabdc591e050cfc78324d4a9393a6d9df6e65833c9e3708b9c2dbf756a04375421edde6cd740c5723ba6fe8a0522459595ac6ce13d432470d1d3da2dd95c627e54327c86f94240064bf71e6c530b2f6d0ae3a238a77646256b79600814b461080badedd5df4f82dca672b099a55fb7646307de7a4cf2535120bab4b3de8ed3b71f8a747cd04512dd2e7ca291817cca8cb213cd6b0ff1643b7b8c9b2060a1057354ffdd9dca22b068ff517f39d87d41bc5b919301773a8437ee7b365691c2db7eb4545ce87f"),
            // nBits
            0x1f07ffff, 
            // Version
            4, 
            // Reward
            0); 

        consensus.hashGenesisBlock = genesis.GetHash();
        consensus.timeGenesisBlock = genesis.nTime;

        assert(consensus.hashGenesisBlock == uint256S("00015cb28cab26f2d4385a4bc261d3c88d6cafbc489dc26e6e752456f90dd26b"));
        assert(genesis.hashMerkleRoot == uint256S("0x75e9e549a9938a815b0a7b85f698fea072d5f57a8015f0f1c25c5e7abe02aacf"));

        // Note that of those which support the service bits prefix, most only support a subset of
        // possible options.
        // This is fine at runtime as we'll fall back to using them as a oneshot if they dont support the
        // service bits we want, but we should get them updated to support all service bits wanted by any
        // release ASAP to avoid it where possible.

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 28);// 
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 63);// 
        base58Prefixes[SECRET_KEY] = std::vector<unsigned char>(1, 48);// 
        base58Prefixes[EXT_PUBLIC_KEY] = { 0x53, 0x41, 0x46, 0x45 };// 
        base58Prefixes[EXT_SECRET_KEY] = { 0x53, 0x61, 0x66, 0x65 };// 

        bech32_hrp = "genx";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));
        vSeeds.emplace_back("mainnet1.genesisnetwork.io", true);
        vSeeds.emplace_back("mainnet2.genesisnetwork.io", true);
        vSeeds.emplace_back("mainnet3.genesisnetwork.io", true);
        vSeeds.emplace_back("mainnet4.genesisnetwork.io", true);

        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;

        checkpointData = {
            {
                {
                    0, consensus.hashGenesisBlock
                },
                {
                    10000, uint256S("0x000002a7e0ce0fec9117d68137819a4cfb7fa4f46408384340c9f652e7029b49")
                },
                {
                    20000, uint256S("0x00000d375549a032c60f9a857da1cbe260dcb53c1d718216f06e897fb2fe3501")
                }
            }
        };

        chainTxData = ChainTxData{
            // Data from rpc: getchaintxstats 4096 00000d375549a032c60f9a857da1cbe260dcb53c1d718216f06e897fb2fe3501
            /* nTime    */ 1532884444,
            /* nTxCount */ 43002,
            /* dTxRate  */ 0.05389735186421477
        };

        // Switch at block
        fGenX_SwitchAtBlock = 30000;
        fGenX_EnforceAtBlock = 35000;

        // Founders Addresses: A vector of addresses
        vFounderAddress = 
        {
            "SPfqCriDDxsaH854z3YHigCNUPfSdN3sr1", // Chris 
            "SaSmUn7LkjmV2WUH1dKFK1xZR1FMRT4qrn", // Jimmy 
            "SbfnZN1rPdFq4WsfUUjxphGFcfEits7JXH", // Scott 
            "SSW62dCjdCxNbKiZdmJh5GLepauY1J1rXU", // Shelby 
            "SW9GN4tZVfPftAQvGmZQLbK6NqePSs8fX1", // Loki 
        };

        // Infrastructure Addresses: A vector of addresses
        vInfrastructureAddress = 
        {
            "SYSaqv2yChvf462gqmVX8VLrh3m6mXiPLd", // Infrastructure
        };
        
        // Giveaway Addresses: A vector of addresses
        vGiveawayAddress = 
        {
            "SQnWFjgxMJyyMQK97gjdF8gYBUUH3kSWEA", // Giveaways
        };

        // Masternodes
        consensus.nMasternodeCollateral = 750000 * COIN;
        consensus.nMasternodePaymentsStartBlock = 300000;
		consensus.nGovernanceBlockOffset = 1; // One block after the bonus block
        consensus.nGovernanceMinQuorum = 10;
        consensus.nGovernanceFilterElements = 20000;
        consensus.nMasternodeMinimumConfirmations = 15;
        consensus.nFulfilledRequestExpireTime = 60*60; // fulfilled requests expire in 1 hour
        consensus.nMasternodeCheckSeconds = 5;                    
        consensus.nMasternodeMinMnbSeconds = 5 * 60;                      
        consensus.nMasternodeMinMnpSeconds = 10 * 60;                    
        consensus.nMasternodeSentinelPingMaxSeconds = 60 * 60;              
        consensus.nMasternodeExpirationSeconds = 120 * 60;                   
        consensus.nMasternodeNewStartRequiredSeconds = 180 * 60;             
        consensus.nMasternodePoseBanMaxScore = 5;                    
        consensus.nMasternodeSignHashThreshold = 600000;                  
        // Masternode maturity configuration
        consensus.nMasternodeMaturityBlockMultiplier = 1440;             
        consensus.nMasternodeMaturityThreshold = 336;                   
        consensus.nMasternodeMaturitySecondariesMaxCount = 20; 
        consensus.aMasternodeMaturiySecondariesMinAmount = 1;       
        // Block subsidy definition(s)
        consensus.nBlockRewardFinder = 350;     // miner / minter
        consensus.nBlockRewardMasternode = 200;                         
        consensus.nBlockRewardFounders = 60;                           
        consensus.nBlockRewardGiveaways = 0;                          
        consensus.nBlockRewardInfrastructure = 0;                    
        consensus.nBlockRewardTotal = consensus.nBlockRewardFinder + consensus.nBlockRewardMasternode + consensus.nBlockRewardFounders + consensus.nBlockRewardGiveaways + consensus.nBlockRewardInfrastructure; // 610 // Normal block                               
        consensus.nBlockRewardGovernance = 90;                   
    }
};

/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        consensus.nSubsidyHalvingInterval = 210000;
        consensus.BIP16Height = 0; 
        consensus.BIP34Height = 0;
        consensus.BIP34Hash = uint256S("022a190e703ddb3223c7c8bdfedec01d64359859cc2584b1386b47b3d5fa725a");
        consensus.BIP65Height = 0; 
        consensus.BIP66Height = 0; 
        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; 
        consensus.nPowTargetSpacing = 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1916; 
        consensus.nMinerConfirmationWindow = 2016; 
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // LWMA
        consensus.nZawyLwmaAveragingWindow = 90;

        // Maturity
        consensus.nCoinbaseMaturity = 5;
        consensus.nTxMinConfirmations = 1;

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x000000000000000000000000000000000000000000000000000000000000001f");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00"); 

        pchMessageStart[0] = 0xc6; // Test 0
        pchMessageStart[1] = 0x54; // Test 1
        pchMessageStart[2] = 0xaa; // Test 2
        pchMessageStart[3] = 0xc3; // Test 3
        nDefaultPort = 17233;
        nPruneAfterHeight = 1000;

	    // Equihash
        const size_t N = 192, K = 7;
        BOOST_STATIC_ASSERT(equihash_parameters_acceptable(N, K));
        nEquihashN = N;
        nEquihashK = K;
        consensus.nPowAveragingWindow = 17;
        //assert(maxUint/UintToArith256(consensus.powLimit) >= consensus.nPowAveragingWindow);
        consensus.nPowMaxAdjustDown = 32; // 32% adjustment down
        consensus.nPowMaxAdjustUp = 16; // 16% adjustment up
        // Genesis PoW
        consensus.nSuperBlockInterval = 10; 

        genesis = CreateGenesisBlock(
            // nTime
            1534467330, 
            // nNonce
            uint256S("000000000000000000000000000000000000000000000000000000000000000d"), 
            // Solution
            ParseHex("0013a4135562228b1afc56c365be5a5204c797f4e4036dddb8bd09ab5b531760b775f5263a472794e78e11a4d4e686e888a55204c3af109ddc64fa3c18472b20d0fcf78e90b34f9755a5897bcf7636dcd2b853ba01fbb5ab7c97e896d519088a3a4718da294031923a04d1abc1a212f8c34d7a71710341e539153b1ffeda098aaafdaf84895b5a93c2504464bdb1077652217d1ae2fa3106eaebefd939e2593df0fcfe26699de1f6017f28a3fcfe28edf49b3230ae246bd9feab5e90311b9dc7d7ed753821b4cb12472e6d445a6b333ef41305fc80c8f28c806947f0f6cc8bbf19daa8a6b865c42f226dbbc8e78bb1d29574cb23d147b1b503baf63805af5f641f2b367d9f775339bccd093921f63a3ccf42eacfee4fa6d28f59a51901634d419f10acda2a381674ae46a50caed1027901a417284f615fff58f56846087cff72682311e8d0d729b0d50852819bf9b85a00cc9f4e2382f82a7ae48012bd2d45bcbee59b988b1c335d358cca82db318e4265707d1a7cecd714716f03694d556604333994068119cdbceff49282333599176e78c20ed308d5c41ff26333bb9d057a1dbc9c48035b07f00d09b268f015aac7677fdc7322517f5e1505d66104c70e72db034d33633f3ef7e6763cda7dc90a02ce19dcd41aa4c53fa2b172de74861ea87143e2125d9b5190df6d9bdd06d92914e1088e5ef6d8012e04d9414ed4ce561993ec510e808bd4d8dc31c793bd3f80aafaafe35439b9d0648fe77e2cca36dab1e9db0a42e3a864af8455fab5545bf975930ab1991fee1c0a77f68d67e9a0d17bb615409c5f3beea6b2bd9a6b06abd75c3184d023dc07baf24afa9692f46dff44ac0f92710b020c0c9071976a7e2eeba1f2e92e1bf7ff08c3fe99bcccb8afeec254f3f9686d51b75c10ee520a9c52c5a69243bbd886f1b1efae8f79216754553202108f49c98a381aeec2d948cfd785cf3bc3baf43d3430d3be48111af7f70f04e2133d4117dd20ff37231319a8d8034935757b4492a207cd888209a6b10932628b66cc7725e4fb3ee9c66ef23486b685da1f33eb0cdc9df5a5e9e21bd47116e5d4eeacd287ef1f7e86111263572546c3acf206750f8c7bbbd1702fde4fcd13fa8b07f8d18b70d38611f5d976823966d9d550ad473a268ccb2c8da9f8c714b9edb0f2213f2f19752407a8ca110686066d8742e160e5ebb506c221b7ce5f34065f8f38d029f4f77d77637a7ff711df421a815c0c7d5b6bbe041386bea4a2241921801935cd7d2f26472fd42a74940eef08f4166def55507a286992e7aa096b1d2286164a50f3a3341422b9aea2bc0a1f552311f6e8cb27f22a6b91bf215a04c284e49949d6f3e80ba066c3b0e3a5dda7d8523aadca580784355edcdc1b54bbaf43ada309ca0b54068545539696e29838a702d05101ee18805b31bd707d53738a3242ab9c92981793ba747e6a3be17f79524f15d1a615afb59ff7fd06011ba3ebdc245151ad1367eb5cbdc542995ab0782c23adba5e8e12e0d372146c4ad0dc59d742b95f7502ea5d70da91e1ff172a77631a6e99e7731a7c012a093d2795ed46f3cc9d2f92f3a4286d797f9db7a38f207aec9ea4a3afcd3b631346bfd6b71eb9df9d081a2f703e52f10feb66fbee534699d88e95c8d4ce8e8c032e210ae3a2dd078f31e148ef14db4cb0627c7dbb11ba06dbc785de4badcbf3caf55dafee071a7d2ac31dcd7eeaf6957822aefca35e6c6ff7d5703ddb09591fb0c77446ab63f7feddc301379b293a51075cb3aa05b214fe81aa8d69a0ab4066f30545d8244012f15a13b1efda675c168db37f11e8a4d01cbce7155890e31ca426f0f29c0a6b7485c22f2a51f996b46c58398034d92404d6b3b79dc9f036170b78afb2b6c97ebe0e"),
            // nBits
            0x2007ffff, 
            // Version
            4, 
            // Reward
            0); 

        consensus.hashGenesisBlock = genesis.GetHash();
        consensus.timeGenesisBlock = genesis.nTime;
        assert(consensus.hashGenesisBlock == uint256S("022a190e703ddb3223c7c8bdfedec01d64359859cc2584b1386b47b3d5fa725a"));
        assert(genesis.hashMerkleRoot == uint256S("75e9e549a9938a815b0a7b85f698fea072d5f57a8015f0f1c25c5e7abe02aacf"));

        vFixedSeeds.clear();
        vSeeds.clear();
        // nodes with support for servicebits filtering should be at the top
        //vSeeds.emplace_back("testnet1.genesisnetwork.io", true);
        //vSeeds.emplace_back("testnet2.genesisnetwork.io", true);


        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 125);// 
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 87);// 
        base58Prefixes[SECRET_KEY] = std::vector<unsigned char>(1, 15);// 
        base58Prefixes[EXT_PUBLIC_KEY] = { 0x53, 0x4e, 0x55, 0x4c };// 
        base58Prefixes[EXT_SECRET_KEY] = { 0x53, 0x6f, 0x75, 0x6c };// 

        bech32_hrp = "genxt";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;


        checkpointData = {
            {
                {0, consensus.hashGenesisBlock},
            }
        };

        chainTxData = ChainTxData{
            0,
            0,
            0
        };

        // Switch at block
        fGenX_SwitchAtBlock = 11;
        fGenX_EnforceAtBlock = 12;

        // Founders Addresses: 
        vFounderAddress = 
        {
            "cHTa12xmjeDt4PykhVQLe9F1NGfayGfiC7", // Chris 
            "c43Dy1h4Smp5EKjeF5sZew9SECVVUfkNnV", // Jimmy 
            "c8wETLX6n3xbeNz4SAyf64E9vHPs3gNR2f", // Scott 
            "c4wozCPLGwvuSXngEHaE8P9xMNzoaRU8Ss", // Shelby 
            "cAbEZ8P6b5a1HbC5LDksMifnGvgrgRrND6", // Loki 
        };
        
        // Infrastructure Addresses:
        vInfrastructureAddress = 
        {
            "cFDCRyLcXFWCPMMyxUJajGCPdJLoyAzck6", // Infrastructure
        };
        
        // Giveaway Addresses:
        vGiveawayAddress = 
        {
            "c4NjsSBF4NGXbzxAJUiK1P1KfmxpxXiaaP", // Giveaways
        };

        // Masternodes
        consensus.nMasternodeCollateral = 1 * COIN;
        consensus.nMasternodePaymentsStartBlock = 21;
		consensus.nGovernanceBlockOffset = 1; 
        consensus.nGovernanceMinQuorum = 1;
        consensus.nGovernanceFilterElements = 500;
        consensus.nMasternodeMinimumConfirmations = 1;
        consensus.nFulfilledRequestExpireTime = 5*60; // fulfilled requests expire in 5 minutes
        consensus.nMasternodeCheckSeconds = 5;                    
        consensus.nMasternodeMinMnbSeconds = 5 * 60;                      
        consensus.nMasternodeMinMnpSeconds = 10 * 60;                    
        consensus.nMasternodeSentinelPingMaxSeconds = 60 * 60;              
        consensus.nMasternodeExpirationSeconds = 120 * 60;                   
        consensus.nMasternodeNewStartRequiredSeconds = 180 * 60;             
        consensus.nMasternodePoseBanMaxScore = 5;                    
        consensus.nMasternodeSignHashThreshold = 600000;                  
        // Masternode maturity configuration
        consensus.nMasternodeMaturityBlockMultiplier = 1440;             
        consensus.nMasternodeMaturityThreshold = 336;                   
        consensus.nMasternodeMaturitySecondariesMaxCount = 20; 
        consensus.aMasternodeMaturiySecondariesMinAmount = 1;       
        // Block subsidy definition(s)
        consensus.nBlockRewardFinder = 350;     // miner / minter
        consensus.nBlockRewardMasternode = 200;                         
        consensus.nBlockRewardFounders = 60;                           
        consensus.nBlockRewardGiveaways = 0;                          
        consensus.nBlockRewardInfrastructure = 0;                    
        consensus.nBlockRewardTotal = consensus.nBlockRewardFinder + consensus.nBlockRewardMasternode + consensus.nBlockRewardFounders + consensus.nBlockRewardGiveaways + consensus.nBlockRewardInfrastructure; // 610 // Normal block                               
        consensus.nBlockRewardGovernance = 90;                              
    }
};

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    CRegTestParams() {
        strNetworkID = "regtest";
        consensus.nSubsidyHalvingInterval = 210000;
        consensus.BIP16Height = 0; 
        consensus.BIP34Height = 0;
        consensus.BIP34Hash = uint256S("064306a130ea0bec674ca8a092817c03d1d081bc83d0e437e8fe538dec5b6db2");
        consensus.BIP65Height = 0; 
        consensus.BIP66Height = 0; 
        consensus.powLimit = uint256S("0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f");
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; 
        consensus.nPowTargetSpacing = 60;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1916; 
        consensus.nMinerConfirmationWindow = 2016; 
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // LWMA
        consensus.nZawyLwmaAveragingWindow = 90;

        // Maturity
        consensus.nCoinbaseMaturity = 1;
        consensus.nTxMinConfirmations = 1;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00");

        pchMessageStart[0] = 0xae; // RegTest 0
        pchMessageStart[1] = 0x74; // RegTest 1
        pchMessageStart[2] = 0x8c; // RegTest 2
        pchMessageStart[3] = 0xc3; // Regtest 3
        nDefaultPort = 27233;
        nPruneAfterHeight = 1000;

    	// Equihash
        const size_t N = 48, K = 5;
        BOOST_STATIC_ASSERT(equihash_parameters_acceptable(N, K));
        nEquihashN = N;
        nEquihashK = K;
        consensus.nPowAveragingWindow = 17;
        assert(maxUint/UintToArith256(consensus.powLimit) >= consensus.nPowAveragingWindow);
        consensus.nPowMaxAdjustDown = 0; // Turn off adjustment down
        consensus.nPowMaxAdjustUp = 0; // Turn off adjustment up
        // Genesis PoW
        consensus.nSuperBlockInterval = 10; 

        genesis = CreateGenesisBlock(
            // nTime
            1534467330, 
            // nNonce
            uint256S("000000000000000000000000000000000000000000000000000000000000003a"), 
            // Solution
            ParseHex("15fc8b5287ed1e45911c8fd175f23b7d831022e0122e3684564fea2be86efb63be418504"),
            // nBits
            0x200f0f0f, 
            // Version
            4, 
            // Reward
            0); 
        consensus.hashGenesisBlock = genesis.GetHash();
        consensus.timeGenesisBlock = genesis.nTime;
        assert(consensus.hashGenesisBlock == uint256S("064306a130ea0bec674ca8a092817c03d1d081bc83d0e437e8fe538dec5b6db2"));
        assert(genesis.hashMerkleRoot == uint256S("75e9e549a9938a815b0a7b85f698fea072d5f57a8015f0f1c25c5e7abe02aacf"));

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //!< Regtest mode doesn't have any DNS seeds.

        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;

        checkpointData = {
            {
                {
                    0, consensus.hashGenesisBlock
                },
            }
        };

        chainTxData = ChainTxData{
            0,
            0,
            0
        };

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 125);// 
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 87);// 
        base58Prefixes[SECRET_KEY] = std::vector<unsigned char>(1, 15);// 
        base58Prefixes[EXT_PUBLIC_KEY] = { 0x53, 0x4e, 0x55, 0x4c };// 
        base58Prefixes[EXT_SECRET_KEY] = { 0x53, 0x6f, 0x75, 0x6c };// 
        
        bech32_hrp = "genxrt";

        // Switch at block
        fGenX_SwitchAtBlock = 3;
        fGenX_EnforceAtBlock = 3;

        // Founders Addresses: A vector of 2-of-3 multisig addresses
        vFounderAddress = 
        {
            "c2uRLNyBD5cM56n4WDxHBY3aF88gmF6kJH", // Chris 
            "cF31f7sBiufhX1xQ9Xg6W47jgPy2NqZ2nN", // Jimmy 
            "cLeGwFJuVxs8qSLCEmFVMwCDHYXzNptmG7", // Scott 
            "cMZgmvPhNGYfzJx7mNWsuxd5WrjxRyJh83", // Shelby 
            "cKzFwcsWSKW4KoeiJGTqEv677frELvbacD", // Loki 
        };
        
        // Infrastructure Addresses: A vector of 2-of-3 multisig addresses
        vInfrastructureAddress = 
        {
            "cC9WzRDphttg9nBCXj1wHMP2zSQURwzQ4n", // Infrastructure
        };
        
        // Giveaway Addresses: A vector of 2-of-3 multisig addresses
        vGiveawayAddress = 
        {
            "c5M76MoQpWA5SqqKLiRWy8jpuT4Ubrcuqr", // Giveaways
        };

        // Masternodes
        consensus.nMasternodeCollateral = 1 * COIN;
        consensus.nMasternodePaymentsStartBlock = 21;
		consensus.nGovernanceBlockOffset = 1;
        consensus.nGovernanceMinQuorum = 1;
        consensus.nGovernanceFilterElements = 500;
        consensus.nMasternodeMinimumConfirmations = 1;
        consensus.nFulfilledRequestExpireTime = 5*60; // fulfilled requests expire in 5 minutes
        consensus.nMasternodeCheckSeconds = 5;                    
        consensus.nMasternodeMinMnbSeconds = 5 * 60;                      
        consensus.nMasternodeMinMnpSeconds = 10 * 60;                    
        consensus.nMasternodeSentinelPingMaxSeconds = 60 * 60;              
        consensus.nMasternodeExpirationSeconds = 120 * 60;                   
        consensus.nMasternodeNewStartRequiredSeconds = 180 * 60;             
        consensus.nMasternodePoseBanMaxScore = 5;                    
        consensus.nMasternodeSignHashThreshold = 600000;                  
        // Masternode maturity configuration
        consensus.nMasternodeMaturityBlockMultiplier = 1440;             
        consensus.nMasternodeMaturityThreshold = 336;                   
        consensus.nMasternodeMaturitySecondariesMaxCount = 20; 
        consensus.aMasternodeMaturiySecondariesMinAmount = 1;       
        // Block subsidy definition(s)
        consensus.nBlockRewardFinder = 350;     // miner / minter
        consensus.nBlockRewardMasternode = 200;                         
        consensus.nBlockRewardFounders = 60;                           
        consensus.nBlockRewardGiveaways = 0;                          
        consensus.nBlockRewardInfrastructure = 0;                    
        consensus.nBlockRewardTotal = consensus.nBlockRewardFinder + consensus.nBlockRewardMasternode + consensus.nBlockRewardFounders + consensus.nBlockRewardGiveaways + consensus.nBlockRewardInfrastructure; // 610 // Normal block                               
        consensus.nBlockRewardGovernance = 90;                                      
    }
};

static std::unique_ptr<CChainParams> globalChainParams;

const CChainParams &Params() {
    assert(globalChainParams);
    return *globalChainParams;
}

std::unique_ptr<CChainParams> CreateChainParams(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
        return std::unique_ptr<CChainParams>(new CMainParams());
    else if (chain == CBaseChainParams::TESTNET)
        return std::unique_ptr<CChainParams>(new CTestNetParams());
    else if (chain == CBaseChainParams::REGTEST)
        return std::unique_ptr<CChainParams>(new CRegTestParams());
    throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    globalChainParams = CreateChainParams(network);
}

void UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
{
    globalChainParams->UpdateVersionBitsParameters(d, nStartTime, nTimeout);
}

// Convenience Functions
CScript CChainParams::AddressToScript(std::string inAddress) const
{
    CTxDestination address = DecodeDestination(inAddress.c_str());
    assert(IsValidDestination(address));
    assert(boost::get<CScriptID>(&address) != nullptr);
    CScriptID scriptID = boost::get<CScriptID>(address); // address is a boost variant
    CScript script = CScript() << OP_HASH160 << ToByteVector(scriptID) << OP_EQUAL;
    return script;
}

// Sustainability
// Separated logic, in case individual rules change

// Block height must be >0 and <=last founders reward block height 
// or block time must be within 1 year of the genesis block time
// Index variable i ranges from 0 - (vFounderAddress.size()-1)
std::string CChainParams::GetFounderAddressAtHeight(uint32_t nHeight) const 
{
    uint32_t maxHeight = consensus.GetLastFoundersRewardBlockHeight();
    uint32_t justAZero = 0;
    assert(nHeight > justAZero && nHeight <= maxHeight);

    size_t addressChangeInterval = (maxHeight + vFounderAddress.size()) / vFounderAddress.size();
    size_t i = nHeight / addressChangeInterval;
    return vFounderAddress[i];
}

// Block height must be >0 and <=last founders reward block height
// or block time must be within 1 year of the genesis block time
// The address is expected to be a multisig (P2SH) address
CScript CChainParams::GetFounderScriptAtHeight(uint32_t nHeight) const 
{
    //assert(nHeight > 0 && nHeight <= consensus.GetLastFoundersRewardBlockHeight());
    return AddressToScript(GetFounderAddressAtHeight(nHeight).c_str());
}

std::string CChainParams::GetFounderAddressAtIndex(uint32_t i) const 
{
    uint32_t justAZero = 0;
    assert(i >= justAZero && i < vFounderAddress.size());
    return vFounderAddress[i];
}

std::vector<CScript> CChainParams::GetAllFounderScripts() const
{
    std::vector<CScript> output;
    for (auto &address : vFounderAddress)
    {
        output.push_back(AddressToScript(address));
    }
    return output;
}

// Block height must be >0 and <=last founders reward block height 
// or block time must be within 1 year of the genesis block time
// Index variable i ranges from 0 - (vFoundersRewardAddress.size()-1)
std::string CChainParams::GetInfrastructureAddressAtHeight(uint32_t nHeight) const 
{
    uint32_t maxHeight = consensus.GetLastFoundersRewardBlockHeight();
    uint32_t justAZero = 0;
    assert(nHeight > justAZero && nHeight <= maxHeight);

    size_t addressChangeInterval = (maxHeight + vInfrastructureAddress.size()) / vInfrastructureAddress.size();
    size_t i = nHeight / addressChangeInterval;
    return vInfrastructureAddress[i];
}

// Block height must be >0 and <=last founders reward block height
// or block time must be within 1 year of the genesis block time
// The address is expected to be a multisig (P2SH) address
CScript CChainParams::GetInfrastructureScriptAtHeight(uint32_t nHeight) const 
{
    //assert(nHeight > 0 && nHeight <= consensus.GetLastFoundersRewardBlockHeight());
    return AddressToScript(GetInfrastructureAddressAtHeight(nHeight).c_str());
}

std::string CChainParams::GetInfrastructureAddressAtIndex(uint32_t i) const 
{
    uint32_t justAZero = 0;
    assert(i >= justAZero && i < vInfrastructureAddress.size());
    return vInfrastructureAddress[i];
}

// Block height must be >0 and <=last founders reward block height 
// or block time must be within 1 year of the genesis block time
// Index variable i ranges from 0 - (vFoundersRewardAddress.size()-1)
std::string CChainParams::GetGiveawayAddressAtHeight(uint32_t nHeight) const 
{
    uint32_t maxHeight = consensus.GetLastFoundersRewardBlockHeight();
    uint32_t justAZero = 0;
    assert(nHeight > justAZero && nHeight <= maxHeight);

    size_t addressChangeInterval = (maxHeight + vGiveawayAddress.size()) / vGiveawayAddress.size();
    size_t i = nHeight / addressChangeInterval;
    return vGiveawayAddress[i];
}

// Block height must be >0 and <=last founders reward block height
// or block time must be within 1 year of the genesis block time
// The address is expected to be a multisig (P2SH) address
CScript CChainParams::GetGiveawayScriptAtHeight(uint32_t nHeight) const 
{
    //assert(nHeight > 0 && nHeight <= consensus.GetLastFoundersRewardBlockHeight());
    return AddressToScript(GetGiveawayAddressAtHeight(nHeight).c_str());
}

std::string CChainParams::GetGiveawayAddressAtIndex(uint32_t i) const 
{
    uint32_t justAZero = 0;
    assert(i >= justAZero && i < vGiveawayAddress.size());
    return vGiveawayAddress[i];
}
