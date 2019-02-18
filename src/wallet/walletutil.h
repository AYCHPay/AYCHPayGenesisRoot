// Copyright (c) 2017-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef GENESIS_WALLET_UTIL_H
#define GENESIS_WALLET_UTIL_H

#include <chainparamsbase.h>
#include <util.h>

//! Get the path of the wallet directory.
fs::path GetWalletDir();

#endif // GENESIS_WALLET_UTIL_H
