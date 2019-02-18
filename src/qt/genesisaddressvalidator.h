// Copyright (c) 2011-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef GENESIS_QT_GENESISADDRESSVALIDATOR_H
#define GENESIS_QT_GENESISADDRESSVALIDATOR_H

#include <QValidator>

/** Base58 entry widget validator, checks for valid characters and
 * removes some whitespace.
 */
class GenesisAddressEntryValidator : public QValidator
{
    Q_OBJECT

public:
    explicit GenesisAddressEntryValidator(QObject *parent);

    State validate(QString &input, int &pos) const;
};

/** Genesis address widget validator, checks for a valid Genesis address.
 */
class GenesisAddressCheckValidator : public QValidator
{
    Q_OBJECT

public:
    explicit GenesisAddressCheckValidator(QObject *parent);

    State validate(QString &input, int &pos) const;
};

#endif // GENESIS_QT_GENESISADDRESSVALIDATOR_H
