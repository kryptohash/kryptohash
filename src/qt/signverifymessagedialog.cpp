// Copyright (c) 2011-2013 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "signverifymessagedialog.h"
#include "ui_signverifymessagedialog.h"

#include "addressbookpage.h"
#include "guiutil.h"
#include "walletmodel.h"

#include "base58.h"
#include "init.h"
#include "wallet.h"

#include <string>
#include <vector>

#include <QClipboard>

SignVerifyMessageDialog::SignVerifyMessageDialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::SignVerifyMessageDialog),
    model(0)
{
    ui->setupUi(this);

#if QT_VERSION >= 0x040700
    ui->signatureOut_SM->setPlaceholderText(tr("Click \"Sign Message\" to generate signature"));
    ui->addressIn_VM->setPlaceholderText(tr("Enter a Kryptohash address (e.g. kDgzWy3rwYgFTCxLfPxKFg1KinXM57y1GD)"));
#endif

    GUIUtil::setupAddressWidget(ui->addressIn_SM, this);
    GUIUtil::setupAddressWidget(ui->addressIn_VM, this);

    ui->addressIn_SM->installEventFilter(this);
    ui->messageIn_SM->installEventFilter(this);
    ui->signatureOut_SM->installEventFilter(this);
    ui->addressIn_VM->installEventFilter(this);
    ui->messageIn_VM->installEventFilter(this);
    ui->signatureIn_VM->installEventFilter(this);

    ui->signatureOut_SM->setFont(GUIUtil::bitcoinAddressFont());
    ui->signatureIn_VM->setFont(GUIUtil::bitcoinAddressFont());
}

SignVerifyMessageDialog::~SignVerifyMessageDialog()
{
    delete ui;
}

void SignVerifyMessageDialog::setModel(WalletModel *model)
{
    this->model = model;
}

void SignVerifyMessageDialog::setAddress_SM(const QString &address)
{
    ui->addressIn_SM->setText(address);
    ui->messageIn_SM->setFocus();
}

void SignVerifyMessageDialog::setAddress_VM(const QString &address)
{
    ui->addressIn_VM->setText(address);
    ui->messageIn_VM->setFocus();
}

void SignVerifyMessageDialog::showTab_SM(bool fShow)
{
    ui->tabWidget->setCurrentIndex(0);
    if (fShow)
        this->show();
}

void SignVerifyMessageDialog::showTab_VM(bool fShow)
{
    ui->tabWidget->setCurrentIndex(1);
    if (fShow)
        this->show();
}

void SignVerifyMessageDialog::on_addressBookButton_SM_clicked()
{
    if (model && model->getAddressTableModel())
    {
        AddressBookPage dlg(AddressBookPage::ForSelection, AddressBookPage::ReceivingTab, this);
        dlg.setModel(model->getAddressTableModel());
        if (dlg.exec())
        {
            setAddress_SM(dlg.getReturnValue());
        }
    }
}

void SignVerifyMessageDialog::on_pasteButton_SM_clicked()
{
    setAddress_SM(QApplication::clipboard()->text());
}

void SignVerifyMessageDialog::on_signMessageButton_SM_clicked()
{
    if (!model)
        return;

    /* Clear old signature to ensure users don't get confused on error with an old signature displayed */
    ui->signatureOut_SM->clear();

    CBitcoinAddress addr(ui->addressIn_SM->text().toStdString());
    if (!addr.IsValid())
    {
        ui->statusLabel_SM->setStyleSheet("QLabel { color: red; }");
        ui->statusLabel_SM->setText(tr("The entered address is invalid.") + QString(" ") + tr("Please check the address and try again."));
        return;
    }
    CKeyID keyID;
    if (!addr.GetKeyID(keyID))
    {
        ui->addressIn_SM->setValid(false);
        ui->statusLabel_SM->setStyleSheet("QLabel { color: red; }");
        ui->statusLabel_SM->setText(tr("The entered address does not refer to a key.") + QString(" ") + tr("Please check the address and try again."));
        return;
    }

    WalletModel::UnlockContext ctx(model->requestUnlock());
    if (!ctx.isValid())
    {
        ui->statusLabel_SM->setStyleSheet("QLabel { color: red; }");
        ui->statusLabel_SM->setText(tr("Wallet unlock was cancelled."));
        return;
    }

    CKey key;
    if (!pwalletMain->GetKey(keyID, key))
    {
        ui->statusLabel_SM->setStyleSheet("QLabel { color: red; }");
        ui->statusLabel_SM->setText(tr("Private key for the entered address is not available."));
        return;
    }

    CDataStream ss(SER_GETHASH, 0);
    ss << strMessageMagic;
    ss << ui->messageIn_SM->document()->toPlainText().toStdString();

    std::vector<unsigned char> vchSig;
    unsigned int nSigningDiff = GetArg("-messagesigningdiff", 0);
    if (nSigningDiff > 128) {
        ui->statusLabel_SM->setStyleSheet("QLabel { color: red; }");
        ui->statusLabel_SM->setText(QString("<nobr>") + tr("Message signing failed.") + QString(" ") + tr("messagesigningdiff value too high.") + QString("</nobr>"));
        return;
    }
    if (nSigningDiff == 0) {
        if (!key.Sign(Hash256(ss.begin(), ss.end()), vchSig))
        {
            ui->statusLabel_SM->setStyleSheet("QLabel { color: red; }");
            ui->statusLabel_SM->setText(QString("<nobr>") + tr("Message signing failed.") + QString("</nobr>"));
            return;
        }
    }
    else {
        if (!key.Sign(Hash256(ss.begin(), ss.end()), vchSig, nSigningDiff))
        {
            ui->statusLabel_SM->setStyleSheet("QLabel { color: red; }");
            ui->statusLabel_SM->setText(QString("<nobr>") + tr("Message signing failed.") + QString(" ") + tr("incorrect messagesigningdiff value or diff is too high.") + QString("</nobr>"));
            return;
        }
    }

    ui->statusLabel_SM->setStyleSheet("QLabel { color: green; }");
    ui->statusLabel_SM->setText(QString("<nobr>") + tr("Message signed.") + QString("</nobr>"));

    ui->signatureOut_SM->setText(QString::fromStdString(EncodeBase64(&vchSig[0], vchSig.size())));
}

void SignVerifyMessageDialog::on_copySignatureButton_SM_clicked()
{
    GUIUtil::setClipboard(ui->signatureOut_SM->text());
}

void SignVerifyMessageDialog::on_clearButton_SM_clicked()
{
    ui->addressIn_SM->clear();
    ui->messageIn_SM->clear();
    ui->signatureOut_SM->clear();
    ui->statusLabel_SM->clear();

    ui->addressIn_SM->setFocus();
}

void SignVerifyMessageDialog::on_addressBookButton_VM_clicked()
{
    if (model && model->getAddressTableModel())
    {
        AddressBookPage dlg(AddressBookPage::ForSelection, AddressBookPage::SendingTab, this);
        dlg.setModel(model->getAddressTableModel());
        if (dlg.exec())
        {
            setAddress_VM(dlg.getReturnValue());
        }
    }
}

void SignVerifyMessageDialog::on_verifyMessageButton_VM_clicked()
{
    CBitcoinAddress addr(ui->addressIn_VM->text().toStdString());
    if (!addr.IsValid())
    {
        ui->statusLabel_VM->setStyleSheet("QLabel { color: red; }");
        ui->statusLabel_VM->setText(tr("The entered address is invalid.") + QString(" ") + tr("Please check the address and try again."));
        return;
    }
    CKeyID keyID;
    if (!addr.GetKeyID(keyID))
    {
        ui->addressIn_VM->setValid(false);
        ui->statusLabel_VM->setStyleSheet("QLabel { color: red; }");
        ui->statusLabel_VM->setText(tr("The entered address does not refer to a key.") + QString(" ") + tr("Please check the address and try again."));
        return;
    }

    bool fInvalid = false;
    std::vector<unsigned char> vchPayload = DecodeBase64(ui->signatureIn_VM->text().toStdString().c_str(), &fInvalid);

    if (fInvalid)
    {
        ui->signatureIn_VM->setValid(false);
        ui->statusLabel_VM->setStyleSheet("QLabel { color: red; }");
        ui->statusLabel_VM->setText(tr("The signature could not be decoded.") + QString(" ") + tr("Please check the signature and try again."));
        return;
    }

#ifdef USE_ED25519
    unsigned int nMinVerifyDiff = GetArg("-minmessageverifydiff", 0);

    /* Check if the payload header (or prefix) is valid */
    if ((vchPayload[0] & 0xF8) == 0xA0) {
        /* Payload is always 104 bytes long for this ed25519 first serial structure */
        if (vchPayload.size() != 104)
        {
            ui->signatureIn_VM->setValid(false);
            ui->statusLabel_VM->setStyleSheet("QLabel { color: red; }");
            ui->statusLabel_VM->setText(tr("The signature length is incorrect.") + QString(" ") + tr("Please check the signature and try again."));
            return;
        }

        /* Right now, this structure is hardcoded to 64 bytes for ed25519 signature, 32 bytes for public key
        * and 4 bytes for checksum/nonce
        */
        if (vchPayload[1] != 0x40 || vchPayload[2] != 0x20 || vchPayload[3] != 0x04)
        {
            ui->signatureIn_VM->setValid(false);
            ui->statusLabel_VM->setStyleSheet("QLabel { color: red; }");
            ui->statusLabel_VM->setText(tr("Malformed header or unsupported signature size.") + QString(" ") + tr("Please check the signature and try again."));
            return;
        }

        unsigned int nZeroBytes = (unsigned int)(vchPayload[0] & 0x07);
        if (nZeroBytes) {
            /* Suffix is a Nonce */

            /* Check minimum verify difficulty parameter */
            if (nMinVerifyDiff > nZeroBytes * 8) {
                ui->signatureIn_VM->setValid(false);
                ui->statusLabel_VM->setStyleSheet("QLabel { color: red; }");
                ui->statusLabel_VM->setText(tr("Proof of work with higher difficulty is needed.") + QString(" ") + tr("Please check the signature and try again."));
                return;
            }

            /* Check if proof of work is met by doing KSHAKE320(payload) then, check if the number
            * of leading zero bytes in the hash meets the minimum required by nZeroBytes.
            */
            uint320 hash  = KryptoHash(vchPayload.begin(), vchPayload.end());
            uint320 proof = (~uint320(0) >> nZeroBytes * 8);
            if (hash > proof)
            {
                ui->signatureIn_VM->setValid(false);
                ui->statusLabel_VM->setStyleSheet("QLabel { color: red; }");
                ui->statusLabel_VM->setText(tr("Signature rejected due to insufficient proof of work."));
                return;
            }
        }
        else {
            /* Suffix is a checksum */

            /* Calculate the checksum by doing SHA3-256(SHA3-256(header+signature+pubkey)) */
            uint256 hash = Hash256(vchPayload.begin(), vchPayload.end() - 4);

            /* Ensure the first 4-bytes of the hash matches the last 4-bytes of the payload */
            if (memcmp(&hash, &vchPayload.end()[-4], 4) != 0)
            {
                ui->signatureIn_VM->setValid(false);
                ui->statusLabel_VM->setStyleSheet("QLabel { color: red; }");
                ui->statusLabel_VM->setText(tr("Signature did not pass the checksum check.") + QString(" ") + tr("Please check the signature and try again."));
                return;
            }
        }
    }
    else if (vchPayload[0] == 0xA8) {
        /* Payload is always 108 bytes long for this ed25519 second serial structure */
        if (vchPayload.size() != 108)
        {
            ui->signatureIn_VM->setValid(false);
            ui->statusLabel_VM->setStyleSheet("QLabel { color: red; }");
            ui->statusLabel_VM->setText(tr("The signature length is incorrect.") + QString(" ") + tr("Please check the signature and try again."));
            return;
        }

        /* Right now, this structure is hardcoded to 64 bytes for ed25519 signature, 32 bytes for public key
        * and 8 bytes for both the Difficulty and Nonce
        */
        if (vchPayload[1] != 0x40 || vchPayload[2] != 0x20 || vchPayload[3] != 0x08)
        {
            ui->signatureIn_VM->setValid(false);
            ui->statusLabel_VM->setStyleSheet("QLabel { color: red; }");
            ui->statusLabel_VM->setText(tr("Malformed header or unsupported signature size.") + QString(" ") + tr("Please check the signature and try again."));
            return;
        }

        if (nMinVerifyDiff > 128) {
            ui->signatureIn_VM->setValid(false);
            ui->statusLabel_VM->setStyleSheet("QLabel { color: red; }");
            ui->statusLabel_VM->setText(tr("-minmessageverifydiff value too high.") + QString(" ") + tr("Please reduce the parameter in kryptohash.conf file and try again."));
            return;
        }

        /* Suffix contains the Diff bits and a Nonce */

        /* Check if proof of work is met by doing KSHAKE320(payload) then, check if the number
        * of leading zero bits in the hash meets the minimum required by the Diff bits.
        */
        uint320 hash = KryptoHash(vchPayload.begin(), vchPayload.end());
        uint32_t& nBits = *(uint32_t*)(&vchPayload.end()[-8]);

        CBigNum bnTarget;
        bnTarget.SetCompact(nBits);
        uint320 proof  = bnTarget.getuint320();
        uint320 target = (~uint320(0) >> nMinVerifyDiff);

        /* Check minimum verify difficulty parameter */
        if (proof > target) {
            ui->signatureIn_VM->setValid(false);
            ui->statusLabel_VM->setStyleSheet("QLabel { color: red; }");
            ui->statusLabel_VM->setText(tr("Proof of work with higher difficulty is needed.") + QString(" ") + tr("Please request a signature with higher proof of work."));
            return;
        }

        if (hash > proof)
        {
            ui->signatureIn_VM->setValid(false);
            ui->statusLabel_VM->setStyleSheet("QLabel { color: red; }");
            ui->statusLabel_VM->setText(tr("Signature rejected due to insufficient proof of work."));
            return;
        }
    }
    else {
        ui->signatureIn_VM->setValid(false);
        ui->statusLabel_VM->setStyleSheet("QLabel { color: red; }");
        ui->statusLabel_VM->setText(tr("Invalid header - wrong magic.") + QString(" ") + tr("Please check the signature and try again."));
        return;
    }

#endif

    CDataStream ss(SER_GETHASH, 0);
    ss << strMessageMagic;
    ss << ui->messageIn_VM->document()->toPlainText().toStdString();

#ifdef USE_ED25519
    /* Extract the Pubic Key from the payload */
    vector<unsigned char> vchPubKey(vchPayload.begin() + 68, vchPayload.begin() + 100);
    CPubKey pubkey(vchPubKey);
    /* Extract the ed25519 signature from the payload */
    vector<unsigned char> vchSig(vchPayload.begin() + 4, vchPayload.begin() + 68);
    if (!pubkey.Verify(Hash256(ss.begin(), ss.end()), vchSig))
#else
    CPubKey pubkey;
    if (!pubkey.RecoverCompact(Hash256(ss.begin(), ss.end()), vchPayload))
#endif
    {
        ui->signatureIn_VM->setValid(false);
        ui->statusLabel_VM->setStyleSheet("QLabel { color: red; }");
        ui->statusLabel_VM->setText(tr("The signature did not match the message digest.") + QString(" ") + tr("Please check the signature and try again."));
        return;
    }

    if (!(CBitcoinAddress(pubkey.GetID()) == addr))
    {
        ui->statusLabel_VM->setStyleSheet("QLabel { color: red; }");
        ui->statusLabel_VM->setText(QString("<nobr>") + tr("Message verification failed.") + QString("</nobr>"));
        return;
    }

    ui->statusLabel_VM->setStyleSheet("QLabel { color: green; }");
    ui->statusLabel_VM->setText(QString("<nobr>") + tr("Message verified.") + QString("</nobr>"));
}

void SignVerifyMessageDialog::on_clearButton_VM_clicked()
{
    ui->addressIn_VM->clear();
    ui->signatureIn_VM->clear();
    ui->messageIn_VM->clear();
    ui->statusLabel_VM->clear();

    ui->addressIn_VM->setFocus();
}

bool SignVerifyMessageDialog::eventFilter(QObject *object, QEvent *event)
{
    if (event->type() == QEvent::MouseButtonPress || event->type() == QEvent::FocusIn)
    {
        if (ui->tabWidget->currentIndex() == 0)
        {
            /* Clear status message on focus change */
            ui->statusLabel_SM->clear();

            /* Select generated signature */
            if (object == ui->signatureOut_SM)
            {
                ui->signatureOut_SM->selectAll();
                return true;
            }
        }
        else if (ui->tabWidget->currentIndex() == 1)
        {
            /* Clear status message on focus change */
            ui->statusLabel_VM->clear();
        }
    }
    return QDialog::eventFilter(object, event);
}
