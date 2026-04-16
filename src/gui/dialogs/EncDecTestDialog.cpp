/**
 * @file EncDecTestDialog.cpp
 * @brief 容器加解密测试对话框实现
 */

#include "EncDecTestDialog.h"

#include <QDebug>
#include <QHBoxLayout>
#include <QLabel>
#include <QVBoxLayout>

#include <ElaComboBox.h>
#include <ElaPlainTextEdit.h>
#include <ElaPushButton.h>

#include "core/crypto/CertService.h"
#include "gui/UiHelper.h"

namespace wekey {

EncDecTestDialog::EncDecTestDialog(const QString& devName, const QString& appName,
                                   const QString& containerName, ContainerInfo::KeyType keyType,
                                   QWidget* parent)
    : QDialog(parent)
    , devName_(devName)
    , appName_(appName)
    , containerName_(containerName)
    , containerInfo_({containerName, false, keyType, true, true, false})
    , keyType_(keyType) {
    setupUi();
    updateButtonState();
}

EncDecTestDialog::EncDecTestDialog(const QString& devName, const QString& appName,
                                   const QString& containerName, const ContainerInfo& containerInfo,
                                   QWidget* parent)
    : QDialog(parent)
    , devName_(devName)
    , appName_(appName)
    , containerName_(containerName)
    , containerInfo_(containerInfo)
    , keyType_(containerInfo.keyType) {
    setupUi();
    updateButtonState();
}

void EncDecTestDialog::setupUi() {
    setWindowTitle(QString("加密测试 - %1").arg(containerName_));
    resize(560, 0);
    UiHelper::styleDialog(this);

    auto* mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(24, 24, 24, 24);
    mainLayout->setSpacing(8);

    auto* algorithmLabel = new QLabel(this);
    algorithmLabel->setTextFormat(Qt::RichText);
    if (keyType_ == ContainerInfo::KeyType::RSA) {
        // Java 端 RSA 逻辑允许分别验证“签名私钥”和“加密私钥”的解密能力。
        // 因此这里显式让用户选择，避免把两条语义不同的测试混在一起。
        algorithmLabel->setText(
            "<span style='color:#000000; font-size:14px;'>算法：RSA</span>");
        mainLayout->addWidget(algorithmLabel);

        auto* keyLabel = new QLabel(this);
        keyLabel->setTextFormat(Qt::RichText);
        keyLabel->setText(
            "<span style='color:#000000; font-size:14px;'>密钥类型</span>");
        mainLayout->addWidget(keyLabel);

        rsaKeyCombo_ = new ElaComboBox(this);
        UiHelper::styleComboBox(rsaKeyCombo_);
        const bool hasExplicitCapabilities = containerInfo_.signKeyAvailable || containerInfo_.encKeyAvailable;
        if (containerInfo_.signKeyAvailable || !hasExplicitCapabilities) {
            rsaKeyCombo_->addItem("签名密钥", true);
        }
        if (containerInfo_.encKeyAvailable || !hasExplicitCapabilities) {
            rsaKeyCombo_->addItem("加密密钥", false);
        }
        mainLayout->addWidget(rsaKeyCombo_);
        mainLayout->addSpacing(8);
    } else {
        // SM2 路径对齐 Java 端限制：仅允许使用加密私钥解密。
        // SKF_ECCPrvKeyDecrypt 不用于签名私钥，因此这里不提供切换项。
        algorithmLabel->setText(
            "<span style='color:#000000; font-size:14px;'>算法：SM2（仅支持加密密钥）</span>");
        mainLayout->addWidget(algorithmLabel);
        mainLayout->addSpacing(8);
    }

    auto* plainTextLabel = new QLabel(this);
    plainTextLabel->setTextFormat(Qt::RichText);
    plainTextLabel->setText(
        "<span style='color:#ff4d4f; font-size:14px;'>* </span>"
        "<span style='color:#000000; font-size:14px;'>测试明文</span>");
    mainLayout->addWidget(plainTextLabel);

    plainTextEdit_ = new ElaPlainTextEdit(this);
    plainTextEdit_->setObjectName("plainTextEdit");
    plainTextEdit_->setPlaceholderText("请输入要执行加密测试的明文");
    plainTextEdit_->setMinimumHeight(90);
    plainTextEdit_->setMaximumHeight(140);
    mainLayout->addWidget(plainTextEdit_);
    connect(plainTextEdit_, &ElaPlainTextEdit::textChanged, this,
            &EncDecTestDialog::updateButtonState);

    auto* actionLayout = new QHBoxLayout;
    actionLayout->addStretch();
    encryptButton_ = new ElaPushButton("开始加密", this);
    encryptButton_->setObjectName("encryptButton");
    UiHelper::stylePrimaryButton(encryptButton_);
    connect(encryptButton_, &ElaPushButton::clicked, this, &EncDecTestDialog::onEncrypt);
    actionLayout->addWidget(encryptButton_);
    mainLayout->addLayout(actionLayout);

    mainLayout->addWidget(UiHelper::createDivider(this));

    auto* resultLayout = new QVBoxLayout;
    resultLayout->setContentsMargins(0, 8, 0, 0);
    resultLayout->setSpacing(8);

    statusLabel_ = new QLabel(this);
    statusLabel_->setTextFormat(Qt::RichText);
    statusLabel_->setWordWrap(true);
    statusLabel_->setText("<span style='color:#595959;'>请先执行加密，再执行解密。</span>");
    resultLayout->addWidget(statusLabel_);

    auto* encryptedLabel = new QLabel(this);
    encryptedLabel->setTextFormat(Qt::RichText);
    encryptedLabel->setText("<span style='color:#000000; font-size:14px;'>第1步输出 / 第2步输入：密文（Base64）</span>");
    resultLayout->addWidget(encryptedLabel);

    encryptedEdit_ = new ElaPlainTextEdit(this);
    encryptedEdit_->setObjectName("encryptedEdit");
    encryptedEdit_->setReadOnly(false);
    encryptedEdit_->setPlaceholderText("加密后会自动填入，也可以手动粘贴 Base64 密文");
    encryptedEdit_->setMinimumHeight(90);
    encryptedEdit_->setMaximumHeight(130);
    resultLayout->addWidget(encryptedEdit_);
    connect(encryptedEdit_, &ElaPlainTextEdit::textChanged, this,
            &EncDecTestDialog::updateButtonState);

    auto* decryptLayout = new QHBoxLayout;
    decryptLayout->addStretch();
    decryptButton_ = new ElaPushButton("解密", this);
    decryptButton_->setObjectName("decryptButton");
    UiHelper::stylePrimaryButton(decryptButton_);
    connect(decryptButton_, &ElaPushButton::clicked, this, &EncDecTestDialog::onDecrypt);
    decryptLayout->addWidget(decryptButton_);
    resultLayout->addLayout(decryptLayout);

    auto* decryptedLabel = new QLabel(this);
    decryptedLabel->setTextFormat(Qt::RichText);
    decryptedLabel->setText("<span style='color:#000000; font-size:14px;'>解密结果</span>");
    resultLayout->addWidget(decryptedLabel);

    decryptedEdit_ = new ElaPlainTextEdit(this);
    decryptedEdit_->setReadOnly(true);
    decryptedEdit_->setMinimumHeight(90);
    decryptedEdit_->setMaximumHeight(130);
    resultLayout->addWidget(decryptedEdit_);

    mainLayout->addLayout(resultLayout);

    mainLayout->addSpacing(8);
    mainLayout->addWidget(UiHelper::createDivider(this));

    auto* closeLayout = new QHBoxLayout;
    closeLayout->addStretch();
    auto* closeButton = new ElaPushButton("关闭", this);
    UiHelper::styleDefaultButton(closeButton);
    connect(closeButton, &ElaPushButton::clicked, this, &QDialog::accept);
    closeLayout->addWidget(closeButton);
    mainLayout->addLayout(closeLayout);
}

bool EncDecTestDialog::useSignKey() const {
    if (keyType_ != ContainerInfo::KeyType::RSA || !rsaKeyCombo_) {
        return false;
    }
    // ComboBox 的 data 存的是布尔值：
    // true  -> 走 RSA 签名密钥测试
    // false -> 走 RSA 加密密钥测试
    return rsaKeyCombo_->currentData().toBool();
}

void EncDecTestDialog::updateButtonState() {
    if (encryptButton_) {
        encryptButton_->setEnabled(!plainTextEdit_->toPlainText().trimmed().isEmpty());
    }
    if (decryptButton_) {
        decryptButton_->setEnabled(!encryptedEdit_->toPlainText().trimmed().isEmpty());
    }
}

void EncDecTestDialog::onEncrypt() {
    const QString plainText = plainTextEdit_->toPlainText();
    const QByteArray plainBytes = plainText.toUtf8();

    encryptButton_->setEnabled(false);
    encryptButton_->setText("加密中...");

    qInfo() << "[EncDecTestDialog::onEncrypt] start"
            << "devName:" << devName_
            << "appName:" << appName_
            << "containerName:" << containerName_
            << "algorithm:" << (keyType_ == ContainerInfo::KeyType::RSA ? "RSA" : "SM2")
            << "keyType:" << (keyType_ == ContainerInfo::KeyType::RSA
                                 ? (useSignKey() ? "sign" : "enc")
                                 : "enc")
            << "plainBytes:" << plainBytes.size();

    Result<QString> result = (keyType_ == ContainerInfo::KeyType::RSA)
        ? CertService::instance().rsaEncrypt(devName_, appName_, containerName_, useSignKey(), plainText)
        : CertService::instance().sm2Encrypt(devName_, appName_, containerName_, plainText);

    encryptButton_->setText("开始加密");

    if (result.isErr()) {
        qWarning() << "[EncDecTestDialog::onEncrypt] failed"
                   << "devName:" << devName_
                   << "appName:" << appName_
                   << "containerName:" << containerName_
                   << "error:" << result.error().toString(true);
        statusLabel_->setText(
            QString("<span style='color:#ff4d4f;'>加密失败：%1</span>")
                .arg(result.error().friendlyMessage()));
        encryptedEdit_->clear();
        decryptedEdit_->clear();
        updateButtonState();
        return;
    }

    qInfo() << "[EncDecTestDialog::onEncrypt] success"
            << "devName:" << devName_
            << "appName:" << appName_
            << "containerName:" << containerName_
            << "cipherChars:" << result.value().size();
    encryptedEdit_->setPlainText(result.value());
    decryptedEdit_->clear();
    statusLabel_->setText("<span style='color:#52c41a;'>加密成功，请继续执行解密。</span>");
    updateButtonState();
}

void EncDecTestDialog::onDecrypt() {
    const QString encryptedData = encryptedEdit_->toPlainText();

    decryptButton_->setEnabled(false);
    decryptButton_->setText("解密中...");

    qInfo() << "[EncDecTestDialog::onDecrypt] start"
            << "devName:" << devName_
            << "appName:" << appName_
            << "containerName:" << containerName_
            << "algorithm:" << (keyType_ == ContainerInfo::KeyType::RSA ? "RSA" : "SM2")
            << "keyType:" << (keyType_ == ContainerInfo::KeyType::RSA
                                 ? (useSignKey() ? "sign" : "enc")
                                 : "enc")
            << "cipherChars:" << encryptedData.size();

    Result<QString> result = (keyType_ == ContainerInfo::KeyType::RSA)
        ? CertService::instance().rsaDecrypt(devName_, appName_, containerName_, useSignKey(), encryptedData)
        : CertService::instance().sm2Decrypt(devName_, appName_, containerName_, encryptedData);

    decryptButton_->setText("解密");
    updateButtonState();

    if (result.isErr()) {
        qWarning() << "[EncDecTestDialog::onDecrypt] failed"
                   << "devName:" << devName_
                   << "appName:" << appName_
                   << "containerName:" << containerName_
                   << "error:" << result.error().toString(true);
        statusLabel_->setText(
            QString("<span style='color:#ff4d4f;'>解密失败：%1</span>")
                .arg(result.error().friendlyMessage()));
        decryptedEdit_->clear();
        return;
    }

    const QString decryptedText = result.value();
    const bool consistent = (plainTextEdit_->toPlainText() == decryptedText);
    qInfo() << "[EncDecTestDialog::onDecrypt] success"
            << "devName:" << devName_
            << "appName:" << appName_
            << "containerName:" << containerName_
            << "plainChars:" << decryptedText.size()
            << "consistent:" << consistent;
    decryptedEdit_->setPlainText(decryptedText);
    statusLabel_->setText(
        consistent
            ? "<span style='color:#52c41a;'>解密成功：原文与解密结果一致。</span>"
            : "<span style='color:#fa8c16;'>解密成功：但当前明文输入与解密结果不一致。</span>");
}

}  // namespace wekey
