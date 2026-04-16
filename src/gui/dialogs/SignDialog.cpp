/**
 * @file SignDialog.cpp
 * @brief 签名与验签对话框实现
 */

#include "SignDialog.h"

#include <QApplication>
#include <QClipboard>
#include <QHBoxLayout>
#include <QLabel>
#include <QTimer>
#include <QVBoxLayout>

#include <ElaMessageBar.h>
#include <ElaPlainTextEdit.h>
#include <ElaPushButton.h>

#include "core/crypto/CertService.h"
#include "gui/UiHelper.h"

namespace wekey {

SignDialog::SignDialog(const QString& devName, const QString& appName,
                       const QString& containerName, QWidget* parent)
    : QDialog(parent)
    , devName_(devName)
    , appName_(appName)
    , containerName_(containerName) {
    setupUi();
}

void SignDialog::onSign() {
    QString text = dataEdit_->toPlainText().trimmed();
    if (text.isEmpty()) {
        return;
    }

    signBtn_->setEnabled(false);
    signBtn_->setText("签名中...");

    auto result = CertService::instance().sign(devName_, appName_, containerName_, text.toUtf8());

    signBtn_->setText("签名");
    signBtn_->setEnabled(true);

    if (result.isErr()) {
        resultWidget_->setVisible(true);
        verifyWidget_->setVisible(false);
        resultEdit_->setPlainText(QString("签名失败: %1").arg(result.error().friendlyMessage()));
        resultEdit_->setReadOnly(true);
        copyBtn_->setVisible(false);
        return;
    }

    QString base64Sig = QString::fromLatin1(result.value().toBase64());

    // 显示签名结果
    resultWidget_->setVisible(true);
    resultEdit_->setPlainText(base64Sig);
    resultEdit_->setReadOnly(true);
    copyBtn_->setVisible(true);

    // 显示验签区，预填签名值
    verifyWidget_->setVisible(true);
    verifyEdit_->setPlainText(base64Sig);
    verifyResultLabel_->setText("");
}

void SignDialog::onCopySignature() {
    QApplication::clipboard()->setText(resultEdit_->toPlainText());
    copyBtn_->setText("已复制 ✓");
    copyBtn_->setEnabled(false);
    QTimer::singleShot(1500, this, [this]() {
        copyBtn_->setText("复制");
        copyBtn_->setEnabled(true);
    });
}

void SignDialog::onVerify() {
    QString rawText = dataEdit_->toPlainText().trimmed();
    QString sigText = verifyEdit_->toPlainText().trimmed();

    if (rawText.isEmpty() || sigText.isEmpty()) {
        verifyResultLabel_->setText("<span style='color:#faad14;'>请填写待签名数据和签名值</span>");
        return;
    }

    QByteArray sigBytes = QByteArray::fromBase64(sigText.toLatin1());
    auto result = CertService::instance().verify(
        devName_, appName_, containerName_, rawText.toUtf8(), sigBytes);

    if (result.isErr()) {
        verifyResultLabel_->setText(
            QString("<span style='color:#ff4d4f;'>✗ 验签失败: %1</span>")
                .arg(result.error().friendlyMessage()));
        return;
    }

    if (result.value()) {
        verifyResultLabel_->setText("<span style='color:#52c41a;'>✓ 验签成功</span>");
    } else {
        verifyResultLabel_->setText("<span style='color:#ff4d4f;'>✗ 签名无效</span>");
    }
}

void SignDialog::setupUi() {
    setWindowTitle(QString("签名与验签 - %1").arg(containerName_));
    resize(520, 0);
    UiHelper::styleDialog(this);

    auto* mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(24, 24, 24, 24);
    mainLayout->setSpacing(8);

    // ---- 待签名数据 ----
    auto* dataLabel = new QLabel(this);
    dataLabel->setTextFormat(Qt::RichText);
    dataLabel->setText(
        "<span style='color:#ff4d4f; font-size:14px;'>* </span>"
        "<span style='color:#000000; font-size:14px;'>待签名数据</span>");
    mainLayout->addWidget(dataLabel);

    dataEdit_ = new ElaPlainTextEdit(this);
    dataEdit_->setPlaceholderText("请输入待签名的原始数据");
    dataEdit_->setMinimumHeight(80);
    dataEdit_->setMaximumHeight(120);
    mainLayout->addWidget(dataEdit_);
    mainLayout->addSpacing(8);

    // 签名按钮
    auto* signBtnLayout = new QHBoxLayout;
    signBtnLayout->addStretch();
    signBtn_ = new ElaPushButton("签名", this);
    UiHelper::stylePrimaryButton(signBtn_);
    connect(signBtn_, &ElaPushButton::clicked, this, &SignDialog::onSign);
    signBtnLayout->addWidget(signBtn_);
    mainLayout->addLayout(signBtnLayout);

    // ---- 签名结果区（初始隐藏）----
    resultWidget_ = new QWidget(this);
    auto* resultLayout = new QVBoxLayout(resultWidget_);
    resultLayout->setContentsMargins(0, 8, 0, 0);
    resultLayout->setSpacing(8);

    mainLayout->addWidget(UiHelper::createDivider(this));

    auto* resultLabel = new QLabel(this);
    resultLabel->setText("<span style='color:#000000; font-size:14px;'>签名结果（Base64）</span>");
    resultLabel->setTextFormat(Qt::RichText);
    resultLayout->addWidget(resultLabel);

    resultEdit_ = new ElaPlainTextEdit(this);
    resultEdit_->setReadOnly(true);
    resultEdit_->setMinimumHeight(80);
    resultEdit_->setMaximumHeight(120);
    resultLayout->addWidget(resultEdit_);

    auto* copyLayout = new QHBoxLayout;
    copyLayout->addStretch();
    copyBtn_ = new ElaPushButton("复制", this);
    UiHelper::styleDefaultButton(copyBtn_);
    copyBtn_->setFixedWidth(80);
    connect(copyBtn_, &ElaPushButton::clicked, this, &SignDialog::onCopySignature);
    copyLayout->addWidget(copyBtn_);
    resultLayout->addLayout(copyLayout);

    resultWidget_->setVisible(false);
    mainLayout->addWidget(resultWidget_);

    // ---- 验签区（初始隐藏）----
    verifyWidget_ = new QWidget(this);
    auto* verifyLayout = new QVBoxLayout(verifyWidget_);
    verifyLayout->setContentsMargins(0, 0, 0, 0);
    verifyLayout->setSpacing(8);

    mainLayout->addWidget(UiHelper::createDivider(this));

    auto* verifyInputLabel = new QLabel(this);
    verifyInputLabel->setText("<span style='color:#000000; font-size:14px;'>验签签名值（Base64，可修改后验签）</span>");
    verifyInputLabel->setTextFormat(Qt::RichText);
    verifyLayout->addWidget(verifyInputLabel);

    verifyEdit_ = new ElaPlainTextEdit(this);
    verifyEdit_->setMinimumHeight(80);
    verifyEdit_->setMaximumHeight(120);
    verifyLayout->addWidget(verifyEdit_);

    auto* verifyBtnLayout = new QHBoxLayout;
    verifyBtnLayout->addStretch();
    verifyBtn_ = new ElaPushButton("验签", this);
    UiHelper::stylePrimaryButton(verifyBtn_);
    connect(verifyBtn_, &ElaPushButton::clicked, this, &SignDialog::onVerify);
    verifyBtnLayout->addWidget(verifyBtn_);
    verifyLayout->addLayout(verifyBtnLayout);

    verifyResultLabel_ = new QLabel(this);
    verifyResultLabel_->setTextFormat(Qt::RichText);
    verifyResultLabel_->setAlignment(Qt::AlignRight);
    verifyLayout->addWidget(verifyResultLabel_);

    verifyWidget_->setVisible(false);
    mainLayout->addWidget(verifyWidget_);

    // ---- 分隔线 + 关闭按钮 ----
    mainLayout->addSpacing(8);
    mainLayout->addWidget(UiHelper::createDivider(this));

    auto* closeBtnLayout = new QHBoxLayout;
    closeBtnLayout->addStretch();
    auto* closeBtn = new ElaPushButton("关闭", this);
    UiHelper::styleDefaultButton(closeBtn);
    connect(closeBtn, &ElaPushButton::clicked, this, &QDialog::accept);
    closeBtnLayout->addWidget(closeBtn);
    mainLayout->addLayout(closeBtnLayout);
}

}  // namespace wekey