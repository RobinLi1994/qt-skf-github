/**
 * @file EncDecTestDialog.h
 * @brief 容器加解密测试对话框
 */

#pragma once

#include <QDialog>

#include "plugin/interface/PluginTypes.h"

class ElaComboBox;
class ElaPlainTextEdit;
class ElaPushButton;
class QLabel;
class QWidget;

namespace wekey {

class EncDecTestDialog : public QDialog {
    Q_OBJECT

public:
    explicit EncDecTestDialog(const QString& devName, const QString& appName,
                              const QString& containerName, ContainerInfo::KeyType keyType,
                              QWidget* parent = nullptr);
    explicit EncDecTestDialog(const QString& devName, const QString& appName,
                              const QString& containerName, const ContainerInfo& containerInfo,
                              QWidget* parent = nullptr);

private slots:
    void onEncrypt();
    void onDecrypt();
    void updateButtonState();

private:
    void setupUi();
    bool useSignKey() const;

    QString devName_;
    QString appName_;
    QString containerName_;
    ContainerInfo containerInfo_;
    ContainerInfo::KeyType keyType_ = ContainerInfo::KeyType::Unknown;

    ElaComboBox* rsaKeyCombo_ = nullptr;
    ElaPlainTextEdit* plainTextEdit_ = nullptr;
    ElaPushButton* encryptButton_ = nullptr;
    ElaPushButton* decryptButton_ = nullptr;
    QLabel* statusLabel_ = nullptr;
    ElaPlainTextEdit* encryptedEdit_ = nullptr;
    ElaPlainTextEdit* decryptedEdit_ = nullptr;
};

}  // namespace wekey
