/**
 * @file SignDialog.h
 * @brief 签名与验签对话框
 *
 * 允许用户输入原始数据，调用 CertService::sign() 完成签名，
 * 展示 Base64 签名结果，并可进一步调用 CertService::verify() 完成验签。
 */

#pragma once

#include <QDialog>

class ElaPushButton;
class ElaPlainTextEdit;
class QLabel;

namespace wekey {

class SignDialog : public QDialog {
    Q_OBJECT

public:
    /**
     * @brief 构造函数
     * @param devName 设备名称
     * @param appName 应用名称
     * @param containerName 容器名称
     * @param parent 父窗口
     */
    explicit SignDialog(const QString& devName, const QString& appName,
                        const QString& containerName, QWidget* parent = nullptr);

private slots:
    void onSign();
    void onCopySignature();
    void onVerify();

private:
    void setupUi();

    QString devName_;
    QString appName_;
    QString containerName_;

    // 签名输入区
    ElaPlainTextEdit* dataEdit_ = nullptr;
    ElaPushButton* signBtn_ = nullptr;

    // 签名结果区（初始隐藏）
    QWidget* resultWidget_ = nullptr;
    ElaPlainTextEdit* resultEdit_ = nullptr;
    ElaPushButton* copyBtn_ = nullptr;

    // 验签区（初始隐藏）
    QWidget* verifyWidget_ = nullptr;
    ElaPlainTextEdit* verifyEdit_ = nullptr;
    ElaPushButton* verifyBtn_ = nullptr;
    QLabel* verifyResultLabel_ = nullptr;
};

}  // namespace wekey