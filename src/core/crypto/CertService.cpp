/**
 * @file CertService.cpp
 * @brief 证书与签名服务实现
 */

#include "CertService.h"

#include <QDebug>

#include "plugin/PluginManager.h"

namespace wekey {

namespace {

// 加解密测试入口统一要求非空输入。
// 这里在 Service 层拦住，可以避免 UI、API 或未来脚本调用各自重复校验。
Result<void> validateNonEmpty(const QString& value, const QString& errorMsg,
                              const QString& context) {
    if (value.trimmed().isEmpty()) {
        return Result<void>::err(Error(Error::InvalidParam, errorMsg, context));
    }
    return Result<void>::ok();
}

QString buildPlainTextPreview(const QString& plainText) {
    constexpr int kMaxPreviewLength = 24;
    QString preview = plainText;
    preview.replace('\n', "\\n");
    preview.replace('\r', "\\r");
    if (preview.size() > kMaxPreviewLength) {
        preview = preview.left(kMaxPreviewLength) + "...";
    }
    return preview;
}

}  // namespace

CertService& CertService::instance() {
    static CertService instance;
    return instance;
}

CertService::CertService() : QObject(nullptr) {}

Result<QByteArray> CertService::generateKeyPair(const QString& devName, const QString& appName,
                                                 const QString& containerName, const QString& keyType) {
    auto plugin = PluginManager::instance().activePluginShared();
    if (!plugin) {
        return Result<QByteArray>::err(
            Error(Error::NoActiveModule, "驱动模块未激活", "CertService::generateKeyPair"));
    }
    return plugin->generateKeyPair(devName, appName, containerName, keyType);
}

Result<QByteArray> CertService::generateCsr(const QString& devName, const QString& appName,
                                              const QString& containerName, const QVariantMap& args) {
    auto plugin = PluginManager::instance().activePluginShared();
    if (!plugin) {
        return Result<QByteArray>::err(
            Error(Error::NoActiveModule, "驱动模块未激活", "CertService::generateCsr"));
    }
    return plugin->generateCsr(devName, appName, containerName, args);
}

Result<void> CertService::importCert(const QString& devName, const QString& appName, const QString& containerName,
                                      const QByteArray& certData, bool isSignCert) {
    auto plugin = PluginManager::instance().activePluginShared();
    if (!plugin) {
        return Result<void>::err(
            Error(Error::NoActiveModule, "驱动模块未激活", "CertService::importCert"));
    }
    return plugin->importCert(devName, appName, containerName, certData, isSignCert);
}

Result<void> CertService::importKeyCert(const QString& devName, const QString& appName, const QString& containerName,
                                         const QByteArray& sigCert, const QByteArray& encCert,
                                         const QByteArray& encPrivate, bool nonGM) {
    auto plugin = PluginManager::instance().activePluginShared();
    if (!plugin) {
        return Result<void>::err(
            Error(Error::NoActiveModule, "驱动模块未激活", "CertService::importKeyCert"));
    }
    return plugin->importKeyCert(devName, appName, containerName, sigCert, encCert, encPrivate, nonGM);
}

Result<QByteArray> CertService::exportCert(const QString& devName, const QString& appName,
                                            const QString& containerName, bool isSignCert) {
    auto plugin = PluginManager::instance().activePluginShared();
    if (!plugin) {
        return Result<QByteArray>::err(
            Error(Error::NoActiveModule, "驱动模块未激活", "CertService::exportCert"));
    }
    return plugin->exportCert(devName, appName, containerName, isSignCert);
}

Result<CertInfo> CertService::getCertInfo(const QString& devName, const QString& appName,
                                           const QString& containerName, bool isSignCert) {
    auto plugin = PluginManager::instance().activePluginShared();
    if (!plugin) {
        return Result<CertInfo>::err(
            Error(Error::NoActiveModule, "驱动模块未激活", "CertService::getCertInfo"));
    }
    return plugin->getCertInfo(devName, appName, containerName, isSignCert);
}

Result<QByteArray> CertService::sign(const QString& devName, const QString& appName, const QString& containerName,
                                      const QByteArray& data) {
    auto plugin = PluginManager::instance().activePluginShared();
    if (!plugin) {
        return Result<QByteArray>::err(
            Error(Error::NoActiveModule, "驱动模块未激活", "CertService::sign"));
    }
    return plugin->sign(devName, appName, containerName, data);
}

Result<bool> CertService::verify(const QString& devName, const QString& appName, const QString& containerName,
                                  const QByteArray& data, const QByteArray& signature) {
    auto plugin = PluginManager::instance().activePluginShared();
    if (!plugin) {
        return Result<bool>::err(
            Error(Error::NoActiveModule, "驱动模块未激活", "CertService::verify"));
    }
    return plugin->verify(devName, appName, containerName, data, signature);
}

Result<EncDecTestResult> CertService::rsaEncDecTest(const QString& devName, const QString& appName,
                                                    const QString& containerName, bool useSignKey,
                                                    const QString& plainText) {
    const QByteArray plainBytes = plainText.toUtf8();
    qInfo() << "[CertService::rsaEncDecTest] start"
            << "devName:" << devName
            << "appName:" << appName
            << "containerName:" << containerName
            << "keyType:" << (useSignKey ? "sign" : "enc")
            << "plainBytes:" << plainBytes.size()
            << "plainPreview:" << buildPlainTextPreview(plainText);

    // 先做通用参数校验，确保插件实现只处理“业务有效”的输入。
    auto validation = validateNonEmpty(plainText, "测试明文不能为空", "CertService::rsaEncDecTest");
    if (validation.isErr()) {
        qWarning() << "[CertService::rsaEncDecTest] invalid plainText,"
                   << "devName:" << devName
                   << "appName:" << appName
                   << "containerName:" << containerName
                   << "error:" << validation.error().toString(true);
        return Result<EncDecTestResult>::err(validation.error());
    }

    // CertService 不复制 RSA 加解密细节，只负责把调用路由到当前激活插件。
    // 这样 UI / API 层都能复用同一条本地能力链路。
    auto plugin = PluginManager::instance().activePluginShared();
    if (!plugin) {
        qWarning() << "[CertService::rsaEncDecTest] no active plugin,"
                   << "devName:" << devName
                   << "appName:" << appName
                   << "containerName:" << containerName;
        return Result<EncDecTestResult>::err(
            Error(Error::NoActiveModule, "驱动模块未激活", "CertService::rsaEncDecTest"));
    }

    auto result = plugin->rsaEncDecTest(devName, appName, containerName, useSignKey, plainText);
    if (result.isErr()) {
        qWarning() << "[CertService::rsaEncDecTest] failed"
                   << "devName:" << devName
                   << "appName:" << appName
                   << "containerName:" << containerName
                   << "keyType:" << (useSignKey ? "sign" : "enc")
                   << "error:" << result.error().toString(true);
        return result;
    }

    qInfo() << "[CertService::rsaEncDecTest] success"
            << "devName:" << devName
            << "appName:" << appName
            << "containerName:" << containerName
            << "keyType:" << (useSignKey ? "sign" : "enc")
            << "cipherChars:" << result.value().encryptedData.size()
            << "consistent:" << result.value().consistent;
    return result;
}

Result<EncDecTestResult> CertService::sm2EncDecTest(const QString& devName, const QString& appName,
                                                    const QString& containerName,
                                                    const QString& plainText) {
    const QByteArray plainBytes = plainText.toUtf8();
    qInfo() << "[CertService::sm2EncDecTest] start"
            << "devName:" << devName
            << "appName:" << appName
            << "containerName:" << containerName
            << "keyType: enc"
            << "plainBytes:" << plainBytes.size()
            << "plainPreview:" << buildPlainTextPreview(plainText);

    // SM2 路径与 RSA 共享同一套明文校验规则，保持前置行为一致。
    auto validation = validateNonEmpty(plainText, "测试明文不能为空", "CertService::sm2EncDecTest");
    if (validation.isErr()) {
        qWarning() << "[CertService::sm2EncDecTest] invalid plainText,"
                   << "devName:" << devName
                   << "appName:" << appName
                   << "containerName:" << containerName
                   << "error:" << validation.error().toString(true);
        return Result<EncDecTestResult>::err(validation.error());
    }

    // 具体的公钥导出、SM2 加密、ECC 私钥解密都留在插件层实现，
    // Service 只承担“统一入口 + 当前激活模块分发”的职责。
    auto plugin = PluginManager::instance().activePluginShared();
    if (!plugin) {
        qWarning() << "[CertService::sm2EncDecTest] no active plugin,"
                   << "devName:" << devName
                   << "appName:" << appName
                   << "containerName:" << containerName;
        return Result<EncDecTestResult>::err(
            Error(Error::NoActiveModule, "驱动模块未激活", "CertService::sm2EncDecTest"));
    }

    auto result = plugin->sm2EncDecTest(devName, appName, containerName, plainText);
    if (result.isErr()) {
        qWarning() << "[CertService::sm2EncDecTest] failed"
                   << "devName:" << devName
                   << "appName:" << appName
                   << "containerName:" << containerName
                   << "error:" << result.error().toString(true);
        return result;
    }

    qInfo() << "[CertService::sm2EncDecTest] success"
            << "devName:" << devName
            << "appName:" << appName
            << "containerName:" << containerName
            << "cipherChars:" << result.value().encryptedData.size()
            << "consistent:" << result.value().consistent;
    return result;
}

Result<QString> CertService::rsaEncrypt(const QString& devName, const QString& appName,
                                        const QString& containerName, bool useSignKey,
                                        const QString& plainText) {
    auto validation = validateNonEmpty(plainText, "测试明文不能为空", "CertService::rsaEncrypt");
    if (validation.isErr()) {
        return Result<QString>::err(validation.error());
    }

    auto plugin = PluginManager::instance().activePluginShared();
    if (!plugin) {
        return Result<QString>::err(
            Error(Error::NoActiveModule, "驱动模块未激活", "CertService::rsaEncrypt"));
    }
    return plugin->rsaEncrypt(devName, appName, containerName, useSignKey, plainText);
}

Result<QString> CertService::rsaDecrypt(const QString& devName, const QString& appName,
                                        const QString& containerName, bool useSignKey,
                                        const QString& encryptedData) {
    auto validation = validateNonEmpty(encryptedData, "密文不能为空", "CertService::rsaDecrypt");
    if (validation.isErr()) {
        return Result<QString>::err(validation.error());
    }

    auto plugin = PluginManager::instance().activePluginShared();
    if (!plugin) {
        return Result<QString>::err(
            Error(Error::NoActiveModule, "驱动模块未激活", "CertService::rsaDecrypt"));
    }
    return plugin->rsaDecrypt(devName, appName, containerName, useSignKey, encryptedData);
}

Result<QString> CertService::sm2Encrypt(const QString& devName, const QString& appName,
                                        const QString& containerName, const QString& plainText) {
    auto validation = validateNonEmpty(plainText, "测试明文不能为空", "CertService::sm2Encrypt");
    if (validation.isErr()) {
        return Result<QString>::err(validation.error());
    }

    auto plugin = PluginManager::instance().activePluginShared();
    if (!plugin) {
        return Result<QString>::err(
            Error(Error::NoActiveModule, "驱动模块未激活", "CertService::sm2Encrypt"));
    }
    return plugin->sm2Encrypt(devName, appName, containerName, plainText);
}

Result<QString> CertService::sm2Decrypt(const QString& devName, const QString& appName,
                                        const QString& containerName, const QString& encryptedData) {
    auto validation = validateNonEmpty(encryptedData, "密文不能为空", "CertService::sm2Decrypt");
    if (validation.isErr()) {
        return Result<QString>::err(validation.error());
    }

    auto plugin = PluginManager::instance().activePluginShared();
    if (!plugin) {
        return Result<QString>::err(
            Error(Error::NoActiveModule, "驱动模块未激活", "CertService::sm2Decrypt"));
    }
    return plugin->sm2Decrypt(devName, appName, containerName, encryptedData);
}

}  // namespace wekey
