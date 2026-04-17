#include <QtTest>

#include <memory>
#include <type_traits>

#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "common/Error.h"
#include "core/crypto/CertService.h"
#include "plugin/PluginManager.h"

namespace wekey {

namespace {

QStringList gCapturedMessages;

void captureQtMessage(QtMsgType, const QMessageLogContext&, const QString& message) {
    gCapturedMessages.append(message);
}

class ScopedMessageCapture {
public:
    ScopedMessageCapture() : previous_(qInstallMessageHandler(captureQtMessage)) {
        gCapturedMessages.clear();
    }

    ~ScopedMessageCapture() {
        qInstallMessageHandler(previous_);
    }

    [[nodiscard]] QString joined() const {
        return gCapturedMessages.join('\n');
    }

private:
    QtMessageHandler previous_ = nullptr;
};

template <typename T, typename = void>
struct HasImportCert : std::false_type {};

template <typename T>
struct HasImportCert<T, std::void_t<decltype(&T::importCert)>> : std::true_type {};

static_assert(!HasImportCert<IDriverPlugin>::value,
              "IDriverPlugin should only expose importKeyCert");

using EvpPkeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using X509Ptr = std::unique_ptr<X509, decltype(&X509_free)>;
using EvpPkeyCtxPtr = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;

struct TestCertMaterial {
    QByteArray certDer;
};

QByteArray encodeX509ToDer(X509* cert) {
    const int len = i2d_X509(cert, nullptr);
    if (len <= 0) {
        return {};
    }
    QByteArray der(len, Qt::Uninitialized);
    unsigned char* p = reinterpret_cast<unsigned char*>(der.data());
    i2d_X509(cert, &p);
    return der;
}

EvpPkeyPtr generateRsaKeyPair() {
    EvpPkeyCtxPtr ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr), &EVP_PKEY_CTX_free);
    if (!ctx || EVP_PKEY_keygen_init(ctx.get()) != 1 ||
        EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.get(), 2048) != 1) {
        return EvpPkeyPtr(nullptr, &EVP_PKEY_free);
    }

    EVP_PKEY* rawKey = nullptr;
    if (EVP_PKEY_keygen(ctx.get(), &rawKey) != 1) {
        return EvpPkeyPtr(nullptr, &EVP_PKEY_free);
    }
    return EvpPkeyPtr(rawKey, &EVP_PKEY_free);
}

TestCertMaterial makeRsaCertMaterial(long notBeforeOffsetSeconds = -60,
                                     long notAfterOffsetSeconds = 3600) {
    auto key = generateRsaKeyPair();
    if (!key) {
        return {};
    }

    X509Ptr cert(X509_new(), &X509_free);
    if (!cert) {
        return {};
    }

    X509_set_version(cert.get(), 2);
    ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), 1);
    X509_gmtime_adj(X509_getm_notBefore(cert.get()), notBeforeOffsetSeconds);
    X509_gmtime_adj(X509_getm_notAfter(cert.get()), notAfterOffsetSeconds);
    X509_set_pubkey(cert.get(), key.get());

    X509_NAME* subject = X509_get_subject_name(cert.get());
    X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char*>("unit-test"), -1, -1, 0);
    X509_set_issuer_name(cert.get(), subject);

    if (X509_sign(cert.get(), key.get(), EVP_sha256()) <= 0) {
        return {};
    }

    return {encodeX509ToDer(cert.get())};
}

class FakeDriverPlugin final : public IDriverPlugin {
public:
    Result<QList<DeviceInfo>> enumDevices(bool) override {
        return Result<QList<DeviceInfo>>::err(
            Error(Error::Fail, "not implemented", "FakeDriverPlugin::enumDevices"));
    }

    Result<void> changeDeviceAuth(const QString&, const QString&, const QString&) override {
        return Result<void>::err(
            Error(Error::Fail, "not implemented", "FakeDriverPlugin::changeDeviceAuth"));
    }

    Result<void> setDeviceLabel(const QString&, const QString&) override {
        return Result<void>::err(
            Error(Error::Fail, "not implemented", "FakeDriverPlugin::setDeviceLabel"));
    }

    Result<int> waitForDeviceEvent() override {
        return Result<int>::err(
            Error(Error::Fail, "not implemented", "FakeDriverPlugin::waitForDeviceEvent"));
    }

    Result<QList<AppInfo>> enumApps(const QString&) override {
        return Result<QList<AppInfo>>::err(
            Error(Error::Fail, "not implemented", "FakeDriverPlugin::enumApps"));
    }

    Result<void> createApp(const QString&, const QString&, const QVariantMap&) override {
        return Result<void>::err(
            Error(Error::Fail, "not implemented", "FakeDriverPlugin::createApp"));
    }

    Result<void> deleteApp(const QString&, const QString&) override {
        return Result<void>::err(
            Error(Error::Fail, "not implemented", "FakeDriverPlugin::deleteApp"));
    }

    Result<void> openApp(const QString&, const QString&, const QString&, const QString&) override {
        return Result<void>::err(
            Error(Error::Fail, "not implemented", "FakeDriverPlugin::openApp"));
    }

    Result<void> closeApp(const QString&, const QString&) override {
        return Result<void>::err(
            Error(Error::Fail, "not implemented", "FakeDriverPlugin::closeApp"));
    }

    Result<void> changePin(const QString&, const QString&, const QString&, const QString&,
                           const QString&) override {
        return Result<void>::err(
            Error(Error::Fail, "not implemented", "FakeDriverPlugin::changePin"));
    }

    Result<void> unlockPin(const QString&, const QString&, const QString&, const QString&,
                           const QVariantMap&) override {
        return Result<void>::err(
            Error(Error::Fail, "not implemented", "FakeDriverPlugin::unlockPin"));
    }

    Result<int> getRetryCount(const QString&, const QString&, const QString&, const QString&) override {
        return Result<int>::err(
            Error(Error::Fail, "not implemented", "FakeDriverPlugin::getRetryCount"));
    }

    Result<PinInfo> getPinInfo(const QString&, const QString&, const QString&) override {
        return Result<PinInfo>::err(
            Error(Error::Fail, "not implemented", "FakeDriverPlugin::getPinInfo"));
    }

    Result<QList<ContainerInfo>> enumContainers(const QString&, const QString&) override {
        return Result<QList<ContainerInfo>>::ok(containers);
    }

    Result<void> createContainer(const QString&, const QString&, const QString&) override {
        return Result<void>::err(
            Error(Error::Fail, "not implemented", "FakeDriverPlugin::createContainer"));
    }

    Result<void> deleteContainer(const QString&, const QString&, const QString&) override {
        return Result<void>::err(
            Error(Error::Fail, "not implemented", "FakeDriverPlugin::deleteContainer"));
    }

    Result<QByteArray> generateKeyPair(const QString&, const QString&, const QString&,
                                       const QString&) override {
        return Result<QByteArray>::err(
            Error(Error::Fail, "not implemented", "FakeDriverPlugin::generateKeyPair"));
    }

    Result<QByteArray> generateCsr(const QString&, const QString&, const QString&,
                                   const QVariantMap&) override {
        return Result<QByteArray>::err(
            Error(Error::Fail, "not implemented", "FakeDriverPlugin::generateCsr"));
    }

    Result<void> importKeyCert(const QString&, const QString&, const QString&, const QByteArray& sigCert,
                               const QByteArray& encCert, const QByteArray&, bool) override {
        importKeyCertCalled = true;
        if (importKeyCertResult.isErr()) {
            return importKeyCertResult;
        }

        auto buildPostImportError = [](const QString& stage, const Error& cause) {
            return Error(cause.code(),
                         QString("导入已执行，但%1失败：%2").arg(stage, cause.friendlyMessage()),
                         "FakeDriverPlugin::importKeyCert");
        };

        const QString devName = QStringLiteral("dev-1");
        const QString appName = QStringLiteral("app-1");
        const QString containerName = QStringLiteral("container-1");

        if (!sigCert.isEmpty()) {
            const QByteArray payload("wekey-import-cert-sign-check");
            auto signOutcome = sign(devName, appName, containerName, payload);
            if (signOutcome.isErr()) {
                return Result<void>::err(buildPostImportError("签名验签校验", signOutcome.error()));
            }
            auto verifyOutcome = verify(devName, appName, containerName, payload, signOutcome.value());
            if (verifyOutcome.isErr()) {
                return Result<void>::err(buildPostImportError("签名验签校验", verifyOutcome.error()));
            }
            if (!verifyOutcome.value()) {
                return Result<void>::err(
                    Error(Error::Fail, "导入已执行，但签名验签校验失败：签名无效",
                          "FakeDriverPlugin::importKeyCert"));
            }
        }

        if (!encCert.isEmpty()) {
            const QString plainText = QStringLiteral("wekey-import-cert-enc-check");
            const auto keyType = containers.isEmpty()
                ? ContainerInfo::KeyType::Unknown
                : containers.first().keyType;
            if (keyType == ContainerInfo::KeyType::RSA) {
                auto encryptOutcome = rsaEncrypt(devName, appName, containerName, false, plainText);
                if (encryptOutcome.isErr()) {
                    return Result<void>::err(buildPostImportError("加密解密校验", encryptOutcome.error()));
                }
                auto decryptOutcome = rsaDecrypt(devName, appName, containerName, false,
                                                 encryptOutcome.value());
                if (decryptOutcome.isErr()) {
                    return Result<void>::err(buildPostImportError("加密解密校验", decryptOutcome.error()));
                }
                if (decryptOutcome.value() != plainText) {
                    return Result<void>::err(
                        Error(Error::Fail, "导入已执行，但加密解密校验失败：解密结果与原文不一致",
                              "FakeDriverPlugin::importKeyCert"));
                }
            } else if (keyType == ContainerInfo::KeyType::SM2) {
                auto encryptOutcome = sm2Encrypt(devName, appName, containerName, plainText);
                if (encryptOutcome.isErr()) {
                    return Result<void>::err(buildPostImportError("加密解密校验", encryptOutcome.error()));
                }
                auto decryptOutcome = sm2Decrypt(devName, appName, containerName,
                                                 encryptOutcome.value());
                if (decryptOutcome.isErr()) {
                    return Result<void>::err(buildPostImportError("加密解密校验", decryptOutcome.error()));
                }
                if (decryptOutcome.value() != plainText) {
                    return Result<void>::err(
                        Error(Error::Fail, "导入已执行，但加密解密校验失败：解密结果与原文不一致",
                              "FakeDriverPlugin::importKeyCert"));
                }
            }
        }

        return Result<void>::ok();
    }

    Result<QByteArray> exportCert(const QString&, const QString&, const QString&, bool) override {
        return Result<QByteArray>::err(
            Error(Error::Fail, "not implemented", "FakeDriverPlugin::exportCert"));
    }

    Result<CertInfo> getCertInfo(const QString&, const QString&, const QString&, bool) override {
        return Result<CertInfo>::err(
            Error(Error::Fail, "not implemented", "FakeDriverPlugin::getCertInfo"));
    }

    Result<QByteArray> sign(const QString&, const QString&, const QString&, const QByteArray&) override {
        signCalled = true;
        return signResult;
    }

    Result<bool> verify(const QString&, const QString&, const QString&, const QByteArray&,
                        const QByteArray&) override {
        verifyCalled = true;
        return verifyResult;
    }

    Result<QStringList> enumFiles(const QString&, const QString&) override {
        return Result<QStringList>::err(
            Error(Error::Fail, "not implemented", "FakeDriverPlugin::enumFiles"));
    }

    Result<QByteArray> readFile(const QString&, const QString&, const QString&) override {
        return Result<QByteArray>::err(
            Error(Error::Fail, "not implemented", "FakeDriverPlugin::readFile"));
    }

    Result<void> writeFile(const QString&, const QString&, const QString&, const QByteArray&, int,
                           int) override {
        return Result<void>::err(
            Error(Error::Fail, "not implemented", "FakeDriverPlugin::writeFile"));
    }

    Result<void> deleteFile(const QString&, const QString&, const QString&) override {
        return Result<void>::err(
            Error(Error::Fail, "not implemented", "FakeDriverPlugin::deleteFile"));
    }

    Result<QByteArray> generateRandom(const QString&, int) override {
        return Result<QByteArray>::err(
            Error(Error::Fail, "not implemented", "FakeDriverPlugin::generateRandom"));
    }

    Result<EncDecTestResult> rsaEncDecTest(const QString& devName, const QString& appName,
                                           const QString& containerName, bool useSignKey,
                                           const QString& plainText) override {
        rsaCalled = true;
        lastDevName = devName;
        lastAppName = appName;
        lastContainerName = containerName;
        lastUseSignKey = useSignKey;
        lastPlainText = plainText;
        return rsaResult;
    }

    Result<EncDecTestResult> sm2EncDecTest(const QString& devName, const QString& appName,
                                           const QString& containerName,
                                           const QString& plainText) override {
        sm2Called = true;
        lastDevName = devName;
        lastAppName = appName;
        lastContainerName = containerName;
        lastPlainText = plainText;
        return sm2Result;
    }

    Result<QString> rsaEncrypt(const QString& devName, const QString& appName,
                               const QString& containerName, bool useSignKey,
                               const QString& plainText) override {
        rsaEncryptCalled = true;
        lastDevName = devName;
        lastAppName = appName;
        lastContainerName = containerName;
        lastUseSignKey = useSignKey;
        lastPlainText = plainText;
        return rsaEncryptResult;
    }

    Result<QString> rsaDecrypt(const QString& devName, const QString& appName,
                               const QString& containerName, bool useSignKey,
                               const QString& encryptedData) override {
        rsaDecryptCalled = true;
        lastDevName = devName;
        lastAppName = appName;
        lastContainerName = containerName;
        lastUseSignKey = useSignKey;
        lastEncryptedData = encryptedData;
        return rsaDecryptResult;
    }

    Result<QString> sm2Encrypt(const QString& devName, const QString& appName,
                               const QString& containerName,
                               const QString& plainText) override {
        sm2EncryptCalled = true;
        lastDevName = devName;
        lastAppName = appName;
        lastContainerName = containerName;
        lastPlainText = plainText;
        return sm2EncryptResult;
    }

    Result<QString> sm2Decrypt(const QString& devName, const QString& appName,
                               const QString& containerName,
                               const QString& encryptedData) override {
        sm2DecryptCalled = true;
        lastDevName = devName;
        lastAppName = appName;
        lastContainerName = containerName;
        lastEncryptedData = encryptedData;
        return sm2DecryptResult;
    }

    bool rsaCalled = false;
    bool sm2Called = false;
    bool rsaEncryptCalled = false;
    bool rsaDecryptCalled = false;
    bool sm2EncryptCalled = false;
    bool sm2DecryptCalled = false;
    bool signCalled = false;
    bool verifyCalled = false;
    bool importKeyCertCalled = false;
    bool lastUseSignKey = false;
    QString lastDevName;
    QString lastAppName;
    QString lastContainerName;
    QString lastPlainText;
    QString lastEncryptedData;
    QList<ContainerInfo> containers;
    Result<void> importKeyCertResult = Result<void>::ok();
    Result<QByteArray> signResult = Result<QByteArray>::ok(QByteArray("signature"));
    Result<bool> verifyResult = Result<bool>::ok(true);
    Result<EncDecTestResult> rsaResult = Result<EncDecTestResult>::ok(
        EncDecTestResult{"plain", "cipher", "plain", true});
    Result<EncDecTestResult> sm2Result = Result<EncDecTestResult>::ok(
        EncDecTestResult{"plain", "cipher", "plain", true});
    Result<QString> rsaEncryptResult = Result<QString>::ok(QStringLiteral("rsa-cipher"));
    Result<QString> rsaDecryptResult = Result<QString>::ok(QStringLiteral("rsa-plain"));
    Result<QString> sm2EncryptResult = Result<QString>::ok(QStringLiteral("sm2-cipher"));
    Result<QString> sm2DecryptResult = Result<QString>::ok(QStringLiteral("sm2-plain"));
};

class CertServiceTest : public QObject {
    Q_OBJECT

private slots:
    void cleanup() {
        auto& pluginManager = PluginManager::instance();
        if (pluginManager.activePluginName() == kPluginName) {
            pluginManager.unregisterPlugin(kPluginName, false);
        } else if (pluginManager.getPlugin(kPluginName)) {
            pluginManager.unregisterPlugin(kPluginName, false);
        }
    }

    void rsaEncDecTest_withoutActivePlugin_returnsNoActiveModule() {
        auto result = CertService::instance().rsaEncDecTest(
            "dev-1", "app-1", "container-1", true, "hello");

        QVERIFY(result.isErr());
        QCOMPARE(result.error().code(), Error::NoActiveModule);
    }

    void rsaEncDecTest_withEmptyPlainText_rejectsBeforePluginCall() {
        auto plugin = std::make_shared<FakeDriverPlugin>();
        auto& pluginManager = PluginManager::instance();
        QVERIFY(pluginManager.registerPluginInstance(kPluginName, plugin).isOk());
        QVERIFY(pluginManager.setActivePlugin(kPluginName, false).isOk());

        auto result = CertService::instance().rsaEncDecTest(
            "dev-1", "app-1", "container-1", false, "   ");

        QVERIFY(result.isErr());
        QCOMPARE(result.error().code(), Error::InvalidParam);
        QVERIFY(!plugin->rsaCalled);
    }

    void rsaEncDecTest_delegatesToPlugin() {
        auto plugin = std::make_shared<FakeDriverPlugin>();
        auto& pluginManager = PluginManager::instance();
        QVERIFY(pluginManager.registerPluginInstance(kPluginName, plugin).isOk());
        QVERIFY(pluginManager.setActivePlugin(kPluginName, false).isOk());

        EncDecTestResult expected{"输入原文", "Y2lwaGVy", "输入原文", true};
        plugin->rsaResult = Result<EncDecTestResult>::ok(expected);

        auto result = CertService::instance().rsaEncDecTest(
            "dev-9", "app-9", "container-rsa", true, expected.plainText);

        QVERIFY(result.isOk());
        QVERIFY(plugin->rsaCalled);
        QCOMPARE(plugin->lastDevName, QString("dev-9"));
        QCOMPARE(plugin->lastAppName, QString("app-9"));
        QCOMPARE(plugin->lastContainerName, QString("container-rsa"));
        QVERIFY(plugin->lastUseSignKey);
        QCOMPARE(plugin->lastPlainText, expected.plainText);
        QCOMPARE(result.value().encryptedData, expected.encryptedData);
        QCOMPARE(result.value().decryptedData, expected.decryptedData);
        QCOMPARE(result.value().consistent, expected.consistent);
    }

    void rsaEncDecTest_logsStartAndFinishContext() {
        auto plugin = std::make_shared<FakeDriverPlugin>();
        auto& pluginManager = PluginManager::instance();
        QVERIFY(pluginManager.registerPluginInstance(kPluginName, plugin).isOk());
        QVERIFY(pluginManager.setActivePlugin(kPluginName, false).isOk());

        EncDecTestResult expected{"日志测试明文", "Y2lwaGVy", "日志测试明文", true};
        plugin->rsaResult = Result<EncDecTestResult>::ok(expected);

        ScopedMessageCapture capture;
        auto result = CertService::instance().rsaEncDecTest(
            "dev-log", "app-log", "container-log", false, expected.plainText);

        QVERIFY(result.isOk());
        const QString logs = capture.joined();
        QVERIFY2(logs.contains("CertService::rsaEncDecTest"), qPrintable(logs));
        QVERIFY2(logs.contains("dev-log"), qPrintable(logs));
        QVERIFY2(logs.contains("app-log"), qPrintable(logs));
        QVERIFY2(logs.contains("container-log"), qPrintable(logs));
        QVERIFY2(logs.contains("success"), qPrintable(logs));
    }

    void sm2EncDecTest_delegatesToPlugin() {
        auto plugin = std::make_shared<FakeDriverPlugin>();
        auto& pluginManager = PluginManager::instance();
        QVERIFY(pluginManager.registerPluginInstance(kPluginName, plugin).isOk());
        QVERIFY(pluginManager.setActivePlugin(kPluginName, false).isOk());

        EncDecTestResult expected{"hello-sm2", "Y2lwaGVyLXNtMg==", "hello-sm2", true};
        plugin->sm2Result = Result<EncDecTestResult>::ok(expected);

        auto result = CertService::instance().sm2EncDecTest(
            "dev-sm2", "app-sm2", "container-sm2", expected.plainText);

        QVERIFY(result.isOk());
        QVERIFY(plugin->sm2Called);
        QCOMPARE(plugin->lastDevName, QString("dev-sm2"));
        QCOMPARE(plugin->lastAppName, QString("app-sm2"));
        QCOMPARE(plugin->lastContainerName, QString("container-sm2"));
        QCOMPARE(plugin->lastPlainText, expected.plainText);
        QCOMPARE(result.value().encryptedData, expected.encryptedData);
        QCOMPARE(result.value().decryptedData, expected.decryptedData);
        QCOMPARE(result.value().consistent, expected.consistent);
    }

    void importKeyCert_withExpiredSignCert_stillRunsPostChecks() {
        auto plugin = std::make_shared<FakeDriverPlugin>();
        ContainerInfo container;
        container.containerName = QStringLiteral("container-1");
        container.keyGenerated = true;
        container.keyType = ContainerInfo::KeyType::RSA;
        container.signKeyAvailable = true;
        container.encKeyAvailable = true;
        plugin->containers = {container};

        auto& pluginManager = PluginManager::instance();
        QVERIFY(pluginManager.registerPluginInstance(kPluginName, plugin).isOk());
        QVERIFY(pluginManager.setActivePlugin(kPluginName, false).isOk());

        const TestCertMaterial expired = makeRsaCertMaterial(-7200, -3600);
        QVERIFY(!expired.certDer.isEmpty());

        auto result = CertService::instance().importKeyCert(
            "dev-1", "app-1", "container-1", expired.certDer, {}, {}, false);

        QVERIFY(result.isOk());
        QVERIFY(plugin->importKeyCertCalled);
        QVERIFY(plugin->signCalled);
        QVERIFY(plugin->verifyCalled);
    }

    void importKeyCert_withExpiredEncCert_stillRunsPostChecks() {
        auto plugin = std::make_shared<FakeDriverPlugin>();
        ContainerInfo container;
        container.containerName = QStringLiteral("container-1");
        container.keyGenerated = true;
        container.keyType = ContainerInfo::KeyType::RSA;
        container.signKeyAvailable = true;
        container.encKeyAvailable = true;
        plugin->containers = {container};

        const TestCertMaterial expired = makeRsaCertMaterial(-7200, -3600);
        QVERIFY(!expired.certDer.isEmpty());
        plugin->rsaDecryptResult = Result<QString>::ok(QStringLiteral("wekey-import-cert-enc-check"));

        auto& pluginManager = PluginManager::instance();
        QVERIFY(pluginManager.registerPluginInstance(kPluginName, plugin).isOk());
        QVERIFY(pluginManager.setActivePlugin(kPluginName, false).isOk());

        auto result = CertService::instance().importKeyCert(
            "dev-1", "app-1", "container-1", {}, expired.certDer, {}, false);

        QVERIFY(result.isOk());
        QVERIFY(plugin->importKeyCertCalled);
        QVERIFY(plugin->rsaEncryptCalled);
        QVERIFY(plugin->rsaDecryptCalled);
    }

    void importKeyCert_withSignVerifyFailure_returnsErrAfterImport() {
        auto plugin = std::make_shared<FakeDriverPlugin>();
        ContainerInfo container;
        container.containerName = QStringLiteral("container-1");
        container.keyGenerated = true;
        container.keyType = ContainerInfo::KeyType::RSA;
        container.signKeyAvailable = true;
        container.encKeyAvailable = true;
        plugin->containers = {container};

        const TestCertMaterial signCert = makeRsaCertMaterial();
        QVERIFY(!signCert.certDer.isEmpty());
        plugin->verifyResult = Result<bool>::ok(false);

        auto& pluginManager = PluginManager::instance();
        QVERIFY(pluginManager.registerPluginInstance(kPluginName, plugin).isOk());
        QVERIFY(pluginManager.setActivePlugin(kPluginName, false).isOk());

        auto result = CertService::instance().importKeyCert(
            "dev-1", "app-1", "container-1", signCert.certDer, {}, {}, false);

        QVERIFY(result.isErr());
        QVERIFY(plugin->importKeyCertCalled);
        QVERIFY(plugin->signCalled);
        QVERIFY(plugin->verifyCalled);
    }

    void importKeyCert_withEncDecryptFailure_returnsErrAfterImport() {
        auto plugin = std::make_shared<FakeDriverPlugin>();
        ContainerInfo container;
        container.containerName = QStringLiteral("container-1");
        container.keyGenerated = true;
        container.keyType = ContainerInfo::KeyType::RSA;
        container.signKeyAvailable = true;
        container.encKeyAvailable = true;
        plugin->containers = {container};

        const TestCertMaterial encCert = makeRsaCertMaterial();
        QVERIFY(!encCert.certDer.isEmpty());
        plugin->rsaDecryptResult = Result<QString>::err(
            Error(Error::Fail, "decrypt failed", "FakeDriverPlugin::rsaDecrypt"));

        auto& pluginManager = PluginManager::instance();
        QVERIFY(pluginManager.registerPluginInstance(kPluginName, plugin).isOk());
        QVERIFY(pluginManager.setActivePlugin(kPluginName, false).isOk());

        auto result = CertService::instance().importKeyCert(
            "dev-1", "app-1", "container-1", {}, encCert.certDer, {}, false);

        QVERIFY(result.isErr());
        QVERIFY(plugin->importKeyCertCalled);
        QVERIFY(plugin->rsaEncryptCalled);
        QVERIFY(plugin->rsaDecryptCalled);
    }

    void rsaEncrypt_delegatesToPlugin() {
        auto plugin = std::make_shared<FakeDriverPlugin>();
        auto& pluginManager = PluginManager::instance();
        QVERIFY(pluginManager.registerPluginInstance(kPluginName, plugin).isOk());
        QVERIFY(pluginManager.setActivePlugin(kPluginName, false).isOk());

        plugin->rsaEncryptResult = Result<QString>::ok(QStringLiteral("cipher-base64"));
        auto result = CertService::instance().rsaEncrypt(
            "dev-rsa", "app-rsa", "container-rsa", true, "hello");

        QVERIFY(result.isOk());
        QVERIFY(plugin->rsaEncryptCalled);
        QCOMPARE(plugin->lastDevName, QString("dev-rsa"));
        QCOMPARE(plugin->lastAppName, QString("app-rsa"));
        QCOMPARE(plugin->lastContainerName, QString("container-rsa"));
        QVERIFY(plugin->lastUseSignKey);
        QCOMPARE(plugin->lastPlainText, QString("hello"));
        QCOMPARE(result.value(), QString("cipher-base64"));
    }

    void rsaDecrypt_delegatesToPlugin() {
        auto plugin = std::make_shared<FakeDriverPlugin>();
        auto& pluginManager = PluginManager::instance();
        QVERIFY(pluginManager.registerPluginInstance(kPluginName, plugin).isOk());
        QVERIFY(pluginManager.setActivePlugin(kPluginName, false).isOk());

        plugin->rsaDecryptResult = Result<QString>::ok(QStringLiteral("plain-back"));
        auto result = CertService::instance().rsaDecrypt(
            "dev-rsa", "app-rsa", "container-rsa", false, "cipher-data");

        QVERIFY(result.isOk());
        QVERIFY(plugin->rsaDecryptCalled);
        QCOMPARE(plugin->lastEncryptedData, QString("cipher-data"));
        QCOMPARE(result.value(), QString("plain-back"));
    }

    void sm2Encrypt_delegatesToPlugin() {
        auto plugin = std::make_shared<FakeDriverPlugin>();
        auto& pluginManager = PluginManager::instance();
        QVERIFY(pluginManager.registerPluginInstance(kPluginName, plugin).isOk());
        QVERIFY(pluginManager.setActivePlugin(kPluginName, false).isOk());

        plugin->sm2EncryptResult = Result<QString>::ok(QStringLiteral("sm2-cipher-base64"));
        auto result = CertService::instance().sm2Encrypt(
            "dev-sm2", "app-sm2", "container-sm2", "hello");

        QVERIFY(result.isOk());
        QVERIFY(plugin->sm2EncryptCalled);
        QCOMPARE(plugin->lastPlainText, QString("hello"));
        QCOMPARE(result.value(), QString("sm2-cipher-base64"));
    }

    void sm2Decrypt_delegatesToPlugin() {
        auto plugin = std::make_shared<FakeDriverPlugin>();
        auto& pluginManager = PluginManager::instance();
        QVERIFY(pluginManager.registerPluginInstance(kPluginName, plugin).isOk());
        QVERIFY(pluginManager.setActivePlugin(kPluginName, false).isOk());

        plugin->sm2DecryptResult = Result<QString>::ok(QStringLiteral("sm2-plain-back"));
        auto result = CertService::instance().sm2Decrypt(
            "dev-sm2", "app-sm2", "container-sm2", "cipher-data");

        QVERIFY(result.isOk());
        QVERIFY(plugin->sm2DecryptCalled);
        QCOMPARE(plugin->lastEncryptedData, QString("cipher-data"));
        QCOMPARE(result.value(), QString("sm2-plain-back"));
    }

private:
    static inline const QString kPluginName = QStringLiteral("cert-service-test-plugin");
};

}  // namespace

}  // namespace wekey

QTEST_GUILESS_MAIN(wekey::CertServiceTest)

#include "CertServiceTest.moc"
