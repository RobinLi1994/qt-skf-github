#include <QtTest>

#include <openssl/asn1.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wkeyword-macro"
#define private public
#include "plugin/skf/SkfPlugin.h"
#undef private
#pragma clang diagnostic pop

namespace wekey {

namespace {

const auto kDeviceHandle = reinterpret_cast<skf::DEVHANDLE>(quintptr(0x1));
const auto kAppHandle = reinterpret_cast<skf::HAPPLICATION>(quintptr(0x2));
const auto kContainerHandle = reinterpret_cast<skf::HCONTAINER>(quintptr(0x3));
const auto kHashHandle = reinterpret_cast<skf::HANDLE>(quintptr(0x4));
constexpr int kRsaBitLen = 512;
constexpr int kRsaSigBytes = kRsaBitLen / 8;

skf::ULONG fakeGetContainerType(skf::HCONTAINER, skf::ULONG* containerType) {
    *containerType = 1;
    return skf::SAR_OK;
}

skf::ULONG fakeExportPublicKey(skf::HCONTAINER, skf::BOOL, skf::BYTE* keyBlob, skf::ULONG* keyLen) {
    auto* rsaBlob = reinterpret_cast<skf::RSAPUBLICKEYBLOB*>(keyBlob);
    std::memset(rsaBlob, 0, sizeof(*rsaBlob));
    rsaBlob->bitLen = kRsaBitLen;
    *keyLen = sizeof(*rsaBlob);
    return skf::SAR_OK;
}

skf::ULONG fakeDigestInit(skf::DEVHANDLE, skf::ULONG, skf::ECCPUBLICKEYBLOB*, skf::BYTE*, skf::ULONG,
                          skf::HANDLE* hashHandle) {
    *hashHandle = kHashHandle;
    return skf::SAR_OK;
}

skf::ULONG fakeDigest(skf::HANDLE, skf::BYTE*, skf::ULONG, skf::BYTE* digest, skf::ULONG* digestLen) {
    std::memset(digest, 0x5A, 32);
    *digestLen = 32;
    return skf::SAR_OK;
}

skf::ULONG fakeRsaVerify(skf::DEVHANDLE, skf::RSAPUBLICKEYBLOB*, skf::BYTE*, skf::ULONG, skf::BYTE*, skf::ULONG) {
    return skf::SAR_OK;
}

void primeActiveSession(SkfPlugin& plugin) {
    HandleInfo deviceInfo;
    deviceInfo.devHandle = kDeviceHandle;
    plugin.handles_.insert(plugin.makeKey("dev-1"), deviceInfo);

    HandleInfo appInfo;
    appInfo.appHandle = kAppHandle;
    plugin.handles_.insert(plugin.makeKey("dev-1", "app-1"), appInfo);

    HandleInfo containerInfo;
    containerInfo.containerHandle = kContainerHandle;
    plugin.handles_.insert(plugin.makeKey("dev-1", "app-1", "container-1"), containerInfo);

    LoginInfo loginInfo;
    loginInfo.pin = QStringLiteral("123456789");
    loginInfo.role = QStringLiteral("user");
    plugin.loginCache_.insert(QStringLiteral("dev-1/app-1"), loginInfo);
}

void primeVerifyLibrary(SkfPlugin& plugin) {
    plugin.lib_ = std::make_unique<SkfLibrary>(QStringLiteral("/nonexistent"));
    plugin.lib_->GetContainerType = fakeGetContainerType;
    plugin.lib_->ExportPublicKey = fakeExportPublicKey;
    plugin.lib_->DigestInit = fakeDigestInit;
    plugin.lib_->Digest = fakeDigest;
    plugin.lib_->RSAVerify = fakeRsaVerify;
}

QByteArray makeCertificateDerWithSerial(const QByteArray& serialHex) {
    X509* x509 = X509_new();
    if (!x509) {
        return {};
    }

    X509_set_version(x509, 2);

    BIGNUM* serialBn = nullptr;
    BN_hex2bn(&serialBn, serialHex.constData());
    ASN1_INTEGER* serial = BN_to_ASN1_INTEGER(serialBn, nullptr);
    X509_set_serialNumber(x509, serial);
    ASN1_INTEGER_free(serial);
    BN_free(serialBn);

    X509_NAME* name = X509_NAME_new();
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char*>("CN"), -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char*>("11122"), -1, -1, 0);
    X509_set_subject_name(x509, name);
    X509_set_issuer_name(x509, name);
    X509_NAME_free(name);

    ASN1_TIME_set_string(X509_getm_notBefore(x509), "20260424082321Z");
    ASN1_TIME_set_string(X509_getm_notAfter(x509), "20270424082321Z");

    EVP_PKEY_CTX* pkeyCtx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    EVP_PKEY* pkey = nullptr;
    EVP_PKEY_keygen_init(pkeyCtx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(pkeyCtx, 2048);
    EVP_PKEY_keygen(pkeyCtx, &pkey);
    EVP_PKEY_CTX_free(pkeyCtx);

    X509_set_pubkey(x509, pkey);
    X509_sign(x509, pkey, EVP_sha256());
    EVP_PKEY_free(pkey);

    int derLen = i2d_X509(x509, nullptr);
    QByteArray der(derLen, Qt::Uninitialized);
    unsigned char* out = reinterpret_cast<unsigned char*>(der.data());
    i2d_X509(x509, &out);
    X509_free(x509);

    return der;
}

}  // namespace

class SkfPluginTest : public QObject {
    Q_OBJECT

private slots:
    void hasActiveDeviceSessionLockedReturnsTrueWhenDeviceKeepsLoginState();
    void hasActiveDeviceSessionLockedReturnsFalseForStandaloneDeviceHandle();
    void verifyDoesNotTearDownLoggedInSession();
    void parseDerCertificateReturnsUppercaseSerialNumber();
};

void SkfPluginTest::hasActiveDeviceSessionLockedReturnsTrueWhenDeviceKeepsLoginState() {
    SkfPlugin plugin;

    HandleInfo deviceInfo;
    deviceInfo.devHandle = reinterpret_cast<skf::DEVHANDLE>(quintptr(0x1));
    plugin.handles_.insert(plugin.makeKey("dev-1"), deviceInfo);

    HandleInfo appInfo;
    appInfo.appHandle = reinterpret_cast<skf::HAPPLICATION>(quintptr(0x2));
    plugin.handles_.insert(plugin.makeKey("dev-1", "app-1"), appInfo);

    HandleInfo containerInfo;
    containerInfo.containerHandle = reinterpret_cast<skf::HCONTAINER>(quintptr(0x3));
    plugin.handles_.insert(plugin.makeKey("dev-1", "app-1", "container-1"), containerInfo);

    LoginInfo loginInfo;
    loginInfo.pin = QStringLiteral("123456789");
    loginInfo.role = QStringLiteral("user");
    plugin.loginCache_.insert(QStringLiteral("dev-1/app-1"), loginInfo);

    QVERIFY(plugin.hasActiveDeviceSessionLocked(QStringLiteral("dev-1")));
}

void SkfPluginTest::hasActiveDeviceSessionLockedReturnsFalseForStandaloneDeviceHandle() {
    SkfPlugin plugin;

    HandleInfo deviceInfo;
    deviceInfo.devHandle = reinterpret_cast<skf::DEVHANDLE>(quintptr(0x1));
    plugin.handles_.insert(plugin.makeKey("dev-1"), deviceInfo);

    QVERIFY(!plugin.hasActiveDeviceSessionLocked(QStringLiteral("dev-1")));
}

void SkfPluginTest::verifyDoesNotTearDownLoggedInSession() {
    SkfPlugin plugin;
    primeActiveSession(plugin);
    primeVerifyLibrary(plugin);

    const QByteArray payload("verify-payload");
    const QByteArray signature(kRsaSigBytes, '\x01');

    auto result = plugin.verify(QStringLiteral("dev-1"), QStringLiteral("app-1"),
                                QStringLiteral("container-1"), payload, signature);

    QVERIFY(result.isOk());
    QVERIFY(result.value());
    QVERIFY(plugin.loginCache_.contains(QStringLiteral("dev-1/app-1")));
    QVERIFY(plugin.handles_.contains(plugin.makeKey("dev-1")));
    QVERIFY(plugin.handles_.contains(plugin.makeKey("dev-1", "app-1")));
}

void SkfPluginTest::parseDerCertificateReturnsUppercaseSerialNumber() {
    SkfPlugin plugin;
    const QByteArray der = makeCertificateDerWithSerial("1f0a6fc5bd5ae72cb6cd5d9b2c63285262f86567");

    auto result = plugin.parseDerCertificate(der);

    QVERIFY(result.isOk());
    QCOMPARE(result.value().serialNumber,
             QStringLiteral("1F0A6FC5BD5AE72CB6CD5D9B2C63285262F86567"));
}

}  // namespace wekey

QTEST_MAIN(wekey::SkfPluginTest)

#include "SkfPluginTest.moc"
