#pragma once

#include <QMap>
#include <QStringList>

#include "common/Error.h"
#include "plugin/interface/IDriverPlugin.h"

namespace wekey::test {

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

    Result<void> importKeyCert(const QString&, const QString&, const QString&, const QByteArray&,
                               const QByteArray&, const QByteArray&, bool) override {
        return Result<void>::err(
            Error(Error::Fail, "not implemented", "FakeDriverPlugin::importKeyCert"));
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
        return Result<QByteArray>::err(
            Error(Error::Fail, "not implemented", "FakeDriverPlugin::sign"));
    }

    Result<bool> verify(const QString&, const QString&, const QString&, const QByteArray&,
                        const QByteArray&) override {
        return Result<bool>::err(
            Error(Error::Fail, "not implemented", "FakeDriverPlugin::verify"));
    }

    Result<QStringList> enumFiles(const QString&, const QString&) override {
        return Result<QStringList>::ok(files);
    }

    Result<QByteArray> readFile(const QString&, const QString&, const QString& fileName) override {
        return Result<QByteArray>::ok(fileContents.value(fileName));
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

    Result<EncDecTestResult> rsaEncDecTest(const QString&, const QString&, const QString&, bool,
                                           const QString&) override {
        return Result<EncDecTestResult>::err(
            Error(Error::Fail, "not implemented", "FakeDriverPlugin::rsaEncDecTest"));
    }

    Result<EncDecTestResult> sm2EncDecTest(const QString&, const QString&, const QString&,
                                           const QString&) override {
        return Result<EncDecTestResult>::err(
            Error(Error::Fail, "not implemented", "FakeDriverPlugin::sm2EncDecTest"));
    }

    Result<QString> rsaEncrypt(const QString&, const QString&, const QString&, bool,
                               const QString&) override {
        return Result<QString>::err(
            Error(Error::Fail, "not implemented", "FakeDriverPlugin::rsaEncrypt"));
    }

    Result<QString> rsaDecrypt(const QString&, const QString&, const QString&, bool,
                               const QString&) override {
        return Result<QString>::err(
            Error(Error::Fail, "not implemented", "FakeDriverPlugin::rsaDecrypt"));
    }

    Result<QString> sm2Encrypt(const QString&, const QString&, const QString&,
                               const QString& plainText) override {
        sm2EncryptCalled = true;
        lastPlainText = plainText;
        return sm2EncryptResult;
    }

    Result<QString> sm2Decrypt(const QString&, const QString&, const QString&,
                               const QString& encryptedData) override {
        sm2DecryptCalled = true;
        lastEncryptedData = encryptedData;
        return sm2DecryptResult;
    }

    QList<ContainerInfo> containers;
    QStringList files;
    QMap<QString, QByteArray> fileContents;
    bool sm2EncryptCalled = false;
    bool sm2DecryptCalled = false;
    QString lastPlainText;
    QString lastEncryptedData;
    Result<QString> sm2EncryptResult = Result<QString>::ok(QStringLiteral("sm2-cipher"));
    Result<QString> sm2DecryptResult = Result<QString>::ok(QStringLiteral("sm2-plain"));
};

}  // namespace wekey::test
