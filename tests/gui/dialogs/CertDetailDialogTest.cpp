#include <QtTest>

#include <QAbstractButton>
#include <QTextEdit>

#include "gui/dialogs/CertDetailDialog.h"
#include "plugin/PluginManager.h"
#include "support/FakeDriverPlugin.h"

namespace wekey {

class CertDetailDialogTest : public QObject {
    Q_OBJECT

private slots:
    void cleanup() {
        auto& pluginManager = PluginManager::instance();
        const QString pluginName = QStringLiteral("cert-detail-dialog-test-plugin");
        if (pluginManager.activePluginName() == pluginName) {
            pluginManager.unregisterPlugin(pluginName, false);
        } else if (pluginManager.getPlugin(pluginName)) {
            pluginManager.unregisterPlugin(pluginName, false);
        }
    }

    void copiesCertificatePemFromButtonAndContentArea() {
        const QString pem = QStringLiteral(
            "-----BEGIN CERTIFICATE-----\n"
            "MIIBTEST\n"
            "-----END CERTIFICATE-----\n");

        CertInfo cert;
        cert.cert = pem;
        cert.commonName = QStringLiteral("11122");
        cert.serialNumber = QStringLiteral("1f0a");

        const QString pluginName = QStringLiteral("cert-detail-dialog-test-plugin");
        auto plugin = std::make_shared<test::FakeDriverPlugin>();
        plugin->certInfoResult = Result<CertInfo>::ok(cert);

        auto& pluginManager = PluginManager::instance();
        QVERIFY(pluginManager.registerPluginInstance(pluginName, plugin).isOk());
        QVERIFY(pluginManager.setActivePlugin(pluginName, false).isOk());

        CertDetailDialog dialog("dev-1", "app-1", "container-1");

        auto* pemEdit = dialog.findChild<QTextEdit*>("certPemEdit");
        auto* copyButton = dialog.findChild<QAbstractButton*>("copyCertButton");
        QVERIFY(pemEdit != nullptr);
        QVERIFY(copyButton != nullptr);
        QCOMPARE(copyButton->parentWidget(), pemEdit->viewport());
        QVERIFY(!copyButton->isHidden());

        copyButton->click();
        QCOMPARE(pemEdit->property("lastCopiedText").toString(), pem);
        QVERIFY(pemEdit->property("copyMessageShown").toBool());

        pemEdit->setProperty("lastCopiedText", QString());
        pemEdit->setProperty("copyMessageShown", false);
        QTest::mouseClick(pemEdit->viewport(), Qt::LeftButton);
        QCOMPARE(pemEdit->property("lastCopiedText").toString(), pem);
        QVERIFY(pemEdit->property("copyMessageShown").toBool());
    }
};

}  // namespace wekey

QTEST_MAIN(wekey::CertDetailDialogTest)

#include "CertDetailDialogTest.moc"
