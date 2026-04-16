#include <QtTest>

#include <ElaComboBox.h>
#include <ElaPlainTextEdit.h>
#include <ElaPushButton.h>

#include "gui/dialogs/EncDecTestDialog.h"
#include "plugin/PluginManager.h"
#include "support/FakeDriverPlugin.h"

namespace wekey {

class EncDecTestDialogTest : public QObject {
    Q_OBJECT

private slots:
    void cleanup() {
        auto& pluginManager = PluginManager::instance();
        const QString pluginName = QStringLiteral("enc-dec-dialog-test-plugin");
        if (pluginManager.activePluginName() == pluginName) {
            pluginManager.unregisterPlugin(pluginName, false);
        } else if (pluginManager.getPlugin(pluginName)) {
            pluginManager.unregisterPlugin(pluginName, false);
        }
    }

    void showsSeparateEncryptAndDecryptButtons() {
        EncDecTestDialog dialog("dev-1", "app-1", "container-1",
                                ContainerInfo::KeyType::RSA);

        auto* encryptButton = dialog.findChild<ElaPushButton*>("encryptButton");
        auto* decryptButton = dialog.findChild<ElaPushButton*>("decryptButton");
        auto* plainTextEdit = dialog.findChild<ElaPlainTextEdit*>("plainTextEdit");
        auto* encryptedEdit = dialog.findChild<ElaPlainTextEdit*>("encryptedEdit");

        QVERIFY(encryptButton != nullptr);
        QVERIFY(decryptButton != nullptr);
        QVERIFY(plainTextEdit != nullptr);
        QVERIFY(encryptedEdit != nullptr);
        QCOMPARE(encryptButton->text(), QString("开始加密"));
        QCOMPARE(decryptButton->text(), QString("解密"));
        QVERIFY(!encryptButton->isEnabled());
        QVERIFY(!decryptButton->isEnabled());
        QVERIFY(!encryptedEdit->isReadOnly());
    }

    void encryptFailureClearsPreviousCiphertext() {
        const QString pluginName = QStringLiteral("enc-dec-dialog-test-plugin");
        auto plugin = std::make_shared<test::FakeDriverPlugin>();
        auto& pluginManager = PluginManager::instance();
        QVERIFY(pluginManager.registerPluginInstance(pluginName, plugin).isOk());
        QVERIFY(pluginManager.setActivePlugin(pluginName, false).isOk());

        EncDecTestDialog dialog("dev-1", "app-1", "container-1",
                                ContainerInfo::KeyType::SM2);

        auto* encryptButton = dialog.findChild<ElaPushButton*>("encryptButton");
        auto* decryptButton = dialog.findChild<ElaPushButton*>("decryptButton");
        auto* plainTextEdit = dialog.findChild<ElaPlainTextEdit*>("plainTextEdit");
        auto* encryptedEdit = dialog.findChild<ElaPlainTextEdit*>("encryptedEdit");

        QVERIFY(encryptButton != nullptr);
        QVERIFY(decryptButton != nullptr);
        QVERIFY(plainTextEdit != nullptr);
        QVERIFY(encryptedEdit != nullptr);

        plugin->sm2EncryptResult = Result<QString>::ok(QStringLiteral("Y2lwaGVyLTE="));
        plainTextEdit->setPlainText(QStringLiteral("first"));
        encryptButton->click();

        QCOMPARE(encryptedEdit->toPlainText(), QStringLiteral("Y2lwaGVyLTE="));
        QVERIFY(decryptButton->isEnabled());

        plugin->sm2EncryptResult = Result<QString>::err(
            Error(Error::Fail, "encrypt failed", "FakeDriverPlugin::sm2Encrypt"));
        plainTextEdit->setPlainText(QStringLiteral("second"));
        encryptButton->click();

        QVERIFY(encryptedEdit->toPlainText().isEmpty());
        QVERIFY(!decryptButton->isEnabled());
    }

    void rsaWithoutEncKey_hidesEncryptKeyOption() {
        ContainerInfo container;
        container.containerName = QStringLiteral("rsa-sign-only");
        container.keyType = ContainerInfo::KeyType::RSA;
        container.keyGenerated = true;
        container.signKeyAvailable = true;
        container.encKeyAvailable = false;

        EncDecTestDialog dialog("dev-1", "app-1", container.containerName, container, nullptr);

        auto* keyCombo = dialog.findChild<ElaComboBox*>();
        QVERIFY(keyCombo != nullptr);
        QCOMPARE(keyCombo->count(), 1);
        QCOMPARE(keyCombo->itemText(0), QStringLiteral("签名密钥"));
    }
};

}  // namespace wekey

QTEST_MAIN(wekey::EncDecTestDialogTest)

#include "EncDecTestDialogTest.moc"
