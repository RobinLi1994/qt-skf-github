#include <QtTest>

#include <QHBoxLayout>
#include <QLabel>
#include <QTableWidget>

#include "gui/views/AppDetailView.h"
#include "plugin/PluginManager.h"
#include "support/FakeDriverPlugin.h"

namespace wekey {

namespace {

constexpr auto kPluginName = "app-detail-view-test-plugin";

QLabel* findActionLabel(QWidget* actionWidget, const QString& text) {
    const auto labels = actionWidget->findChildren<QLabel*>();
    for (QLabel* label : labels) {
        if (label->text().contains(text)) {
            return label;
        }
    }
    return nullptr;
}

QTableWidget* findContainerTable(AppDetailView& view) {
    const auto tables = view.findChildren<QTableWidget*>();
    for (QTableWidget* table : tables) {
        if (table->columnCount() == 5) {
            return table;
        }
    }
    return nullptr;
}

}  // namespace

class AppDetailViewTest : public QObject {
    Q_OBJECT

private slots:
    void cleanup() {
        auto& pluginManager = PluginManager::instance();
        if (pluginManager.activePluginName() == QString::fromLatin1(kPluginName)) {
            pluginManager.unregisterPlugin(QString::fromLatin1(kPluginName), false);
        } else if (pluginManager.getPlugin(QString::fromLatin1(kPluginName))) {
            pluginManager.unregisterPlugin(QString::fromLatin1(kPluginName), false);
        }
    }

    void sm2WithoutEncryptKey_disablesEncDecEntry() {
        auto plugin = std::make_shared<test::FakeDriverPlugin>();
        ContainerInfo container;
        container.containerName = QStringLiteral("sm2-sign-only");
        container.keyGenerated = true;
        container.keyType = ContainerInfo::KeyType::SM2;
        container.signKeyAvailable = true;
        container.encKeyAvailable = false;
        plugin->containers = {container};

        auto& pluginManager = PluginManager::instance();
        QVERIFY(pluginManager.registerPluginInstance(QString::fromLatin1(kPluginName), plugin).isOk());
        QVERIFY(pluginManager.setActivePlugin(QString::fromLatin1(kPluginName), false).isOk());

        AppDetailView view;
        view.setContext(QStringLiteral("dev-1"), QStringLiteral("app-1"));

        auto* table = findContainerTable(view);
        QVERIFY(table != nullptr);
        QCOMPARE(table->rowCount(), 1);

        QWidget* actionWidget = table->cellWidget(0, 4);
        QVERIFY(actionWidget != nullptr);

        QLabel* encDecLabel = findActionLabel(actionWidget, QStringLiteral("加密测试"));
        QVERIFY(encDecLabel != nullptr);
        QVERIFY(!encDecLabel->isEnabled());
    }

    void rsaWithOnlySignKey_keepsEncDecEntryEnabled() {
        auto plugin = std::make_shared<test::FakeDriverPlugin>();
        ContainerInfo container;
        container.containerName = QStringLiteral("rsa-sign-only");
        container.keyGenerated = true;
        container.keyType = ContainerInfo::KeyType::RSA;
        container.signKeyAvailable = true;
        container.encKeyAvailable = false;
        plugin->containers = {container};

        auto& pluginManager = PluginManager::instance();
        QVERIFY(pluginManager.registerPluginInstance(QString::fromLatin1(kPluginName), plugin).isOk());
        QVERIFY(pluginManager.setActivePlugin(QString::fromLatin1(kPluginName), false).isOk());

        AppDetailView view;
        view.setContext(QStringLiteral("dev-1"), QStringLiteral("app-1"));

        auto* table = findContainerTable(view);
        QVERIFY(table != nullptr);
        QCOMPARE(table->rowCount(), 1);

        QWidget* actionWidget = table->cellWidget(0, 4);
        QVERIFY(actionWidget != nullptr);

        QLabel* encDecLabel = findActionLabel(actionWidget, QStringLiteral("加密测试"));
        QVERIFY(encDecLabel != nullptr);
        QVERIFY(encDecLabel->isEnabled());
    }
};

}  // namespace wekey

QTEST_MAIN(wekey::AppDetailViewTest)

#include "AppDetailViewTest.moc"
