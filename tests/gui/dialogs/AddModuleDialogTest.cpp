#include <QtTest>

#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QMetaObject>
#include <QSysInfo>

#include <ElaComboBox.h>

#include "gui/dialogs/AddModuleDialog.h"

namespace wekey {

namespace {

QString repoLibDir() {
    return QDir(QCoreApplication::applicationDirPath()).absoluteFilePath("../../lib");
}

QString packagedFrameworksDir() {
    return QDir(QCoreApplication::applicationDirPath()).absoluteFilePath("../Frameworks");
}

QString currentArchBuiltinLibName() {
    const QString arch = QSysInfo::currentCpuArchitecture();
    if (arch == QStringLiteral("arm64") || arch == QStringLiteral("aarch64")) {
        return QStringLiteral("libgm3000.1.0_arm64.dylib");
    }
    return QStringLiteral("libgm3000.1.0_x86.dylib");
}

QString ensureFile(const QString& dirPath, const QString& fileName) {
    QDir dir(dirPath);
    if (!dir.exists()) {
        dir.mkpath(QStringLiteral("."));
    }

    const QString filePath = dir.filePath(fileName);
    QFile file(filePath);
    if (!file.open(QIODevice::WriteOnly)) {
        return {};
    }
    file.write("test");
    file.close();
    return QFileInfo(filePath).absoluteFilePath();
}

void removeIfExists(const QString& filePath) {
    QFile::remove(filePath);
}

}  // namespace

class AddModuleDialogTest : public QObject {
    Q_OBJECT

private slots:
    void init() {
        cleanupArtifacts();
    }

    void cleanup() {
        cleanupArtifacts();
    }

    void developmentPath_prefersCurrentArchitectureLibrary() {
#ifndef Q_OS_MACOS
        QSKIP("macOS-specific built-in path logic");
#endif
        // 开发目录同时存在真实架构库和统一名称时，界面应优先展示真实架构库。
        const QString expectedPath =
            ensureFile(repoLibDir(), currentArchBuiltinLibName());
        QVERIFY(!expectedPath.isEmpty());
        ensureFile(repoLibDir(), QStringLiteral("libgm3000.dylib"));

        AddModuleDialog dialog;
        auto* combo = dialog.findChild<ElaComboBox*>();
        QVERIFY(combo != nullptr);
        combo->setCurrentIndex(0);

        QVERIFY(QMetaObject::invokeMethod(&dialog, "onFetchDefaultPath"));
        QCOMPARE(dialog.modulePath(), expectedPath);
    }

    void packagedPath_keepsFrameworksLookupFirst() {
#ifndef Q_OS_MACOS
        QSKIP("macOS-specific built-in path logic");
#endif
        // 打包后的 .app 始终按统一包内路径查找，不暴露源文件名差异给用户。
        const QString expectedPath =
            ensureFile(packagedFrameworksDir(), QStringLiteral("libgm3000.dylib"));
        QVERIFY(!expectedPath.isEmpty());
        ensureFile(repoLibDir(), currentArchBuiltinLibName());

        AddModuleDialog dialog;
        auto* combo = dialog.findChild<ElaComboBox*>();
        QVERIFY(combo != nullptr);
        combo->setCurrentIndex(0);

        QVERIFY(QMetaObject::invokeMethod(&dialog, "onFetchDefaultPath"));
        QCOMPARE(dialog.modulePath(), expectedPath);
    }

private:
    void cleanupArtifacts() {
        removeIfExists(QDir(repoLibDir()).filePath(QStringLiteral("libgm3000.1.0_arm64.dylib")));
        removeIfExists(QDir(repoLibDir()).filePath(QStringLiteral("libgm3000.1.0_x86.dylib")));
        removeIfExists(QDir(repoLibDir()).filePath(QStringLiteral("libgm3000.dylib")));
        removeIfExists(QDir(packagedFrameworksDir()).filePath(QStringLiteral("libgm3000.dylib")));
    }
};

}  // namespace wekey

QTEST_MAIN(wekey::AddModuleDialogTest)

#include "AddModuleDialogTest.moc"
