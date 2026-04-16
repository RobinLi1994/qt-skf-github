/**
 * @file AddModuleDialog.cpp
 * @brief 添加模块对话框实现
 *
 * 支持两种驱动加载模式：
 * 1. 使用内置驱动 —— 选择预置模块名称，点击"获取默认路径"自动搜索打包后的库路径
 * 2. 上传自定义文件 —— 用户通过文件选择器选择本地 SKF 驱动库文件
 */

#include "AddModuleDialog.h"

#include <QButtonGroup>
#include <QCoreApplication>
#include <QDir>
#include <QFileDialog>
#include <QFileInfo>
#include <QHBoxLayout>
#include <QLabel>
#include <QSysInfo>
#include <QVBoxLayout>

#include <ElaComboBox.h>
#include <ElaLineEdit.h>
#include <ElaPushButton.h>
#include <ElaRadioButton.h>

#include "gui/UiHelper.h"
#include "log/Logger.h"

namespace wekey {

namespace {

QStringList macBuiltinLibNames(const QString& baseName) {
    QStringList libNames;
    if (baseName == QStringLiteral("gm3000")) {
        // 开发态优先展示当前架构对应的真实库名，便于排查到底用了哪一份驱动。
        // 打包态仍统一查 Frameworks/libgm3000.dylib，因此这里只影响开发目录搜索顺序。
        const QString arch = QSysInfo::currentCpuArchitecture();
        if (arch == QStringLiteral("arm64") || arch == QStringLiteral("aarch64")) {
            libNames << QStringLiteral("libgm3000.1.0_arm64.dylib");
        } else if (arch == QStringLiteral("x86_64") || arch == QStringLiteral("amd64")) {
            libNames << QStringLiteral("libgm3000.1.0_x86.dylib");
        }
    }

    libNames << ("lib" + baseName + ".dylib");
    libNames.removeDuplicates();
    return libNames;
}

}  // namespace

AddModuleDialog::AddModuleDialog(QWidget* parent) : QDialog(parent) {
    setupUi();
    setWindowTitle("添加模块");
    resize(520, 0);
    UiHelper::styleDialog(this);
}

QList<AddModuleDialog::BuiltinDriver> AddModuleDialog::builtinDrivers() const {
    // 内置驱动列表，后续新增内置驱动只需在此处添加
    return {
        {"gm3000", "gm3000"},
    };
}

QString AddModuleDialog::findBuiltinLibPath(const QString& baseName) const {
    QString appDir = QCoreApplication::applicationDirPath();

    QStringList searchPaths;

#ifdef Q_OS_MACOS
    const QString packagedLibName = "lib" + baseName + ".dylib";
    const QStringList developmentLibNames = macBuiltinLibNames(baseName);
    // 打包后的 .app 始终先查固定路径：
    // 不论 arm64 还是 x86_64，包内最终文件名都统一为 Frameworks/libgm3000.dylib。
    searchPaths << appDir + "/../Frameworks/" + packagedLibName;
    // 开发态再按“当前架构专用库 -> 通用库”的顺序回退，保证界面显示更准确。
    for (const auto& libName : developmentLibNames) {
        searchPaths << appDir + "/../../../../../lib/" + libName;
        searchPaths << appDir + "/../../lib/" + libName;
    }
#elif defined(Q_OS_WIN)
    // Windows 下某些驱动可能有 mtoken_ 前缀，优先尝试原始名
    const QString libName = baseName + ".dll";
    // Windows 打包环境: exe 同目录
    searchPaths << appDir + "/" + libName;
    // Windows 下尝试 mtoken_ 前缀
    searchPaths << appDir + "/mtoken_" + baseName + ".dll";
    searchPaths << appDir + "/../../../../../lib/" + libName;
    searchPaths << appDir + "/../../lib/" + libName;
#else
    const QString libName = "lib" + baseName + ".so";
    searchPaths << appDir + "/../../../../../lib/" + libName;
    searchPaths << appDir + "/../../lib/" + libName;
#endif

    for (const auto& candidate : searchPaths) {
        QString absPath = QDir(candidate).absolutePath();
        QFileInfo fi(absPath);
        if (fi.exists() && fi.isFile()) {
            LOG_INFO(QString("找到内置驱动库: %1").arg(absPath));
            return absPath;
        }
        LOG_DEBUG(QString("内置驱动候选路径不存在: %1").arg(absPath));
    }

    return {};
}

void AddModuleDialog::setupUi() {
    auto* mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(24, 24, 24, 24);
    mainLayout->setSpacing(4);

    // ---- 模块名称（必填）----
    mainLayout->addWidget(createRequiredLabel("模块名称"));
    nameCombo_ = new ElaComboBox(this);
    UiHelper::styleComboBox(nameCombo_);
    nameCombo_->setEditable(false);
    // 添加内置驱动名称到下拉框
    auto drivers = builtinDrivers();
    for (const auto& drv : drivers) {
        nameCombo_->addItem(drv.displayName, drv.baseName);
    }
    nameCombo_->setCurrentIndex(-1);  // 初始不选中
    nameCombo_->setPlaceholderText("请选择模块名称");
    connect(nameCombo_, QOverload<int>::of(&ElaComboBox::currentIndexChanged),
            this, &AddModuleDialog::validate);
    mainLayout->addWidget(nameCombo_);
    mainLayout->addSpacing(16);

    // ---- 模块路径类型（必填）----
    mainLayout->addWidget(createRequiredLabel("模块路径类型"));

    auto* radioLayout = new QHBoxLayout;
    radioLayout->setContentsMargins(0, 0, 0, 0);
    radioLayout->setSpacing(16);
    builtinRadio_ = new ElaRadioButton("使用内置驱动", this);
    customRadio_ = new ElaRadioButton("上传自定义文件", this);
    auto* radioGroup = new QButtonGroup(this);
    radioGroup->addButton(builtinRadio_);
    radioGroup->addButton(customRadio_);
    builtinRadio_->setChecked(true);
    radioLayout->addWidget(builtinRadio_);
    radioLayout->addWidget(customRadio_);
    radioLayout->addStretch();
    mainLayout->addLayout(radioLayout);
    mainLayout->addSpacing(16);

    // ---- 内置驱动模式：模块路径 + 获取默认路径链接 ----
    builtinWidget_ = new QWidget(this);
    auto* builtinLayout = new QVBoxLayout(builtinWidget_);
    builtinLayout->setContentsMargins(0, 0, 0, 0);
    builtinLayout->setSpacing(4);

    builtinLayout->addWidget(createRequiredLabel("模块路径"));
    builtinPathEdit_ = new ElaLineEdit(builtinWidget_);
    UiHelper::styleLineEdit(builtinPathEdit_);
    builtinPathEdit_->setPlaceholderText("点击按钮获取默认路径");
    builtinPathEdit_->setReadOnly(true);
    builtinLayout->addWidget(builtinPathEdit_);

    fetchPathLink_ = UiHelper::createActionLink("获取默认路径", builtinWidget_);
    connect(fetchPathLink_, &QLabel::linkActivated,
            this, &AddModuleDialog::onFetchDefaultPath);
    builtinLayout->addWidget(fetchPathLink_);

    mainLayout->addWidget(builtinWidget_);

    // ---- 自定义文件模式：模块文件 + 选择文件链接 ----
    customWidget_ = new QWidget(this);
    auto* customLayout = new QVBoxLayout(customWidget_);
    customLayout->setContentsMargins(0, 0, 0, 0);
    customLayout->setSpacing(4);

    customLayout->addWidget(createRequiredLabel("模块文件"));
    customPathEdit_ = new ElaLineEdit(customWidget_);
    UiHelper::styleLineEdit(customPathEdit_);
    customPathEdit_->setPlaceholderText("请选择模块文件");
    customPathEdit_->setReadOnly(true);
    customLayout->addWidget(customPathEdit_);

    selectFileLink_ = UiHelper::createActionLink("选择文件", customWidget_);
    connect(selectFileLink_, &QLabel::linkActivated,
            this, &AddModuleDialog::onSelectFile);
    customLayout->addWidget(selectFileLink_);

    mainLayout->addWidget(customWidget_);
    customWidget_->setVisible(false);  // 默认隐藏自定义文件区域

    mainLayout->addSpacing(16);

    // ---- 分隔线 ----
    mainLayout->addWidget(UiHelper::createDivider(this));

    // ---- 按钮 ----
    auto* btnLayout = new QHBoxLayout;
    btnLayout->addStretch();
    cancelButton_ = new ElaPushButton("取消", this);
    UiHelper::styleDefaultButton(cancelButton_);
    connect(cancelButton_, &ElaPushButton::clicked, this, &QDialog::reject);
    btnLayout->addWidget(cancelButton_);

    okButton_ = new ElaPushButton("确定", this);
    UiHelper::stylePrimaryButton(okButton_);
    okButton_->setEnabled(false);
    connect(okButton_, &ElaPushButton::clicked, this, &QDialog::accept);
    btnLayout->addWidget(okButton_);
    mainLayout->addLayout(btnLayout);

    // ---- 信号连接 ----
    connect(builtinRadio_, &ElaRadioButton::toggled,
            this, [this](bool checked) {
                if (checked) onBuiltinSelected();
            });
    connect(customRadio_, &ElaRadioButton::toggled,
            this, [this](bool checked) {
                if (checked) onCustomSelected();
            });
}

QLabel* AddModuleDialog::createRequiredLabel(const QString& text) {
    auto* label = new QLabel(this);
    label->setTextFormat(Qt::RichText);
    label->setText(
        QString("<span style='color:#ff4d4f; font-size:14px;'>* </span>"
                "<span style='color:#000000; font-size:14px;'>%1</span>")
            .arg(text));
    return label;
}

void AddModuleDialog::onBuiltinSelected() {
    LOG_DEBUG("切换到内置驱动模式");
    builtinWidget_->setVisible(true);
    customWidget_->setVisible(false);
    // 清空自定义文件路径
    customPathEdit_->clear();
    // 允许下拉框编辑（内置模式下不可编辑，使用预设列表）
    nameCombo_->setEditable(false);
    validate();
}

void AddModuleDialog::onCustomSelected() {
    LOG_DEBUG("切换到自定义文件模式");
    builtinWidget_->setVisible(false);
    customWidget_->setVisible(true);
    // 清空内置路径
    builtinPathEdit_->clear();
    // 自定义模式下允许用户手动输入模块名称
    nameCombo_->setEditable(true);
    validate();
}

void AddModuleDialog::onFetchDefaultPath() {
    if (nameCombo_->currentIndex() < 0) {
        LOG_WARN("请先选择模块名称");
        builtinPathEdit_->setText("");
        builtinPathEdit_->setPlaceholderText("请先选择模块名称");
        return;
    }

    QString baseName = nameCombo_->currentData().toString();
    LOG_INFO(QString("获取内置驱动默认路径: %1").arg(baseName));

    QString path = findBuiltinLibPath(baseName);
    if (path.isEmpty()) {
        LOG_WARN(QString("未找到内置驱动: %1").arg(baseName));
        builtinPathEdit_->setText("");
        builtinPathEdit_->setPlaceholderText("未找到内置驱动文件");
    } else {
        builtinPathEdit_->setText(path);
        LOG_INFO(QString("已获取内置驱动路径: %1").arg(path));
    }
    validate();
}

void AddModuleDialog::onSelectFile() {
    QString filter = "SKF 库文件 (*.dll *.dylib *.so);;所有文件 (*)";
    QString filePath = QFileDialog::getOpenFileName(this, "选择 SKF 库文件", QString(), filter);
    if (filePath.isEmpty()) {
        return;
    }

    customPathEdit_->setText(filePath);
    LOG_INFO(QString("用户选择自定义驱动文件: %1").arg(filePath));

    // 如果用户未输入模块名称，自动从文件名推导
    if (nameCombo_->currentText().trimmed().isEmpty()) {
        QFileInfo fi(filePath);
        QString name = fi.completeBaseName();
        if (name.startsWith("lib")) {
            name = name.mid(3);
        }
        nameCombo_->setEditText(name);
        LOG_DEBUG(QString("自动推导模块名称: %1").arg(name));
    }

    validate();
}

void AddModuleDialog::validate() {
    bool nameValid = !nameCombo_->currentText().trimmed().isEmpty();
    bool pathValid = false;

    if (builtinRadio_->isChecked()) {
        pathValid = !builtinPathEdit_->text().trimmed().isEmpty();
    } else {
        pathValid = !customPathEdit_->text().trimmed().isEmpty();
    }

    okButton_->setEnabled(nameValid && pathValid);
}

QString AddModuleDialog::moduleName() const {
    return nameCombo_->currentText().trimmed();
}

QString AddModuleDialog::modulePath() const {
    if (builtinRadio_->isChecked()) {
        return builtinPathEdit_->text().trimmed();
    }
    return customPathEdit_->text().trimmed();
}

}  // namespace wekey
