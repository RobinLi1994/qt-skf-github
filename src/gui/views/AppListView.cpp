/**
 * @file AppListView.cpp
 * @brief 应用列表子视图实现
 */

#include "AppListView.h"

#include <QButtonGroup>
#include <QDialog>
#include <QEvent>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QMouseEvent>
#include <QHeaderView>
#include <QRegularExpression>
#include <QVBoxLayout>

#include <ElaContentDialog.h>
#include <ElaIcon.h>
#include <ElaLineEdit.h>
#include <ElaPushButton.h>
#include <ElaRadioButton.h>
#include <ElaText.h>

#include "gui/UiHelper.h"
#include "config/Config.h"
#include "core/application/AppService.h"
#include "gui/dialogs/CreateAppDialog.h"
#include "gui/dialogs/LoginDialog.h"
#include "gui/dialogs/MessageBox.h"

namespace wekey {

AppListView::AppListView(QWidget* parent) : QWidget(parent) {
    setupUi();
    connectSignals();
}

void AppListView::setDevice(const QString& devName) {
    devName_ = devName;
    titleText_->setText(QString("设备 %1 的应用列表").arg(devName_));
    refreshApps();
}

void AppListView::setupUi() {
    auto* mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(0, 0, 0, 0);
    mainLayout->setSpacing(UiHelper::kSpaceMD);

    // 标题栏：返回箭头 + 标题
    auto* headerLayout = new QHBoxLayout;
    headerLayout->setSpacing(UiHelper::kSpaceSM);
    backButton_ = new QLabel("←", this);
    backButton_->setCursor(Qt::PointingHandCursor);
    backButton_->setStyleSheet(
        "QLabel { color: #000000; font-size: 20px; }"
        "QLabel:hover { color: #1677ff; }"
    );
    backButton_->installEventFilter(this);
    headerLayout->addWidget(backButton_);
    titleText_ = new ElaText("应用列表", this);
    titleText_->setTextPixelSize(20);
    headerLayout->addWidget(titleText_);
    headerLayout->addStretch();
    mainLayout->addLayout(headerLayout);

    // 操作栏：创建 + 刷新
    auto* actionLayout = new QHBoxLayout;
    createButton_ = new ElaPushButton("创建应用", this);
    UiHelper::stylePrimaryButton(createButton_);
    actionLayout->addWidget(createButton_);
    refreshButton_ = new ElaPushButton("刷新", this);
    UiHelper::styleDefaultButton(refreshButton_);
    actionLayout->addWidget(refreshButton_);
    actionLayout->addStretch();
    mainLayout->addLayout(actionLayout);

    // 应用表格（4列：应用名称、登录状态、PIN状态、操作）
    table_ = new QTableWidget(0, 4, this);
    table_->setHorizontalHeaderLabels({"应用名称", "登录状态", "PIN 状态", "操作"});
    table_->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
    table_->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Fixed);
    table_->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Fixed);
    table_->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Fixed);
    table_->horizontalHeader()->resizeSection(3, 400);
    UiHelper::styleTable(table_);

    // 空状态 + 表格用 QStackedWidget 切换（index 0=表格，index 1=空状态）
    tableStack_ = new QStackedWidget(this);
    tableStack_->addWidget(table_);
    tableStack_->addWidget(UiHelper::createEmptyState(
        ElaIconType::Folder, "暂无应用，请点击「创建应用」", this));
    mainLayout->addWidget(tableStack_, 1);
}

void AppListView::connectSignals() {
    // backButton_ 是 QLabel，点击通过 eventFilter 处理
    connect(createButton_, &ElaPushButton::clicked, this, &AppListView::onCreateApp);
    connect(refreshButton_, &ElaPushButton::clicked, this, &AppListView::refreshApps);
}

void AppListView::refreshApps() {
    if (refreshing_ || devName_.isEmpty()) return;
    refreshing_ = true;

    table_->setRowCount(0);

    auto result = AppService::instance().enumApps(devName_);
    if (!result.isOk()) {
        refreshing_ = false;
        MessageBox::error(this, "枚举应用失败", result.error());
        return;
    }

    for (const auto& app : result.value()) {
        int row = table_->rowCount();
        table_->insertRow(row);

        table_->setItem(row, 0, new QTableWidgetItem(app.appName));
        // 登录状态 Tag
        auto* statusTag = app.isLoggedIn
            ? UiHelper::createSuccessTag("已登录")
            : UiHelper::createDefaultTag("未登录");
        table_->setCellWidget(row, 1, statusTag);

        // PIN 状态列：通过 getPinInfo 获取用户 PIN 信息
        bool userPinLocked = false;
        auto pinResult = AppService::instance().getPinInfo(devName_, app.appName, "user");
        if (pinResult.isOk()) {
            const auto& pinInfo = pinResult.value();
            userPinLocked = pinInfo.isLocked();
            if (userPinLocked) {
                table_->setCellWidget(row, 2, UiHelper::createWarningTag(
                    QString("已锁定")));
            } else {
                table_->setCellWidget(row, 2, UiHelper::createSuccessTag(
                    QString("正常")));
            }
        } else {
            // getPinInfo 不可用时显示未知状态
            table_->setCellWidget(row, 2, UiHelper::createDefaultTag("未知"));
        }

        // 操作链接（纯文字带颜色，无按钮边框）
        auto* actionWidget = new QWidget();
        auto* actionLayout = new QHBoxLayout(actionWidget);
        actionLayout->setContentsMargins(4, 2, 4, 2);
        actionLayout->setSpacing(16);

        if (!app.isLoggedIn) {
            auto* loginLink = UiHelper::createActionLink(ElaIconType::RightToBracket, "登录");
            connect(loginLink, &QLabel::linkActivated, this,
                    [this, a = app.appName]() { onLogin(a); });
            actionLayout->addWidget(loginLink);
        } else {
            auto* logoutLink = UiHelper::createActionLink(ElaIconType::RightFromBracket, "登出");
            connect(logoutLink, &QLabel::linkActivated, this,
                    [this, a = app.appName]() { onLogout(a); });
            actionLayout->addWidget(logoutLink);
        }

        auto* changePinLink = UiHelper::createActionLink(ElaIconType::PenToSquare, "编辑 PIN");
        connect(changePinLink, &QLabel::linkActivated, this,
                [this, a = app.appName]() { onChangePin(a); });
        actionLayout->addWidget(changePinLink);

        // 解锁 PIN：仅用户 PIN 锁定时显示
        if (userPinLocked) {
            auto* unlockLink = UiHelper::createActionLink(ElaIconType::UnlockKeyhole, "解锁");
            connect(unlockLink, &QLabel::linkActivated, this,
                    [this, a = app.appName]() { onUnlockPin(a); });
            actionLayout->addWidget(unlockLink);
        }

        // 详情：未登录时灰色不可点击
        if (app.isLoggedIn) {
            auto* detailLink = UiHelper::createActionLink(ElaIconType::FileLines, "详情");
            connect(detailLink, &QLabel::linkActivated, this,
                    [this, a = app.appName]() { emit detailRequested(devName_, a); });
            actionLayout->addWidget(detailLink);
        } else {
            auto* detailLink = UiHelper::createDisabledLink(ElaIconType::FileLines, "详情");
            actionLayout->addWidget(detailLink);
        }

        auto* deleteLink = UiHelper::createDangerLink(ElaIconType::TrashCan, "删除");
        connect(deleteLink, &QLabel::linkActivated, this,
                [this, a = app.appName]() { onDeleteApp(a); });
        actionLayout->addWidget(deleteLink);

        actionLayout->addStretch();
        table_->setCellWidget(row, 3, actionWidget);
    }

    tableStack_->setCurrentIndex(table_->rowCount() == 0 ? 1 : 0);
    refreshing_ = false;
}

void AppListView::onCreateApp() {
    if (devName_.isEmpty()) {
        MessageBox::error(this, "创建应用失败", "未选择设备");
        return;
    }

    // 默认应用名：仅在列表中不存在时才预填
    QString defaultName;
    const QString cfgDefault = Config::instance().defaultAppName();
    if (!cfgDefault.isEmpty()) {
        auto appsResult = AppService::instance().enumApps(devName_);
        bool exists = false;
        if (appsResult.isOk()) {
            for (const auto& app : appsResult.value()) {
                if (app.appName == cfgDefault) {
                    exists = true;
                    break;
                }
            }
        }
        if (!exists) {
            defaultName = cfgDefault;
        }
    }

    CreateAppDialog dialog(defaultName, this);
    if (dialog.exec() != QDialog::Accepted) {
        return;
    }

    QString appName = dialog.appName();
    QVariantMap args = dialog.toArgs();
    qDebug() << "[AppListView] 创建应用:" << appName << "args:" << args;

    auto result = AppService::instance().createApp(devName_, appName, args);
    if (!result.isOk()) {
        MessageBox::error(this, "创建应用失败", result.error());
    } else {
        refreshApps();
    }
}

void AppListView::onDeleteApp(const QString& appName) {
    MessageBox::confirm(this, "删除提示",
                        QString("确定要删除应用 %1 吗？此操作不可恢复！").arg(appName),
                        [this, appName]() {
                            auto result = AppService::instance().deleteApp(devName_, appName);
                            if (!result.isOk()) {
                                MessageBox::error(this, "删除应用失败", result.error());
                            } else {
                                refreshApps();
                            }
                        });
}

void AppListView::onLogin(const QString& appName) {
    LoginDialog dialog(this);
    dialog.setWindowTitle(QString("登录应用 %1").arg(appName));

    if (dialog.exec() != QDialog::Accepted) {
        return;
    }

    QString selectedRole = dialog.role();
    QString inputPin = dialog.pin();
    qDebug() << "[onLogin] 尝试登录, app:" << appName << "role:" << selectedRole;

    auto result = AppService::instance().login(devName_, appName, selectedRole, inputPin);
    if (result.isOk()) {
        qDebug() << "[onLogin] 登录成功";
        refreshApps();
        return;
    }
    MessageBox::error(this, "登录失败", result.error());
}

void AppListView::onLogout(const QString& appName) {
    auto result = AppService::instance().logout(devName_, appName);
    if (!result.isOk()) {
        MessageBox::error(this, "登出失败", result.error());
    } else {
        refreshApps();
    }
}

void AppListView::onChangePin(const QString& appName) {
    auto* dialog = new QDialog(this);
    dialog->setWindowTitle(QString("编辑应用 %1 的PIN码").arg(appName));
    dialog->resize(440, 0);
    UiHelper::styleDialog(dialog);

    auto* mainLayout = new QVBoxLayout(dialog);
    mainLayout->setContentsMargins(24, 24, 24, 24);
    mainLayout->setSpacing(4);

    // 辅助：创建必填标签
    auto makeRequired = [&](const QString& text) {
        auto* lbl = new QLabel(dialog);
        lbl->setTextFormat(Qt::RichText);
        lbl->setText(
            QString("<span style='color:#ff4d4f; font-size:14px;'>* </span>"
                    "<span style='color:#000000; font-size:14px;'>%1</span>").arg(text));
        return lbl;
    };
    // 辅助：创建红色错误提示标签（初始隐藏）
    auto makeHint = [&](const QString& text) {
        auto* lbl = new QLabel(text, dialog);
        lbl->setStyleSheet("color: #ff4d4f; font-size: 12px;");
        lbl->setVisible(false);
        return lbl;
    };

    // ---- 角色选择 ----
    mainLayout->addWidget(makeRequired("角色"));
    auto* roleLayout = new QHBoxLayout;
    roleLayout->setContentsMargins(0, 0, 0, 0);
    roleLayout->setSpacing(16);
    auto* adminRadio = new ElaRadioButton("管理员", dialog);
    auto* userRadio  = new ElaRadioButton("用户", dialog);
    auto* roleGroup  = new QButtonGroup(dialog);
    roleGroup->addButton(adminRadio);
    roleGroup->addButton(userRadio);
    userRadio->setChecked(true);
    roleLayout->addWidget(adminRadio);
    roleLayout->addWidget(userRadio);
    roleLayout->addStretch();
    mainLayout->addLayout(roleLayout);
    mainLayout->addSpacing(12);

    // ---- 原PIN码 ----
    mainLayout->addWidget(makeRequired("原PIN码"));
    auto* oldPinEdit = new ElaLineEdit(dialog);
    UiHelper::styleLineEdit(oldPinEdit);
    oldPinEdit->setEchoMode(QLineEdit::Password);
    UiHelper::addPasswordToggle(oldPinEdit);
    oldPinEdit->setPlaceholderText("请输入原PIN码");
    mainLayout->addWidget(oldPinEdit);
    mainLayout->addSpacing(12);

    // ---- 新PIN码 ----
    mainLayout->addWidget(makeRequired("新PIN码"));
    auto* newPinEdit = new ElaLineEdit(dialog);
    UiHelper::styleLineEdit(newPinEdit);
    newPinEdit->setEchoMode(QLineEdit::Password);
    UiHelper::addPasswordToggle(newPinEdit);
    newPinEdit->setPlaceholderText("至少8位，含大小写字母、数字、特殊字符");
    mainLayout->addWidget(newPinEdit);

    // 强度提示（四项）
    auto* strengthHint = makeHint("");
    mainLayout->addWidget(strengthHint);
    mainLayout->addSpacing(8);

    // ---- 确认新PIN码 ----
    mainLayout->addWidget(makeRequired("确认新PIN码"));
    auto* confirmPinEdit = new ElaLineEdit(dialog);
    UiHelper::styleLineEdit(confirmPinEdit);
    confirmPinEdit->setEchoMode(QLineEdit::Password);
    UiHelper::addPasswordToggle(confirmPinEdit);
    confirmPinEdit->setPlaceholderText("请再次输入新PIN码");
    mainLayout->addWidget(confirmPinEdit);

    auto* confirmHint = makeHint("两次输入的PIN码不一致");
    mainLayout->addWidget(confirmHint);
    mainLayout->addSpacing(16);

    // ---- 分隔线 ----
    mainLayout->addWidget(UiHelper::createDivider(dialog));

    // ---- 按钮 ----
    auto* btnLayout = new QHBoxLayout;
    btnLayout->addStretch();
    auto* cancelBtn = new ElaPushButton("取消", dialog);
    UiHelper::styleDefaultButton(cancelBtn);
    connect(cancelBtn, &ElaPushButton::clicked, dialog, &QDialog::reject);
    btnLayout->addWidget(cancelBtn);
    auto* okBtn = new ElaPushButton("确定", dialog);
    UiHelper::stylePrimaryButton(okBtn);
    okBtn->setEnabled(false);
    connect(okBtn, &ElaPushButton::clicked, dialog, &QDialog::accept);
    btnLayout->addWidget(okBtn);
    mainLayout->addLayout(btnLayout);

    // ---- 实时校验 ----
    auto validateInputs = [=]() {
        const QString newPin     = newPinEdit->text();
        const QString confirmPin = confirmPinEdit->text();

        // 密码强度检查
        bool hasUpper   = newPin.contains(QRegularExpression("[A-Z]"));
        bool hasLower   = newPin.contains(QRegularExpression("[a-z]"));
        bool hasDigit   = newPin.contains(QRegularExpression("[0-9]"));
        bool hasSpecial = newPin.contains(QRegularExpression("[^A-Za-z0-9]"));
        bool longEnough = newPin.length() >= 8;

        QStringList missing;
        if (!longEnough) missing << "至少8位";
        if (!hasUpper)   missing << "大写字母";
        if (!hasLower)   missing << "小写字母";
        if (!hasDigit)   missing << "数字";
        if (!hasSpecial) missing << "特殊字符";

        bool strengthOk = missing.isEmpty();
        if (!newPin.isEmpty() && !strengthOk) {
            strengthHint->setText("缺少：" + missing.join("、"));
            strengthHint->setVisible(true);
        } else {
            strengthHint->setVisible(false);
        }

        // 确认码一致性检查
        confirmHint->setVisible(!confirmPin.isEmpty() && newPin != confirmPin);

        bool valid = !oldPinEdit->text().isEmpty()
                  && strengthOk
                  && !confirmPin.isEmpty()
                  && newPin == confirmPin;
        okBtn->setEnabled(valid);
    };

    connect(oldPinEdit,    &ElaLineEdit::textChanged, dialog, validateInputs);
    connect(newPinEdit,    &ElaLineEdit::textChanged, dialog, validateInputs);
    connect(confirmPinEdit, &ElaLineEdit::textChanged, dialog, validateInputs);

    if (dialog->exec() != QDialog::Accepted) {
        dialog->deleteLater();
        return;
    }

    QString role   = adminRadio->isChecked() ? "admin" : "user";
    QString oldPin = oldPinEdit->text();
    QString newPin = newPinEdit->text();
    dialog->deleteLater();

    auto result = AppService::instance().changePin(devName_, appName, role, oldPin, newPin);
    if (!result.isOk()) {
        MessageBox::error(this, "修改 PIN 失败", result.error());
    } else {
        MessageBox::info(this, "成功", "PIN 已修改");
    }
}

void AppListView::onUnlockPin(const QString& appName) {
    auto* dialog = new QDialog(this);
    dialog->setWindowTitle(QString("解锁应用 %1 的用户 PIN").arg(appName));
    dialog->resize(440, 0);
    UiHelper::styleDialog(dialog);

    auto* mainLayout = new QVBoxLayout(dialog);
    mainLayout->setContentsMargins(24, 24, 24, 24);
    mainLayout->setSpacing(4);

    // 辅助：创建必填标签
    auto makeRequired = [&](const QString& text) {
        auto* lbl = new QLabel(dialog);
        lbl->setTextFormat(Qt::RichText);
        lbl->setText(
            QString("<span style='color:#ff4d4f; font-size:14px;'>* </span>"
                    "<span style='color:#000000; font-size:14px;'>%1</span>").arg(text));
        return lbl;
    };
    // 辅助：创建红色错误提示标签（初始隐藏）
    auto makeHint = [&](const QString& text) {
        auto* lbl = new QLabel(text, dialog);
        lbl->setStyleSheet("color: #ff4d4f; font-size: 12px;");
        lbl->setVisible(false);
        return lbl;
    };

    // 提示信息
    auto* tipLabel = new QLabel(
        "用户 PIN 已锁定，需要使用管理员 PIN 进行解锁并重置用户 PIN。", dialog);
    tipLabel->setStyleSheet("color: #faad14; font-size: 13px; padding: 8px 0;");
    tipLabel->setWordWrap(true);
    mainLayout->addWidget(tipLabel);
    mainLayout->addSpacing(8);

    // ---- 管理员PIN码（必填）----
    mainLayout->addWidget(makeRequired("管理员 PIN"));
    auto* adminPinEdit = new ElaLineEdit(dialog);
    UiHelper::styleLineEdit(adminPinEdit);
    adminPinEdit->setEchoMode(QLineEdit::Password);
    UiHelper::addPasswordToggle(adminPinEdit);
    adminPinEdit->setPlaceholderText("请输入管理员 PIN 码");
    mainLayout->addWidget(adminPinEdit);
    mainLayout->addSpacing(12);

    // ---- 新用户PIN码（必填）----
    mainLayout->addWidget(makeRequired("新用户 PIN"));
    auto* newUserPinEdit = new ElaLineEdit(dialog);
    UiHelper::styleLineEdit(newUserPinEdit);
    newUserPinEdit->setEchoMode(QLineEdit::Password);
    UiHelper::addPasswordToggle(newUserPinEdit);
    newUserPinEdit->setPlaceholderText("请输入新的用户 PIN 码（至少6位）");
    mainLayout->addWidget(newUserPinEdit);

    auto* pinLenHint = makeHint("PIN 码至少需要6位");
    mainLayout->addWidget(pinLenHint);
    mainLayout->addSpacing(8);

    // ---- 确认新用户PIN码（必填）----
    mainLayout->addWidget(makeRequired("确认新用户 PIN"));
    auto* confirmPinEdit = new ElaLineEdit(dialog);
    UiHelper::styleLineEdit(confirmPinEdit);
    confirmPinEdit->setEchoMode(QLineEdit::Password);
    UiHelper::addPasswordToggle(confirmPinEdit);
    confirmPinEdit->setPlaceholderText("请再次输入新用户 PIN 码");
    mainLayout->addWidget(confirmPinEdit);

    auto* confirmHint = makeHint("两次输入的 PIN 码不一致");
    mainLayout->addWidget(confirmHint);
    mainLayout->addSpacing(16);

    // ---- 分隔线 ----
    mainLayout->addWidget(UiHelper::createDivider(dialog));

    // ---- 按钮 ----
    auto* btnLayout = new QHBoxLayout;
    btnLayout->addStretch();
    auto* cancelBtn = new ElaPushButton("取消", dialog);
    UiHelper::styleDefaultButton(cancelBtn);
    connect(cancelBtn, &ElaPushButton::clicked, dialog, &QDialog::reject);
    btnLayout->addWidget(cancelBtn);
    auto* okBtn = new ElaPushButton("确定", dialog);
    UiHelper::stylePrimaryButton(okBtn);
    okBtn->setEnabled(false);
    connect(okBtn, &ElaPushButton::clicked, dialog, &QDialog::accept);
    btnLayout->addWidget(okBtn);
    mainLayout->addLayout(btnLayout);

    // ---- 实时校验 ----
    auto validateInputs = [=]() {
        const QString newPin = newUserPinEdit->text();
        const QString confirmPin = confirmPinEdit->text();

        // PIN 长度提示
        bool pinTooShort = !newPin.isEmpty() && newPin.length() < 6;
        pinLenHint->setVisible(pinTooShort);

        // 确认码一致性检查
        confirmHint->setVisible(!confirmPin.isEmpty() && newPin != confirmPin);

        bool valid = !adminPinEdit->text().isEmpty()
                  && newPin.length() >= 6
                  && !confirmPin.isEmpty()
                  && newPin == confirmPin;
        okBtn->setEnabled(valid);
    };

    connect(adminPinEdit, &ElaLineEdit::textChanged, dialog, validateInputs);
    connect(newUserPinEdit, &ElaLineEdit::textChanged, dialog, validateInputs);
    connect(confirmPinEdit, &ElaLineEdit::textChanged, dialog, validateInputs);

    if (dialog->exec() != QDialog::Accepted) {
        dialog->deleteLater();
        return;
    }

    QString adminPin = adminPinEdit->text();
    QString newUserPin = newUserPinEdit->text();
    dialog->deleteLater();

    auto result = AppService::instance().unlockPin(devName_, appName, adminPin, newUserPin, {});
    if (!result.isOk()) {
        MessageBox::error(this, "解锁 PIN 失败", result.error());
    } else {
        MessageBox::info(this, "成功", "用户 PIN 已解锁并重置");
        refreshApps();
    }
}

bool AppListView::eventFilter(QObject* obj, QEvent* event) {
    if (obj == backButton_ && event->type() == QEvent::MouseButtonRelease) {
        emit backRequested();
        return true;
    }
    return QWidget::eventFilter(obj, event);
}

}  // namespace wekey
