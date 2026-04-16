/**
 * @file MessageBox.cpp
 * @brief 自定义消息框实现
 */

#include "MessageBox.h"

#include <QHBoxLayout>
#include <QLabel>
#include <QWidget>

#include <ElaContentDialog.h>
#include <ElaIcon.h>
#include <ElaMessageBar.h>
#include <ElaPushButton.h>
#include <ElaText.h>

#include "config/Config.h"

namespace wekey {

void MessageBox::info(QWidget* parent, const QString& title, const QString& message) {
    ElaMessageBar::success(ElaMessageBarType::TopRight, title, message, 3000, parent);
}

void MessageBox::error(QWidget* parent, const QString& title, const Error& err) {
    bool detailed = Config::instance().errorMode() == "detailed";
    QString message = err.toString(detailed);
    ElaMessageBar::error(ElaMessageBarType::TopRight, title, message, 5000, parent);
}

void MessageBox::error(QWidget* parent, const QString& title, const QString& message) {
    ElaMessageBar::error(ElaMessageBarType::TopRight, title, message, 5000, parent);
}

void MessageBox::confirm(QWidget* parent, const QString& title, const QString& message,
                         std::function<void()> onConfirm) {
    auto* dialog = new ElaContentDialog(parent);
    dialog->setWindowTitle(title);
    dialog->setMinimumWidth(480);
    dialog->setLeftButtonText("取消");
    dialog->setMiddleButtonText("");
    dialog->setRightButtonText("确定");

    // 隐藏中间按钮
    auto buttons = dialog->findChildren<ElaPushButton*>();
    if (buttons.size() >= 2) {
        buttons[1]->setVisible(false);
    }

    auto* centralWidget = new QWidget(dialog);
    auto* layout = new QHBoxLayout(centralWidget);
    layout->setContentsMargins(20, 20, 20, 20);
    layout->setSpacing(16);

    // 使用 ElaIcon 渲染警告图标，与 ElaWidgetTools 风格一致
    auto* iconLabel = new QLabel(centralWidget);
    QIcon warnIcon = ElaIcon::getInstance()->getElaIcon(
        ElaIconType::TriangleExclamation, 28, QColor("#f5a623"));
    iconLabel->setPixmap(warnIcon.pixmap(32, 32));
    iconLabel->setFixedSize(32, 32);
    layout->addWidget(iconLabel);

    // 使用 ElaText 自动跟随主题配色
    auto* textLabel = new ElaText(message, centralWidget);
    textLabel->setTextPixelSize(14);
    textLabel->setWordWrap(true);
    layout->addWidget(textLabel, 1);

    dialog->setCentralWidget(centralWidget);

    QObject::connect(dialog, &ElaContentDialog::rightButtonClicked, parent,
                     [onConfirm]() { onConfirm(); });

    dialog->exec();
}

}  // namespace wekey
