/**
 * @file MainWindow.cpp
 * @brief 主窗口实现
 */

#include "MainWindow.h"

#include <QApplication>
#include <QCloseEvent>
#include <QFutureWatcher>
#include <QGuiApplication>
#include <QHBoxLayout>
#include <QIcon>
#include <QLabel>
#include <QtConcurrent>

#ifdef Q_OS_WIN
#include <windows.h>
#endif

#include <ElaContentDialog.h>
#include <ElaStatusBar.h>
#include <ElaText.h>
#include <ElaTheme.h>

#include "SystemTray.h"
#include "config/Config.h"
#include "core/device/DeviceService.h"
#include "log/Logger.h"
#include "pages/ConfigPage.h"
#include "pages/DevicePage.h"
#include "pages/LogPage.h"
#include "pages/ModulePage.h"
#include "plugin/PluginManager.h"

namespace wekey {

MainWindow::MainWindow(QWidget* parent) : ElaWindow(parent) {
    // 基本窗口设置
    setWindowTitle("wekey-skf");
    resize(1200, 740);
    setWindowButtonFlag(ElaAppBarType::StayTopButtonHint, false);
    setWindowButtonFlag(ElaAppBarType::ThemeChangeButtonHint, false);
    // Auto 模式：窗口宽时展开导航栏，窄时自动折叠
    setNavigationBarDisplayMode(ElaNavigationType::Auto);

    // 用户信息卡片（头像显示项目 logo，避免 ElaWidgetTools 默认头像）
    setUserInfoCardVisible(true);
    setUserInfoCardTitle("wekey-skf");
    setUserInfoCardSubTitle("SKF 设备管理工具");
    QPixmap logoPix = QIcon(":/icons/app.png").pixmap(60, 60);
    if (!logoPix.isNull()) {
        setUserInfoCardPixmap(logoPix);
    }

    setupNavigation();

    // 状态栏（用单个容器避免 QStatusBar 默认分隔线）
    auto* statusBar = new ElaStatusBar(this);
    statusBar->setSizeGripEnabled(false);
    auto* statusWidget = new QWidget(this);
    auto* statusLayout = new QHBoxLayout(statusWidget);
    statusLayout->setContentsMargins(0, 0, 0, 0);
    statusLayout->setSpacing(4);
    statusText_ = new ElaText("就绪", this);
    statusText_->setTextPixelSize(14);
    statusLayout->addWidget(statusText_);
    statusIcon_ = new QLabel("●", this);
    statusIcon_->setFixedSize(16, 16);
    statusIcon_->setAlignment(Qt::AlignCenter);
    statusLayout->addWidget(statusIcon_);
    statusBar->addWidget(statusWidget);
    setStatusBar(statusBar);

    // 状态栏设备数同步器：
    // 1. 设备页需要显示“真实设备数”，不能靠插入/移除事件做 +1/-1 推算。
    // 2. 转接头整组拔掉时，底层驱动可能只上报一次 remove 事件，
    //    若仍用计数器递减，会出现“页面已空，但状态栏仍显示 2 台设备”的假象。
    // 3. 设备拔出后立即同步调用 SKF 枚举有概率阻塞主线程，因此这里统一走异步重枚举。
    deviceCountRefreshWatcher_ = new QFutureWatcher<QPair<quint64, int>>(this);
    connect(deviceCountRefreshWatcher_, &QFutureWatcher<QPair<quint64, int>>::finished,
            this, &MainWindow::handleAsyncDeviceCountRefreshFinished);

    // 状态栏信号连接
    auto& pm = PluginManager::instance();
    // 插件切换属于“配置变化”而非热插拔：
    // 此时直接同步重算设备数更简单，也能让状态栏尽快显示正确模块下的设备总数。
    connect(&pm, &PluginManager::activePluginChanged, this, [this](const QString& name) {
        LOG_INFO(QString("激活模块已切换，立即同步状态栏设备数，模块=%1").arg(name));
        refreshDeviceCountImmediately(QString("activePluginChanged:%1").arg(name));
    });
    connect(&pm, &PluginManager::pluginUnregistered, this, [this]() {
        // 插件卸载后旧的异步枚举结果不再可信：
        // 例如旧 future 还没跑完，回来后可能把设备数写回成非 0。
        // 这里先提升 generation，使旧结果全部失效，再把状态栏清到 0。
        invalidateAsyncDeviceCountRefresh("pluginUnregistered");
        connectedDeviceCount_ = 0;
        LOG_INFO("驱动模块已卸载，状态栏设备数已重置为 0");
        updateStatus();
    });

    auto& ds = DeviceService::instance();
    // 热插拔只以“设备列表发生变化”为准，不再使用 +1/-1 推算。
    // 这样即使底层一次 remove 事件对应多台设备同时离线，状态栏最终仍以真实枚举结果为准。
    connect(&ds, &DeviceService::deviceListChanged, this, [this]() {
        requestAsyncDeviceCountRefresh("deviceListChanged");
    });

    // 初始化设备计数（插件可能在 MainWindow 构造前就已激活，activePluginChanged 已错过）
    refreshDeviceCountImmediately("MainWindow::ctor");
    updateStatus();

    // 关闭确认对话框
    closeDialog_ = new ElaContentDialog(this);
    closeDialog_->setLeftButtonText("取消");
    closeDialog_->setMiddleButtonText("最小化");
    closeDialog_->setRightButtonText("退出");
    connect(closeDialog_, &ElaContentDialog::rightButtonClicked, this, &MainWindow::closeWindow);
    connect(closeDialog_, &ElaContentDialog::middleButtonClicked, this, [this]() {
        closeDialog_->close();
        showMinimized();
    });

    // 系统托盘
    if (!Config::instance().systrayDisabled()) {
        systemTray_ = new SystemTray(this);
        // 修复：show() 后调用 raise()+activateWindow() 才能在 macOS 上真正浮到前台
        connect(systemTray_, &SystemTray::showRequested, this, &MainWindow::showWindow);
        connect(systemTray_, &SystemTray::exitRequested, qApp, &QApplication::quit);

        // 修复 macOS：Dock 图标点击会触发 ApplicationActive，此时若窗口隐藏则重新显示
#ifdef Q_OS_MAC
        connect(qApp, &QGuiApplication::applicationStateChanged, this,
                [this](Qt::ApplicationState state) {
                    if (state == Qt::ApplicationActive && (!isVisible() || isMinimized())) {
                        showWindow();
                    }
                });
#endif

        setIsDefaultClosed(false);
        connect(this, &MainWindow::closeButtonClicked, this, [this]() {
#ifdef Q_OS_WIN
            // Windows：关闭按钮直接退出进程
            QApplication::quit();
#else
            // macOS：隐藏到托盘，点击托盘图标可恢复
            hide();
#endif
        });
    } else {
        // 无托盘时，关闭按钮弹出确认对话框
        setIsDefaultClosed(false);
        connect(this, &MainWindow::closeButtonClicked, this, [this]() {
            closeDialog_->exec();
        });
    }

    moveToCenter();
}

void MainWindow::closeEvent(QCloseEvent* event) {
    // ElaWindow 通过 closeButtonClicked 信号处理关闭逻辑
    // 此处仅处理系统级关闭事件（如 Alt+F4 / macOS Cmd+Q）
    if (systemTray_ != nullptr) {
#ifdef Q_OS_WIN
        // Windows：Alt+F4 等系统关闭事件同样退出进程
        event->accept();
        QApplication::quit();
#else
        // macOS：隐藏到托盘
        hide();
        event->ignore();
#endif
    } else {
        event->ignore();
        closeDialog_->exec();
    }
}

void MainWindow::showWindow() {
    if (isMinimized()) {
        showNormal();
    } else {
        show();
    }
    raise();
    activateWindow();
}

#ifdef Q_OS_WIN
bool MainWindow::nativeEvent(const QByteArray& eventType, void* message, qintptr* result) {
    // 修复 Windows：Explorer 重启后（如系统更新）托盘图标会丢失，
    // TaskbarCreated 消息通知所有程序重新注册托盘图标
    // 使用局部 static 避免全局初始化时 windows.h 类型污染 macOS clangd
    static const UINT wmTaskbarCreated = ::RegisterWindowMessage(L"TaskbarCreated");
    const MSG* msg = static_cast<const MSG*>(message);
    if (msg->message == wmTaskbarCreated && systemTray_) {
        systemTray_->reinstall();
    }
    return ElaWindow::nativeEvent(eventType, message, result);
}
#endif

void MainWindow::refreshDeviceCountImmediately(const QString& reason) {
    auto result = DeviceService::instance().enumDevices(false, false);
    if (!result.isOk()) {
        // 状态栏设备数是展示态，设备总线掉线时宁可暂时按 0 台显示，
        // 也不能继续保留旧数量误导用户。详细原因交给底层错误日志排查。
        LOG_WARN(QString("同步状态栏设备数失败，原因=%1，错误=%2；按 0 台处理")
                     .arg(reason)
                     .arg(result.error().toString(true).replace('\n', " | ")));
        connectedDeviceCount_ = 0;
        updateStatus();
        return;
    }

    const int newCount = result.value().size();
    LOG_INFO(QString("同步状态栏设备数完成，原因=%1，设备数=%2")
                 .arg(reason)
                 .arg(newCount));
    connectedDeviceCount_ = newCount;
    updateStatus();
}

void MainWindow::requestAsyncDeviceCountRefresh(const QString& reason) {
    // 每次请求都分配新的 generation：
    // - 若当前 future 还在执行，新 generation 会让旧结果在完成时被自动丢弃
    // - 若短时间内连续收到多次热插拔事件，只保留“最后一轮真实重枚举”的结果
    ++deviceCountRefreshGeneration_;
    deviceCountRefreshPending_ = true;
    if (pendingDeviceCountRefreshReason_.isEmpty()) {
        pendingDeviceCountRefreshReason_ = reason;
    } else {
        pendingDeviceCountRefreshReason_.append(" | ");
        pendingDeviceCountRefreshReason_.append(reason);
    }

    LOG_INFO(QString("收到状态栏设备数异步刷新请求，generation=%1，原因=%2，当前显示=%3")
                 .arg(deviceCountRefreshGeneration_)
                 .arg(reason)
                 .arg(connectedDeviceCount_));

    if (deviceCountRefreshWatcher_ && deviceCountRefreshWatcher_->isRunning()) {
        LOG_DEBUG(QString("设备数异步刷新任务仍在执行，合并后续请求，latestGeneration=%1，mergedReason=%2")
                      .arg(deviceCountRefreshGeneration_)
                      .arg(pendingDeviceCountRefreshReason_));
        return;
    }

    startAsyncDeviceCountRefresh();
}

void MainWindow::startAsyncDeviceCountRefresh() {
    if (!deviceCountRefreshPending_ || !deviceCountRefreshWatcher_) {
        return;
    }

    const quint64 generation = deviceCountRefreshGeneration_;
    runningDeviceCountRefreshReason_ = pendingDeviceCountRefreshReason_.isEmpty()
        ? QString("unknown")
        : pendingDeviceCountRefreshReason_;
    pendingDeviceCountRefreshReason_.clear();
    deviceCountRefreshPending_ = false;

    LOG_INFO(QString("开始异步重枚举设备以刷新状态栏，generation=%1，原因=%2")
                 .arg(generation)
                 .arg(runningDeviceCountRefreshReason_));

    deviceCountRefreshWatcher_->setFuture(QtConcurrent::run(
        [generation, reason = runningDeviceCountRefreshReason_]() -> QPair<quint64, int> {
            auto result = DeviceService::instance().enumDevices(false, false);
            if (!result.isOk()) {
                // 后台重枚举失败时同样按 0 台写回，避免状态栏停留在已过期的旧设备数。
                LOG_WARN(QString("异步重枚举设备失败，generation=%1，原因=%2，错误=%3；按 0 台处理")
                             .arg(generation)
                             .arg(reason)
                             .arg(result.error().toString(true).replace('\n', " | ")));
                return qMakePair(generation, 0);
            }

            const int count = result.value().size();
            LOG_INFO(QString("异步重枚举设备完成，generation=%1，原因=%2，设备数=%3")
                         .arg(generation)
                         .arg(reason)
                         .arg(count));
            return qMakePair(generation, count);
        }));
}

void MainWindow::handleAsyncDeviceCountRefreshFinished() {
    if (!deviceCountRefreshWatcher_) {
        return;
    }

    const auto result = deviceCountRefreshWatcher_->result();
    const quint64 generation = result.first;
    const int newCount = result.second;

    // 如果在 future 执行期间又来了更新请求，或插件已被卸载，
    // 当前结果就已经过时，不能再写回状态栏。
    if (generation != deviceCountRefreshGeneration_) {
        LOG_DEBUG(QString("丢弃过期的设备数异步刷新结果，finishedGeneration=%1，latestGeneration=%2，原因=%3")
                      .arg(generation)
                      .arg(deviceCountRefreshGeneration_)
                      .arg(runningDeviceCountRefreshReason_));
        if (deviceCountRefreshPending_) {
            startAsyncDeviceCountRefresh();
        }
        return;
    }

    const int oldCount = connectedDeviceCount_;
    connectedDeviceCount_ = newCount;
    if (oldCount != newCount) {
        LOG_INFO(QString("状态栏设备数已刷新，原因=%1，old=%2，new=%3，generation=%4")
                     .arg(runningDeviceCountRefreshReason_)
                     .arg(oldCount)
                     .arg(newCount)
                     .arg(generation));
    } else {
        LOG_DEBUG(QString("状态栏设备数刷新完成但无变化，原因=%1，count=%2，generation=%3")
                      .arg(runningDeviceCountRefreshReason_)
                      .arg(newCount)
                      .arg(generation));
    }
    updateStatus();

    if (deviceCountRefreshPending_) {
        LOG_DEBUG("检测到合并中的后续设备数刷新请求，继续执行下一轮异步重枚举");
        startAsyncDeviceCountRefresh();
    }
}

void MainWindow::invalidateAsyncDeviceCountRefresh(const QString& reason) {
    // 提升 generation 即可让所有旧 future 在完成时自动失效。
    ++deviceCountRefreshGeneration_;
    deviceCountRefreshPending_ = false;
    pendingDeviceCountRefreshReason_.clear();
    runningDeviceCountRefreshReason_.clear();

    LOG_INFO(QString("已使历史设备数异步刷新结果失效，原因=%1，latestGeneration=%2")
                 .arg(reason)
                 .arg(deviceCountRefreshGeneration_));
}

void MainWindow::updateStatus() {
    bool hasPlugin = !PluginManager::instance().activePluginName().isEmpty();

    if (!hasPlugin) {
        statusText_->setText("未加载驱动");
        statusIcon_->setStyleSheet("color: #ff4d4f; font-size: 14px;");
        return;
    }

    if (connectedDeviceCount_ == 0) {
        statusText_->setText("就绪 · 无设备");
        statusIcon_->setStyleSheet("color: #faad14; font-size: 14px;");
    } else {
        statusText_->setText(QString("就绪 · %1 台设备").arg(connectedDeviceCount_));
        statusIcon_->setStyleSheet("color: #2ecc71; font-size: 14px;");
    }
}

void MainWindow::setupNavigation() {
    // 使用 ElaWindow 内置导航栏添加页面节点
    // ElaIconType 图标替代原有 SVG 图标
    addPageNode("模块管理", new ModulePage, ElaIconType::Plug);
    addPageNode("设备管理", new DevicePage, ElaIconType::UsbDrive);
    addPageNode("配置管理", new ConfigPage, ElaIconType::Sliders);
    addPageNode("日志查看", new LogPage, ElaIconType::Terminal);

    // 底部导航节点：配置和日志
    /*QString configKey;
    addFooterNode("配置管理", new ConfigPage, configKey, 0, ElaIconType::Gears);
    QString logKey;
    addFooterNode("日志查看", new LogPage, logKey, 0, ElaIconType::ClipboardList);*/
}

}  // namespace wekey
