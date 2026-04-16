/**
 * @file MainWindow.h
 * @brief 主窗口 (M5.2)
 *
 * 左侧导航栏 + 右侧内容区 + 状态栏
 */

#pragma once

#include <QFutureWatcher>
#include <QPair>
#include <QString>

#include <ElaWindow.h>

class ElaContentDialog;
class ElaText;
class QLabel;

namespace wekey {

class SystemTray;

class MainWindow : public ElaWindow {
    Q_OBJECT

public:
    explicit MainWindow(QWidget* parent = nullptr);
    ~MainWindow() override = default;

protected:
    void closeEvent(QCloseEvent* event) override;
#ifdef Q_OS_WIN
    bool nativeEvent(const QByteArray& eventType, void* message, qintptr* result) override;
#endif

private:
    void setupNavigation();
    void updateStatus();
    /// @brief 在安全上下文中立即重算设备数（如插件切换、窗口初始化）
    void refreshDeviceCountImmediately(const QString& reason);
    /// @brief 在热插拔场景下异步重算设备数，避免 UI 线程阻塞
    void requestAsyncDeviceCountRefresh(const QString& reason);
    /// @brief 启动一轮异步设备重枚举；若已有任务运行则由 request 侧合并
    void startAsyncDeviceCountRefresh();
    /// @brief 处理异步设备数刷新完成事件，并丢弃失效结果
    void handleAsyncDeviceCountRefreshFinished();
    /// @brief 使当前及更早的异步刷新结果失效，用于插件卸载等上下文切换
    void invalidateAsyncDeviceCountRefresh(const QString& reason);
    /// @brief 将窗口显示并带到前台（跨平台）
    void showWindow();

    SystemTray* systemTray_ = nullptr;
    ElaContentDialog* closeDialog_ = nullptr;
    ElaText* statusText_ = nullptr;
    QLabel* statusIcon_ = nullptr;
    int connectedDeviceCount_ = 0;
    // 异步设备数刷新器：
    // - 只用于状态栏同步，不影响设备页真实枚举逻辑
    // - future 返回 (generation, count)，generation 用于丢弃过期结果
    QFutureWatcher<QPair<quint64, int>>* deviceCountRefreshWatcher_ = nullptr;
    // 若热插拔事件在上一轮刷新期间继续到来，则只合并成“待执行一轮”
    bool deviceCountRefreshPending_ = false;
    // 每次请求都会递增 generation；插件卸载时也会递增以使旧结果失效
    quint64 deviceCountRefreshGeneration_ = 0;
    // 记录当前待执行/执行中的触发原因，便于日志定位计数来源
    QString pendingDeviceCountRefreshReason_;
    QString runningDeviceCountRefreshReason_;
};

}  // namespace wekey
