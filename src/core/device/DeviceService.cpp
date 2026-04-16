/**
 * @file DeviceService.cpp
 * @brief 设备服务实现
 */

#include "DeviceService.h"

#include <QThread>

#include "log/Logger.h"
#include "plugin/PluginManager.h"

namespace wekey {

DeviceService& DeviceService::instance() {
    // 故意使用堆分配、永不释放（intentional leak singleton）。
    // DeviceService 持有监听线程，libusb 的 poll() 阻塞调用无法被
    // pthread_cancel 可靠中断（libusb 内部会临时 DISABLE 取消点）。
    // Qt 6.10 将 QThread::~QThread() 中"线程仍在运行"从 qWarning 改为
    // qFatal，若析构时线程未退出则直接 abort。
    // 解法：永不析构此对象，进程退出时由 OS 统一回收所有线程，QThread
    // 析构不会被调用，crash 彻底消除。
    static DeviceService* instance = new DeviceService();
    return *instance;
}

DeviceService::DeviceService() : QObject(nullptr) {
    // 连接只做一次：线程启动后执行监听循环。
    // 不传 context 对象，lambda 以 DirectConnection 在监听线程直接执行，
    // 避免被 queue 到主线程导致 UI 阻塞。
    QObject::connect(&monitorThread_, &QThread::started, [this]() {
        monitorLoop();
    });
}

DeviceService::~DeviceService() {
    stopDeviceMonitor();
}

Result<QList<DeviceInfo>> DeviceService::enumDevices(bool login, bool emitSignals) {
    auto plugin = PluginManager::instance().activePluginShared();
    if (!plugin) {
        return Result<QList<DeviceInfo>>::err(
            Error(Error::NoActiveModule, "驱动模块未激活", "DeviceService::enumDevices"));
    }
    auto result = plugin->enumDevices(login);
    if (result.isOk() && emitSignals) {
        emit deviceListChanged();
    }
    return result;
}

Result<void> DeviceService::changeDeviceAuth(const QString& devName, const QString& oldPin, const QString& newPin) {
    auto plugin = PluginManager::instance().activePluginShared();
    if (!plugin) {
        return Result<void>::err(
            Error(Error::NoActiveModule, "驱动模块未激活", "DeviceService::changeDeviceAuth"));
    }
    return plugin->changeDeviceAuth(devName, oldPin, newPin);
}

Result<void> DeviceService::setDeviceLabel(const QString& devName, const QString& label) {
    auto plugin = PluginManager::instance().activePluginShared();
    if (!plugin) {
        return Result<void>::err(
            Error(Error::NoActiveModule, "驱动模块未激活", "DeviceService::setDeviceLabel"));
    }
    return plugin->setDeviceLabel(devName, label);
}

void DeviceService::startDeviceMonitor() {
    const bool wasMonitoring = monitoring_.exchange(true);
    if (wasMonitoring) {
        LOG_DEBUG("设备监控已处于启用状态，跳过重复启动");
        return;  // 已在监听，monitorLoop 会自动跟随当前激活插件
    }
    if (monitorThread_.isRunning()) {
        // stopDeviceMonitor() 不再强杀线程，旧线程可能仍阻塞在 WaitForDevEvent。
        // 此处只恢复逻辑启用状态，等待旧线程自然继续即可。
        LOG_INFO("设备监控线程仍在运行，已恢复逻辑监听状态，无需重新启动线程");
        return;
    }
    LOG_INFO("启动设备监控线程");
    monitorThread_.start();
}

void DeviceService::stopDeviceMonitor() {
    const bool wasMonitoring = monitoring_.exchange(false);
    if (!wasMonitoring) {
        LOG_DEBUG("设备监控已处于停用状态，跳过重复停止");
        return;
    }

    if (!monitorThread_.isRunning()) {
        LOG_INFO("设备监控线程未运行，逻辑监听状态已关闭");
        return;
    }

    // 不再使用 QThread::terminate() 强杀监听线程：
    // 1. waitForDeviceEvent() 可能阻塞在三方驱动内部，强杀会把库状态、锁和句柄留在未定义状态。
    // 2. 当前设计下 DeviceService 单例故意泄漏，进程退出时由 OS 回收线程资源即可。
    // 3. stopDeviceMonitor() 现在仅表示“关闭逻辑监听”，待阻塞调用自然返回后线程才会真正结束。
    LOG_WARN("设备监控已标记为停用；监听线程若仍阻塞在 waitForDeviceEvent，将等待其自然返回，不再强制 terminate");
}

bool DeviceService::isMonitoring() const {
    return monitoring_;
}

void DeviceService::monitorLoop() {
    LOG_INFO("设备监控线程已进入监听循环");
    while (monitoring_) {
        // 每轮重新获取激活插件，支持运行时删除/切换模块后自动跟随新插件。
        // 必须使用 shared_ptr 而非原始指针：waitForDeviceEvent() 是阻塞调用，
        // 若调用期间 unregisterPlugin() 移除了 shared_ptr，原始指针会变成野指针，
        // 函数返回后访问 this（如 onDeviceRemoved）导致 EXC_BAD_ACCESS。
        // shared_ptr 持有强引用，确保 SkfPlugin 在整个阻塞调用期间保持存活。
        auto plugin = PluginManager::instance().activePluginShared();
        if (!plugin) {
            QThread::msleep(200);
            continue;
        }

        auto result = plugin->waitForDeviceEvent();
        if (result.isErr()) {
            if (!monitoring_) break;
            LOG_WARN(QString("等待设备事件失败，错误=%1；100ms 后重试")
                         .arg(result.error().message()));
            QThread::msleep(100);
            continue;
        }

        // stopDeviceMonitor() 可能在阻塞等待期间被调用。
        // 若 waitForDeviceEvent 恰好在此时返回，必须先检查 monitoring_，
        // 避免在线程已逻辑停用后继续向 UI 发出过期的插拔事件。
        if (!monitoring_) {
            LOG_INFO("设备监控在线程停用后收到返回，跳过事件分发并退出监听循环");
            break;
        }

        int event = result.value();
        if (event == static_cast<int>(DeviceEvent::Inserted)) {
            emit deviceInserted({});
            emit deviceListChanged();
        } else if (event == static_cast<int>(DeviceEvent::Removed)) {
            emit deviceRemoved({});
            emit deviceListChanged();
        }
    }
    LOG_INFO("设备监控线程已退出监听循环");
}

}  // namespace wekey
