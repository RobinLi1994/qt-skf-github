/**
 * @file AppService.cpp
 * @brief 应用服务实现
 */

#include "AppService.h"

#include <QDebug>

#include "plugin/PluginManager.h"

namespace wekey {

namespace {

bool shouldResyncDevicesAfterLoginFailure(const Error& error) {
    switch (error.code()) {
        case Error::SkfPinIncorrect:
        case Error::SkfPinLocked:
        case Error::SkfAppNotExists:
        case Error::InvalidParam:
        case Error::NoActiveModule:
        case Error::PluginLoadFailed:
            return false;
        default:
            break;
    }

    // 登录阶段出现 SKF 层非预期错误时，优先怀疑热插拔事件漏报或会话已失效。
    // 这里触发一次静默重枚举，让插件用最新设备列表兜底清理缓存状态。
    return error.context().startsWith("SKF_");
}

}  // namespace

AppService& AppService::instance() {
    static AppService instance;
    return instance;
}

AppService::AppService() : QObject(nullptr) {}

Result<QList<AppInfo>> AppService::enumApps(const QString& devName) {
    auto plugin = PluginManager::instance().activePluginShared();
    if (!plugin) {
        return Result<QList<AppInfo>>::err(
            Error(Error::NoActiveModule, "驱动模块未激活", "AppService::enumApps"));
    }
    return plugin->enumApps(devName);
}

Result<void> AppService::createApp(const QString& devName, const QString& appName, const QVariantMap& args) {
    auto plugin = PluginManager::instance().activePluginShared();
    if (!plugin) {
        return Result<void>::err(
            Error(Error::NoActiveModule, "驱动模块未激活", "AppService::createApp"));
    }
    return plugin->createApp(devName, appName, args);
}

Result<void> AppService::deleteApp(const QString& devName, const QString& appName) {
    auto plugin = PluginManager::instance().activePluginShared();
    if (!plugin) {
        return Result<void>::err(
            Error(Error::NoActiveModule, "驱动模块未激活", "AppService::deleteApp"));
    }
    return plugin->deleteApp(devName, appName);
}

Result<void> AppService::login(const QString& devName, const QString& appName, const QString& role,
                                const QString& pin, bool emitSignals) {
    auto plugin = PluginManager::instance().activePluginShared();
    if (!plugin) {
        return Result<void>::err(
            Error(Error::NoActiveModule, "驱动模块未激活", "AppService::login"));
    }

    auto result = plugin->openApp(devName, appName, role, pin);
    if (result.isOk()) {
        if (emitSignals) {
            emit loginStateChanged(devName, appName, true);
        }
    } else {
        auto code = result.error().code();
        if (shouldResyncDevicesAfterLoginFailure(result.error())) {
            qWarning() << "[AppService::login] 登录失败后触发设备状态重同步,"
                       << "devName:" << devName
                       << "appName:" << appName
                       << "error:" << result.error().toString(true);
            auto syncResult = plugin->enumDevices(false);
            if (syncResult.isOk()) {
                qInfo() << "[AppService::login] 登录失败后的设备状态重同步完成,"
                        << "deviceCount:" << syncResult.value().size();
            } else {
                qWarning() << "[AppService::login] 登录失败后的设备状态重同步也失败:"
                           << syncResult.error().toString(true);
            }
        }

        if (code == Error::SkfPinIncorrect) {
            // 剩余次数必须通过无副作用接口读取，不能再次用错误 PIN 调 VerifyPIN。
            auto pinInfoResult = plugin->getPinInfo(devName, appName, role);
            int retryCount = pinInfoResult.isOk() ? pinInfoResult.value().remainRetryCount : -1;
            if (emitSignals) {
                emit pinError(devName, appName, retryCount);
            }
        } else if (code == Error::SkfPinLocked && emitSignals) {
            emit pinLocked(devName, appName);
        }
    }
    return result;
}

Result<void> AppService::logout(const QString& devName, const QString& appName, bool emitSignals) {
    auto plugin = PluginManager::instance().activePluginShared();
    if (!plugin) {
        return Result<void>::err(
            Error(Error::NoActiveModule, "驱动模块未激活", "AppService::logout"));
    }
    auto result = plugin->closeApp(devName, appName);
    if (result.isOk() && emitSignals) {
        emit loginStateChanged(devName, appName, false);
    }
    return result;
}

Result<void> AppService::changePin(const QString& devName, const QString& appName, const QString& role,
                                    const QString& oldPin, const QString& newPin) {
    auto plugin = PluginManager::instance().activePluginShared();
    if (!plugin) {
        return Result<void>::err(
            Error(Error::NoActiveModule, "驱动模块未激活", "AppService::changePin"));
    }
    return plugin->changePin(devName, appName, role, oldPin, newPin);
}

Result<void> AppService::unlockPin(const QString& devName, const QString& appName, const QString& adminPin,
                                    const QString& newUserPin, const QVariantMap& args) {
    auto plugin = PluginManager::instance().activePluginShared();
    if (!plugin) {
        return Result<void>::err(
            Error(Error::NoActiveModule, "驱动模块未激活", "AppService::unlockPin"));
    }
    return plugin->unlockPin(devName, appName, adminPin, newUserPin, args);
}

Result<int> AppService::getRetryCount(const QString& devName, const QString& appName,
                                       const QString& role, const QString& pin) {
    auto plugin = PluginManager::instance().activePluginShared();
    if (!plugin) {
        return Result<int>::err(
            Error(Error::NoActiveModule, "驱动模块未激活", "AppService::getRetryCount"));
    }
    return plugin->getRetryCount(devName, appName, role, pin);
}

Result<PinInfo> AppService::getPinInfo(const QString& devName, const QString& appName,
                                        const QString& role) {
    auto plugin = PluginManager::instance().activePluginShared();
    if (!plugin) {
        return Result<PinInfo>::err(
            Error(Error::NoActiveModule, "驱动模块未激活", "AppService::getPinInfo"));
    }
    return plugin->getPinInfo(devName, appName, role);
}

}  // namespace wekey
