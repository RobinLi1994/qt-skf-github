/**
 * @file PluginManager.cpp
 * @brief 插件管理器实现
 */

#include "PluginManager.h"

#include <QReadLocker>
#include <QWriteLocker>

#include "log/Logger.h"
#include "plugin/skf/SkfPlugin.h"

namespace wekey {

PluginManager& PluginManager::instance() {
    static PluginManager instance;
    return instance;
}

PluginManager::PluginManager() : QObject(nullptr) {}

Result<void> PluginManager::registerPlugin(const QString& name, const QString& libPath, bool emitSignals) {
    if (name.isEmpty() || libPath.isEmpty()) {
        return Result<void>::err(
            Error(Error::InvalidParam, "插件名称和路径不能为空", "PluginManager::registerPlugin"));
    }

    {
        QReadLocker locker(&mutex_);
        if (plugins_.contains(name)) {
            return Result<void>::err(
                Error(Error::AlreadyExists, "插件已注册：" + name, "PluginManager::registerPlugin"));
        }
    }

    auto plugin = std::make_shared<SkfPlugin>();
    auto initResult = plugin->initialize(libPath);

    // 即使初始化失败也注册（路径可能指向尚未就绪的设备驱动），
    // 但保留插件实例以便后续重试或路径查询
    PluginEntry entry;
    entry.libPath = libPath;
    entry.plugin = plugin;
    {
        QWriteLocker locker(&mutex_);
        if (plugins_.contains(name)) {
            return Result<void>::err(
                Error(Error::AlreadyExists, "插件已注册：" + name, "PluginManager::registerPlugin"));
        }
        plugins_.insert(name, entry);
    }

    if (initResult.isOk()) {
        LOG_INFO(QString("插件已注册并初始化成功，名称=%1，路径=%2").arg(name, libPath));
    } else {
        LOG_WARN(QString("插件已注册但初始化失败，名称=%1，路径=%2，错误=%3")
                     .arg(name)
                     .arg(libPath)
                     .arg(initResult.error().message()));
    }

    if (emitSignals) {
        emit pluginRegistered(name);
    }
    return Result<void>::ok();
}

Result<void> PluginManager::registerPluginInstance(const QString& name, std::shared_ptr<IDriverPlugin> plugin) {
    if (name.isEmpty() || !plugin) {
        return Result<void>::err(
            Error(Error::InvalidParam, "插件名称和实例不能为空",
                  "PluginManager::registerPluginInstance"));
    }

    {
        QReadLocker locker(&mutex_);
        if (plugins_.contains(name)) {
            return Result<void>::err(
                Error(Error::AlreadyExists, "插件已注册：" + name,
                      "PluginManager::registerPluginInstance"));
        }
    }

    PluginEntry entry;
    entry.libPath = QStringLiteral("<injected>");
    entry.plugin = std::move(plugin);
    {
        QWriteLocker locker(&mutex_);
        if (plugins_.contains(name)) {
            return Result<void>::err(
                Error(Error::AlreadyExists, "插件已注册：" + name,
                      "PluginManager::registerPluginInstance"));
        }
        plugins_.insert(name, entry);
    }

    LOG_INFO(QString("插件实例已注入注册，名称=%1").arg(name));

    emit pluginRegistered(name);
    return Result<void>::ok();
}

Result<void> PluginManager::unregisterPlugin(const QString& name, bool emitSignals) {
    std::shared_ptr<IDriverPlugin> removedPlugin;
    bool wasActive = false;

    {
        QWriteLocker locker(&mutex_);
        auto it = plugins_.find(name);
        if (it == plugins_.end()) {
            return Result<void>::err(
                Error(Error::NotFound, "插件未找到：" + name, "PluginManager::unregisterPlugin"));
        }

        removedPlugin = it->plugin;
        plugins_.erase(it);

        // 若卸载的是当前激活插件，需要先在锁内清空激活状态，
        // 避免其他线程在 remove 与 clear 之间读到失效的 activePluginName_。
        if (activePluginName_ == name) {
            activePluginName_.clear();
            wasActive = true;
        }
    }

    LOG_INFO(QString("插件已卸载，名称=%1，wasActive=%2")
                 .arg(name)
                 .arg(wasActive));

    if (emitSignals) {
        emit pluginUnregistered(name);
    }
    return Result<void>::ok();
}

IDriverPlugin* PluginManager::getPlugin(const QString& name) const {
    QReadLocker locker(&mutex_);
    auto it = plugins_.find(name);
    if (it == plugins_.end()) {
        return nullptr;
    }
    return it->plugin.get();
}

QString PluginManager::getPluginPath(const QString& name) const {
    QReadLocker locker(&mutex_);
    auto it = plugins_.find(name);
    if (it == plugins_.end()) {
        return {};
    }
    return it->libPath;
}

IDriverPlugin* PluginManager::activePlugin() const {
    QReadLocker locker(&mutex_);
    if (activePluginName_.isEmpty()) {
        return nullptr;
    }

    auto it = plugins_.find(activePluginName_);
    if (it == plugins_.end()) {
        return nullptr;
    }
    return it->plugin.get();
}

std::shared_ptr<IDriverPlugin> PluginManager::activePluginShared() const {
    QReadLocker locker(&mutex_);
    if (activePluginName_.isEmpty()) {
        return nullptr;
    }
    auto it = plugins_.find(activePluginName_);
    if (it == plugins_.end()) {
        return nullptr;
    }
    return it->plugin;
}

QString PluginManager::activePluginName() const {
    QReadLocker locker(&mutex_);
    return activePluginName_;
}

Result<void> PluginManager::setActivePlugin(const QString& name, bool emitSignals) {
    {
        QWriteLocker locker(&mutex_);
        if (!plugins_.contains(name)) {
            return Result<void>::err(
                Error(Error::NotFound, "插件未找到：" + name, "PluginManager::setActivePlugin"));
        }

        activePluginName_ = name;
    }

    LOG_INFO(QString("激活插件已切换，名称=%1").arg(name));
    if (emitSignals) {
        emit activePluginChanged(name);
    }
    return Result<void>::ok();
}

QStringList PluginManager::listPlugins() const {
    QReadLocker locker(&mutex_);
    return plugins_.keys();
}

}  // namespace wekey
