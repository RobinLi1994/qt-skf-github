/**
 * @file AddModuleDialog.h
 * @brief 添加模块对话框
 *
 * 支持两种模式：
 * 1. 使用内置驱动 —— 从下拉列表选择内置模块名称，自动获取打包后的默认路径
 * 2. 上传自定义文件 —— 用户通过文件选择器上传自定义 SKF 驱动库
 *
 * UI 风格使用 ElaWidgetTools 组件库，参考 Ant Design 设计规范。
 */

#pragma once

#include <QDialog>
#include <QLabel>

class ElaComboBox;
class ElaLineEdit;
class ElaPushButton;
class ElaRadioButton;

namespace wekey {

class AddModuleDialog : public QDialog {
    Q_OBJECT

public:
    explicit AddModuleDialog(QWidget* parent = nullptr);

    /// @brief 获取用户选择/输入的模块名称
    QString moduleName() const;

    /// @brief 获取模块库文件路径
    QString modulePath() const;

private slots:
    /// @brief 切换到"使用内置驱动"模式
    void onBuiltinSelected();

    /// @brief 切换到"上传自定义文件"模式
    void onCustomSelected();

    /// @brief 点击"获取默认路径"按钮
    void onFetchDefaultPath();

    /// @brief 点击"选择文件"按钮
    void onSelectFile();

    /// @brief 校验表单，控制确定按钮启用状态
    void validate();

private:
    void setupUi();

    /// @brief 创建带红色星号的必填标签
    QLabel* createRequiredLabel(const QString& text);

    /// @brief 搜索内置 SKF 库路径（复用 Application 的搜索逻辑）
    QString findBuiltinLibPath(const QString& moduleName) const;

    // ---- 内置驱动名称映射 ----
    /// @brief 获取内置驱动列表 (显示名称 -> 库文件基础名)
    struct BuiltinDriver {
        QString displayName;  ///< 下拉框显示名称
        QString baseName;     ///< 库文件基础名（不含 lib 前缀和扩展名）
    };
    QList<BuiltinDriver> builtinDrivers() const;

    // ---- UI 控件 ----
    ElaComboBox* nameCombo_ = nullptr;         ///< 模块名称下拉框
    ElaRadioButton* builtinRadio_ = nullptr;   ///< 使用内置驱动单选按钮
    ElaRadioButton* customRadio_ = nullptr;    ///< 上传自定义文件单选按钮

    // 内置驱动模式控件
    QWidget* builtinWidget_ = nullptr;         ///< 内置驱动路径区域容器
    ElaLineEdit* builtinPathEdit_ = nullptr;   ///< 内置驱动路径（只读）
    QLabel* fetchPathLink_ = nullptr;          ///< "获取默认路径"链接

    // 自定义文件模式控件
    QWidget* customWidget_ = nullptr;          ///< 自定义文件区域容器
    ElaLineEdit* customPathEdit_ = nullptr;    ///< 自定义文件路径（只读）
    QLabel* selectFileLink_ = nullptr;         ///< "选择文件"链接

    ElaPushButton* okButton_ = nullptr;        ///< 确定按钮
    ElaPushButton* cancelButton_ = nullptr;    ///< 取消按钮
};

}  // namespace wekey
