/**
 * @file LogPage.cpp
 * @brief 日志查看页实现
 */

#include "LogPage.h"

#include <QDate>
#include <QFileDialog>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QStackedWidget>
#include <QVBoxLayout>

#include <ElaComboBox.h>
#include <ElaLineEdit.h>
#include <ElaPushButton.h>
#include <ElaScrollPageArea.h>
#include <ElaTableView.h>
#include <ElaText.h>

#include "gui/UiHelper.h"
#include "gui/dialogs/MessageBox.h"
#include "log/Logger.h"

namespace wekey {

LogPage::LogPage(QWidget* parent) : ElaScrollPage(parent) {
    setWindowTitle("日志查看");
    setTitleVisible(false);
    setupUi();
}

ElaLineEdit* LogPage::searchEdit() const { return searchEdit_; }

ElaComboBox* LogPage::levelCombo() const { return levelCombo_; }

ElaPushButton* LogPage::clearButton() const { return clearButton_; }

ElaTableView* LogPage::tableView() const { return tableView_; }

LogModel* LogPage::logModel() const { return logModel_; }

void LogPage::setupUi() {
    // 筛选区域
    auto* filterArea = new ElaScrollPageArea(this);
    UiHelper::styleCard(filterArea);
    auto* filterLayout = new QHBoxLayout(filterArea);
    auto* searchLabel = new ElaText("搜索:", this);
    searchLabel->setTextStyle(ElaTextType::Body);
    filterLayout->addWidget(searchLabel);
    searchEdit_ = new ElaLineEdit(this);
    UiHelper::styleLineEdit(searchEdit_);
    searchEdit_->setPlaceholderText("搜索日志...");
    filterLayout->addWidget(searchEdit_, 1);
    auto* levelLabel = new ElaText("级别:", this);
    levelLabel->setTextStyle(ElaTextType::Body);
    filterLayout->addWidget(levelLabel);
    levelCombo_ = new ElaComboBox(this);
    UiHelper::styleComboBox(levelCombo_);
    levelCombo_->addItems({"All", "Debug", "Info", "Warn", "Error"});
    filterLayout->addWidget(levelCombo_);
    exportButton_ = new ElaPushButton("导出日志", this);
    filterLayout->addWidget(exportButton_);
    clearButton_ = new ElaPushButton("清空", this);
    UiHelper::styleDangerButton(clearButton_);
    filterLayout->addWidget(clearButton_);

    // 日志表格
    logModel_ = new LogModel(this);
    logModel_->connectToLogger();

    tableView_ = new ElaTableView(this);
    tableView_->setModel(logModel_);
    tableView_->verticalHeader()->setVisible(false);
    tableView_->verticalHeader()->setDefaultSectionSize(36);
    tableView_->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Fixed);    // 时间
    tableView_->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Fixed);    // 级别
    tableView_->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Fixed);    // 来源
    tableView_->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Stretch);  // 消息
    tableView_->setColumnWidth(0, 200);  // yyyy-MM-dd hh:mm:ss.zzz
    tableView_->setColumnWidth(1, 60);   // DEBUG/INFO
    tableView_->setColumnWidth(2, 140);  // 来源
    tableView_->horizontalHeader()->setStretchLastSection(true);
    tableView_->setSelectionBehavior(QAbstractItemView::SelectRows);
    tableView_->setEditTriggers(QAbstractItemView::NoEditTriggers);

    // 空状态 + 表格用 QStackedWidget 切换（index 0=表格，index 1=空状态）
    logStack_ = new QStackedWidget(this);
    logStack_->addWidget(tableView_);
    logStack_->addWidget(UiHelper::createEmptyState(
        ElaIconType::Terminal, "暂无日志", this));
    logStack_->setCurrentIndex(1);  // 初始为空状态

    // 组装到中心区域
    auto* centralWidget = new QWidget(this);
    auto* centerLayout = new QVBoxLayout(centralWidget);
    centerLayout->setContentsMargins(0, 0, 0, 0);
    centerLayout->setSpacing(UiHelper::kSpaceMD);
    centerLayout->addWidget(filterArea);
    centerLayout->addWidget(logStack_, 1);
    addCentralWidget(centralWidget, true, true, 0);

    connect(searchEdit_, &ElaLineEdit::textChanged, logModel_, &LogModel::setSearchText);

    connect(levelCombo_, &ElaComboBox::currentIndexChanged, this, [this](int index) {
        LogLevel level = LogLevel::Debug;
        switch (index) {
            case 1: level = LogLevel::Debug; break;
            case 2: level = LogLevel::Info; break;
            case 3: level = LogLevel::Warn; break;
            case 4: level = LogLevel::Error; break;
            default: level = LogLevel::Debug; break;
        }
        logModel_->setFilterLevel(level);
    });

    connect(clearButton_, &ElaPushButton::clicked, logModel_, &LogModel::clear);

    // 根据日志条目数量切换空状态 / 表格视图
    auto updateLogStack = [this]() {
        logStack_->setCurrentIndex(logModel_->rowCount() == 0 ? 1 : 0);
    };
    connect(logModel_, &QAbstractItemModel::rowsInserted, this, updateLogStack);
    connect(logModel_, &QAbstractItemModel::modelReset, this, updateLogStack);

    connect(exportButton_, &ElaPushButton::clicked, this, [this]() {
        QString defaultName = "wekey-skf-" + QDate::currentDate().toString("yyyyMMdd") + ".log";
        QString destPath = QFileDialog::getSaveFileName(
            this, "导出日志", defaultName, "日志文件 (*.log);;所有文件 (*)");
        if (destPath.isEmpty()) {
            return;
        }
        QString result = Logger::instance().exportLog(destPath);
        if (result.isEmpty()) {
            MessageBox::error(this, "导出失败", "无法读取或写入日志文件");
        } else {
            bool compressed = result.endsWith(".zz");
            QString msg = compressed
                ? QString("已压缩导出至: %1").arg(result)
                : QString("已导出至: %1").arg(result);
            MessageBox::info(this, "导出成功", msg);
        }
    });
}

}  // namespace wekey
