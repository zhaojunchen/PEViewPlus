#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "PE.h"
#include "treemodel.h"
#include <QStandardItemModel>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    setWindowState(Qt::WindowMaximized);

    ui->setupUi(this);
    setCentralWidget(ui->splitter);
    ui->splitter->setStretchFactor(0, 1);
    ui->splitter->setStretchFactor(1, 5);

    // 不可编辑
    ui->tableView->setEditTriggers(QAbstractItemView::NoEditTriggers);

    // 选中一行而非的那个单元格
    ui->tableView->setSelectionBehavior(QAbstractItemView::SelectRows);

    // 列宽随内容变化
    ui->tableView->horizontalHeader()->setSectionResizeMode(
        QHeaderView::ResizeToContents);


    // 取消网格线
    ui->tableView->setShowGrid(false);
    ui->tableView->horizontalHeader()->setHighlightSections(false);
    ui->tableView->verticalHeader()->setHidden(true);

    QStandardItemModel *model = new QStandardItemModel(this);
    PE   pe("C:\\Users\\zjc98\\Desktop\\leetcode32R.exe");
    auto node = pe.init_pe_file();
    QStandardItem *p;

    model->setColumnCount(3);

    model->setHeaderData(0, Qt::Horizontal, QString("Addr"));
    model->setHeaderData(1, Qt::Horizontal, QString("Data"));
    model->setHeaderData(2, Qt::Horizontal, QString("Value"));

    for (int i = 0; i < node->addr.size(); i++) {
        p = new QStandardItem(node->addr[i]);
        model->setItem(i, 0, new QStandardItem(node->addr[i]));
        model->setItem(i, 1, new QStandardItem(node->data[i]));
        model->setItem(i, 2, new QStandardItem(node->value[i]));
    }

    ui->tableView->setModel(model);

    // ui->treeView->setModel();
}

MainWindow::~MainWindow()
{
    delete ui;
}
