#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "treemodel.h"
#include "treeitem.h"

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    setWindowState(Qt::WindowMaximized);

    ui->setupUi(this);
    setCentralWidget(ui->splitter);
    ui->splitter->setStretchFactor(0, 1);
    ui->splitter->setStretchFactor(1, 4);

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

    tableModel = new QStandardItemModel(this);

    //    QString filePath = "C:\\Users\\zjc98\\Desktop\\leetcode32R.exe";

    QString filePath = "C:\\Users\\zjc98\\Desktop\\twain_32.dll";
    pe = new PE(filePath);
    auto node = pe->nodes[0];
    QStandardItem *p;

    tableModel->setColumnCount(3);

    tableModel->setHeaderData(0, Qt::Horizontal, QString("Addr"));
    tableModel->setHeaderData(1, Qt::Horizontal, QString("Data"));
    tableModel->setHeaderData(2, Qt::Horizontal, QString("Value"));


    for (int i = 0; i < node->addr.size(); i++) {
        p = new QStandardItem(node->addr[i]);
        tableModel->setItem(i, 0, new QStandardItem(node->addr[i]));
        tableModel->setItem(i, 1, new QStandardItem(node->data[i]));
        tableModel->setItem(i, 2, new QStandardItem(node->value[i]));
    }

    ui->tableView->setModel(tableModel);

    treeModel = new TreeModel(pe->treeList);

    ui->treeView->setModel(treeModel);
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::on_treeView_clicked(const QModelIndex& index)
{
    if (!index.isValid()) return;

    TreeItem *item = static_cast<TreeItem *>(index.internalPointer());

    auto clickIndex = item->data(1).value<int>();

    if (lastClick != clickIndex) {
        refreshTableModel(pe->nodes[item->data(1).value<int>()]);
        lastClick = clickIndex;
        qDebug() << item->data(1);
    }
}

void MainWindow::refreshTableModel(Node *node)
{
    this->tableModel->clear();

    if (node->hasDesc) {
        tableModel->setColumnCount(4);
        tableModel->setHeaderData(0, Qt::Horizontal, QString("Addr"));
        tableModel->setHeaderData(1, Qt::Horizontal, QString("Data"));
        tableModel->setHeaderData(2, Qt::Horizontal, QString("Desc"));
        tableModel->setHeaderData(3, Qt::Horizontal, QString("Value"));

        for (int i = 0; i < node->addr.size(); i++) {
            tableModel->setItem(i, 0, new QStandardItem(node->addr[i]));
            tableModel->setItem(i, 1, new QStandardItem(node->data[i]));
            tableModel->setItem(i, 2, new QStandardItem(node->desc[i]));
            tableModel->setItem(i, 3, new QStandardItem(node->value[i]));
        }
    } else {
        tableModel->setColumnCount(3);
        tableModel->setHeaderData(0, Qt::Horizontal, QString("Addr"));
        tableModel->setHeaderData(1, Qt::Horizontal, QString("Data"));
        tableModel->setHeaderData(2, Qt::Horizontal, QString("Value"));


        for (int i = 0; i < node->addr.size(); i++) {
            tableModel->setItem(i, 0, new QStandardItem(node->addr[i]));
            tableModel->setItem(i, 1, new QStandardItem(node->data[i]));
            tableModel->setItem(i, 2, new QStandardItem(node->value[i]));
        }
    }
    ui->tableView->update();
}
