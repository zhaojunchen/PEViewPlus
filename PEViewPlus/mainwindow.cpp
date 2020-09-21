#include "mainwindow.h"
#include "treeitem.h"
#include "ui_mainwindow.h"
#include "Disassembly.h"
#include "PeInject.h"
#include "reloc.h"

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    // 添加图标，有意者可以更换
    setWindowIcon(QIcon(":/pic/logo.png"));
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
    ui->tableView->setModel(tableModel);
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::on_actionopen_triggered()
{
    // 弹出打开文件对话框
    QString curPath = QDir::currentPath();       // 获取系统当前目录
    QString title = "Please Open .dll or .exe "; // 对话框标题
    QString filter = "PE File(*exe *dll)";       // 文件过滤器

    this->file = QFileDialog::getOpenFileName(this, title, curPath, filter);

    if (MainWindow::file.isEmpty()) {
        return;
    }

    // 通过记录上次打开的文件、避免重复打开相同的文件

    if (lastFileName == file) {
        return;
    } else {
        // 判断是否是一个有效的win32、win64 PE文件
        int ret = PE::file_isPE(file);

        if (ret == 0) {
            QMessageBox::critical(this,
                                  "File is not a PE type file",
                                  "Please open a real PE file");
            return;
        }
#ifndef _WIN64

        if (ret == 64) {
            QMessageBox::critical(this,
                                  "PE file bits64",
                                  "File is a 64 bits PE file, Please open it in PEViewPlus64");
            return;
        }

#else // ifndef _WIN64

        if (ret == 32) {
            QMessageBox::critical(this,
                                  "PE file bits32",
                                  "File is a 32 bits PE file, Please open it in PEViewPlus32");
            return;
        }

#endif // ifndef _WIN64

        lastFileName = file;
    }
    cout << file;


    // file有效，准备打开新的文件
    // 打开之前判断文件是否是一个有效的32位文件


    // 打开之前的清理工作
    // 清理PE结构，回收其分配的new
    if (this->pe != nullptr) {
        delete this->pe;
        this->pe = nullptr;
    }

    // 清理treeModel
    if (treeModel != nullptr) {
        // 具体的没有编写清除的方法，只有将其回收，并且新new一个
        delete treeModel;
        treeModel = nullptr;
    }

    // 清除treeView的显示
    ui->treeView->setModel(nullptr);

    // 清理tableModel的内容
    tableModel->clear();

    // 清理tableView的显示
    ui->tableView->update();

    // 初始化操作
    pe = new PE(file);
    Test(pe);

    // 优化自己点击自己、造成的TableView刷新开销
    lastClick = 0;

    // 自动展示首个节点
    auto node = pe->nodes[0];

    // 载入初始化tableModel显示

    tableModel->setColumnCount(3);

    tableModel->setHeaderData(0, Qt::Horizontal, QString("Addr"));
    tableModel->setHeaderData(1, Qt::Horizontal, QString("Data"));
    tableModel->setHeaderData(2, Qt::Horizontal, QString("Value"));


    for (int i = 0; i < node->addr.size(); i++) {
        tableModel->setItem(i, 0, new QStandardItem(node->addr[i]));
        tableModel->setItem(i, 1, new QStandardItem(node->data[i]));
        tableModel->setItem(i, 2, new QStandardItem(node->value[i]));
    }

    treeModel = new TreeModel(pe->getPeTreeList());
    ui->treeView->setModel(treeModel);

    //    自动展开 treeView
    ui->treeView->expandAll();
}

void MainWindow::on_actionClose_triggered()
{
    // no file is opened
    if (file == "") {
        return;
    }
    file = "";
    lastFileName = "";


    if (this->pe != nullptr) {
        delete this->pe;
        this->pe = nullptr;
    }

    // 清理treeModel
    if (treeModel != nullptr) {
        // 具体的没有编写清除的方法，只有将其回收，并且新new一个
        delete treeModel;
        treeModel = nullptr;
    }

    // 清除treeView的显示
    ui->treeView->setModel(nullptr);

    // 清理tableModel的内容
    tableModel->clear();

    // 清理tableView的显示
    ui->tableView->update();
}

void MainWindow::on_actionExit_triggered()
{
    qApp->quit();
}

void MainWindow::on_actionAbout_triggered()
{
    QString title = "PEViewPlus";
    QString info =
        "github: https://github.com/zhaojunchen/PEViewPlus";

    QMessageBox::about(this,
                       title,
                       info);
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

void MainWindow::on_actionDisassembly_triggered()
{
    if (pe == nullptr) return;

    /*auto sizeOfCode = pe->nt_header->OptionalHeader.SizeOfCode; // 实际代码
       auto baseOfCode = pe->nt_header->OptionalHeader.BaseOfCode; // RVA
       auto RVA = baseOfCode;
       auto p = pe->section_header;

       for (int i = 0; i < pe->nt_header->FileHeader.NumberOfSections; i++) {
        if ((RVA >= p->VirtualAddress) &&
            (RVA < (p->VirtualAddress + p->SizeOfRawData))) {
            break;
        }
        p++;
       }
       auto dis = p->VirtualAddress - p->PointerToRawData;
       auto file_offset = baseOfCode - dis;

       auto disas =
        code_disassembly((us *)(pe->content + file_offset), sizeOfCode, 0);*/
    QByteArray codeBlock = pe->getCodeBlock();

    auto disas = code_disassembly((us *)codeBlock.data(), codeBlock.size(), 0);
    dialogDecompiler = new DialogDecompiler(this, disas);

    dialogDecompiler->setModal(true);
    dialogDecompiler->show();
}

void MainWindow::on_actionAboutQt_triggered()
{
    QMessageBox::aboutQt(this);
}

void MainWindow::on_actionFont_triggered()
{
    // 弹出打开文件对话框
    QString curPath = QDir::currentPath();       // 获取系统当前目录
    QString title = "Please Open .dll or .exe "; // 对话框标题
    QString filter = "PE File(*exe *dll)";       // 文件过滤器
    QString orinalFile =
        QFileDialog::getOpenFileName(this, title, curPath, filter);

    if (orinalFile.isNull() || orinalFile.isEmpty()) {
        QMessageBox::critical(this, "Error", "You should choose a pe file");
    }

    if (PE::file_isPE(orinalFile) == 0) {
        QMessageBox::critical(this, "", "This is not a pe file");
        return;
    }

    QFileInfo orinalFileInfo(orinalFile);


    QString saveFile = QFileDialog::getSaveFileName(this,
                                                    "choose saved file",
                                                    orinalFileInfo.path(),
                                                    filter);


    if (!saveFile.isEmpty()) {
        if (saveFile == orinalFile) {
            QMessageBox::critical(this, "",
                                  "Please create a another file to save");
            return;
        } else {
            QFileInfo info(saveFile);

            if (info.isFile()) {
                QMessageBox::critical(this,
                                      "",
                                      "Please choose an another not exists file to save");
                return;
            }
        }
        int ret = inject(orinalFile, saveFile);

        if (ret == 0) {
            QMessageBox::information(this, "Success", "PE file inject success");
        } else {
            QMessageBox::information(this,
                                     "Oh my god",
                                     "PE file inject failed, Some error occur!!!");
        }
    } else {
        QMessageBox::warning(this,
                             "",
                             "You should choose a file name to save this content");
        return;
    }

    //    打开文件
}

void MainWindow::on_actionPEInfo_triggered()
{
    //    if (pe == nullptr) return;

    ////    dialogDecompiler = new DialogDecompiler(this, peinfo(this->file));
    //    dialogDecompiler->setModal(true);
    //    dialogDecompiler->show();
}
