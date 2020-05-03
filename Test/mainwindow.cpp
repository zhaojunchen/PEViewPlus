#include "mainwindow.h"
#include "treemodel.h"
#include "ui_mainwindow.h"
#include <QDebug>
#include <QFile>
#include <QMessageBox>
#include <treeitem.h>

// todo Qbyte array https://blog.csdn.net/ecourse/article/details/80575691

MainWindow::MainWindow(QWidget *parent, int newParameter) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    setCentralWidget(ui->splitter);

    // 设置不可见属性 控件完全不可见
    ui->listView->setVisible(false);
    ui->label->setVisible(false);

    // 1.
    QStringList stringList1;
    QStringList stringList2;
    QStringList stringList3;
    QStringList stringList4;
    stringList1 << "wuhan" << "daxue" << "liujiao" << "zhongshan";
    stringList2 = stringList3 = stringList4 = stringList1;
    stringMode1 = new QStringListModel(this);
    stringMode1->setStringList(stringList1);
    ui->listView->setModel(stringMode1);

    // 设置可以编辑
    ui->listView->setEditTriggers(QAbstractItemView::NoEditTriggers);

    stringMode2 = new QStringListModel(this);
    stringMode2->setStringList(stringList2);
    ui->listView_2->setModel(stringMode1);
    ui->listView_2->setEditTriggers(QAbstractItemView::NoEditTriggers);
    stringMode3 = new QStringListModel(this);
    stringMode3->setStringList(stringList3);
    ui->listView_3->setModel(stringMode1);
    ui->listView_3->setEditTriggers(QAbstractItemView::NoEditTriggers);
    stringMode4 = new QStringListModel(this);
    stringMode4->setStringList(stringList4);
    ui->listView_4->setModel(stringMode1);
    ui->listView_4->setEditTriggers(QAbstractItemView::NoEditTriggers);

    //    stringList4.append(QString::number(123123, 16));
    //    chBuf[20] = "wuhandaxue1";
    //    // 字符串转换问题 QString::number(123123, 16)
    //    QByteArray::toHex();
    //    string key;
    //    sprintf(c,"%02x ");
    //    key = QString::fromUtf8(chBuf);

    //    if (stringMode4 != nullptr) {
    //        delete stringMode4;
    //    }
    //    stringMode4 = new QStringListModel(stringList4);
    //    ui->listView->setModel(stringMode4);

    // 刷新listView
    stringMode4->setStringList(stringList4);
    ui->listView_4->setModel(stringMode4);

    //
    //  ui->splitter->setStretchFactor(0 , 1);
    //    ui->splitter->setStretchFactor(1, 20);


    //    setCentralWidget(ui->splitter);

    QFile file(":/default.txt");

    if (file.open(QIODevice::ReadOnly))
    {
        qDebug() << "open ok!";
    }
    else
    {
        qDebug() << file.error();
        qDebug() << file.errorString();
    }

    //    在堆上分配内存
    TreeModel *model = new TreeModel(file.readAll());
    file.close();
    ui->treeView->setModel(model);

    //    ui->treeView->show();

    //    for (int column = 0; column < model->columnCount();
    //         ++column) ui->treeView->resizeColumnToContents(column);
}

MainWindow::~MainWindow()
{
    delete ui;
}

// 点击事件 起始下表 RVA
void MainWindow::on_treeView_clicked(const QModelIndex& index)
{
    TreeItem *t = static_cast<TreeItem *>(index.internalPointer());

    ui->label_2->setText(t->data(0).value<QString>());
}

void MainWindow::on_actionOpen_triggered()
{
    QMessageBox::information(this, "TIPS", "Open File");
}
