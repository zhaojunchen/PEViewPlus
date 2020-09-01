#include "mainwindow.h"
#include "ui_mainwindow.h"

QString MainWindow::file = "C:/test.exe";

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    setCentralWidget(ui->splitter);
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::on_actionopen_triggered()
{
    //    QString curPath=QDir::currentPath();//获取系统当前目录
    QString path = "C:/";
    QString title = "选择PE文件";                // 对话框标题
    QString filter = "PE文件(*exe *dll *lib)"; // 文件过滤器
    MainWindow::file = QFileDialog::getOpenFileName(this, title, path, filter);
    if(MainWindow::file.isEmpty()){
        return;
    }
}

void MainWindow::on_actionClose_triggered()
{
    //    todo  清除内容
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
