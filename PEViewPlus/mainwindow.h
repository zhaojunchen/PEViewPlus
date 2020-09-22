#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include "PE.h"
#include "dialogdecompiler.h"
#include "treemodel.h"


namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow {
    Q_OBJECT

public:

    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();
    QString file = "";

private slots:

    void on_actionopen_triggered();

    void on_actionClose_triggered();

    void on_actionExit_triggered();

    void on_actionAbout_triggered();

    void on_treeView_clicked(const QModelIndex& index);

    void on_actionDisassembly_triggered();

    void on_actionAboutQt_triggered();

    void on_actionFont_triggered();

    void on_actionPEInfo_triggered();

    void on_actionSignature_triggered();

    void on_actionImageBase_triggered();

private:

    Ui::MainWindow *ui = nullptr;
    QStandardItemModel *tableModel = nullptr;
    TreeModel *treeModel = nullptr;
    PE *pe = nullptr;
    int lastClick = 0;
    QString lastFileName = "";
    DialogDecompiler *dialogDecompiler;


    void refreshTableModel(Node *node);
};


#endif // MAINWINDOW_H
