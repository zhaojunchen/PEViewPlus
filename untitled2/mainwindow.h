
#include "PE.h"
#include "treemodel.h"
#ifndef MAINWINDOW_H
# define MAINWINDOW_H


QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow {
    Q_OBJECT

public:

    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:

    void on_treeView_clicked(const QModelIndex& index);

private:

    Ui::MainWindow *ui = nullptr;
    QStandardItemModel *tableModel = nullptr;
    TreeModel *treeModel = nullptr;
    PE *pe = nullptr;
    int lastClick = -1;
    void refreshTableModel(Node *node);
};
#endif // MAINWINDOW_H
