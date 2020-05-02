#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QStringListModel>
namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow {
    Q_OBJECT

public:

    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:

    void on_treeView_clicked(const QModelIndex& index);

    void on_actionOpen_triggered();

private:

    Ui::MainWindow *ui;
    QStringListModel *stringMode1;
    QStringListModel *stringMode2;
    QStringListModel *stringMode3;
    QStringListModel *stringMode4;
};

#endif // MAINWINDOW_H
