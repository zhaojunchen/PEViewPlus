#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>


namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow {
    Q_OBJECT

public:

    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();
    static QString file;

private slots:

    void on_actionopen_triggered();

    void on_actionClose_triggered();

    void on_actionExit_triggered();

    void on_actionAbout_triggered();

private:

    Ui::MainWindow *ui;
};


#endif // MAINWINDOW_H
