#include "mainwindow.h"
#include <QApplication>
#include <QDebug>
int main(int argc, char *argv[])
{
#if (QT_VERSION >= QT_VERSION_CHECK(5, 9, 0))
    QApplication::setAttribute(Qt::AA_EnableHighDpiScaling);
#endif // if (QT_VERSION >= QT_VERSION_CHECK(5, 9, 0))
    QApplication a(argc, argv);
    MainWindow   w;


    w.show();

    return a.exec();
}
