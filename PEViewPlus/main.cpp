#include "mainwindow.h"
#include <QApplication>
#include <QDebug>
#include "include/add.h"
int main(int argc, char *argv[])
{
#if (QT_VERSION >= QT_VERSION_CHECK(5, 9, 0))
    QApplication::setAttribute(Qt::AA_EnableHighDpiScaling);
#endif // if (QT_VERSION >= QT_VERSION_CHECK(5, 9, 0))


    QApplication a(argc, argv);
    MainWindow   w;


#ifndef _WIN64
    qDebug() << "32bit!\n";
#else // ifndef _WIN64
    qDebug() << "64bit!\n";
#endif // ifndef _WIN64


    int result = add(1, 3);
    qDebug() << result;

    w.show();


    return a.exec();
}
