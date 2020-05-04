#include <QCoreApplication>
#include "tool.h"
typedef uint8_t us;

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);

    us *c = new us[20];

    memcpy(c, "wuhadnaxu1", 10);
    qDebug("wuhandaxue");
    qDebug("zjc");
    qDebug() << "zjc";
    qDebug() << "zjc";



    show(c, 16);

    return a.exec();
}
