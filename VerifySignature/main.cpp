#include <QtCore/QCoreApplication>
#include<qdebug.h>

int main(int argc, char *argv[])
{
	QCoreApplication a(argc, argv);
	QDebug() << "sfy";

	return a.exec();
}
