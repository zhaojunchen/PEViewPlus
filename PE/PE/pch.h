#pragma once

/* Add C++ includes here */
#include <QtCore/QCoreApplication>
#include <iostream>
#include <Windows.h>
#include <winnt.h>
#include <QDebug>
#include <fstream>
#include <iostream>
#include <string>
#include <QCoreApplication>
#include <QList>
#include <QVariant>
#include <QObject>
#include <QRegExp>
#include <QString>
#include <QStringList>
#include <QTextCodec>
#include <QPointer>
#include <QScopedPointer>
#include <QSharedPointer>
#include <QDebug>
#include <unordered_map>
#include <vector>
#include <unordered_set>
#include <QtAlgorithms>

#define cout qDebug()
#define Addr(value, size) QString("%1").arg((value), (size) << 1, 16, \
    QChar('0')).toUpper()

typedef  unsigned char us;

using std::string;
using std::ios;
using std::ifstream;
using std::ofstream;
using std::map;
using std::unordered_map;
using std::vector;
void error(QString message) {
	qDebug() << "error message";
	exit(-1);
}
void show(void *src, int size) {
	char *p = (char *)src;

	for (int i = 0; i < size; i++) {
		if (i % 16 == 0) {
			printf("\n");
		}
		printf("%02X ", static_cast<unsigned char>(*p));
		p++;
	}
}
