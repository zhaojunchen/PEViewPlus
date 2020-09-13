#ifndef PCH_H
#define PCH_H

/* Add C++ includes here */

#include <QCoreApplication>
#include <QList>

#include <QObject>
#include <QRegExp>


#include <QTextCodec>
#include <QPointer>
#include <QScopedPointer>
#include <QSharedPointer>
#include <QtAlgorithms>
#include <QDebug>
#include <QMainWindow>
#include <QString>
#include <QFileDialog>
#include <QMessageBox>
#include <QSplitter>
#include <QPushButton>
#include <QVector>
#include <QAbstractItemModel>
#include <QModelIndex>
#include <QVariant>
#include <QApplication>
#include <QFile>
#include <QTreeView>
#include <QStringList>
#include <QLabel>
#include <QStandardItemModel>
#include <QItemSelectionModel>
#include <QMessageBox>
#include <QDialog>


#include <Windows.h>
#include <winnt.h>
#include <fstream>
#include <iostream>
#include <unordered_map>
#include <unordered_set>
#include <string>
#include <vector>

#define cout qDebug()
#define Addr(value, size) QString("  %1  ").arg((value), (size) << 1, 16, \
                                                QChar('0')).toUpper()

typedef  unsigned char us;

using std::string;
using std::ios;
using std::ifstream;
using std::ofstream;
using std::map;
using std::unordered_map;
using std::vector;

#endif // PCH_H
