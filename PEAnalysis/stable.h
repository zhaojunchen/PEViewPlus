/** precompile header*/

/* Add C includes here */

#if defined __cplusplus

/* Add C++ includes here */
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
#define cout qDebug()
#define Addr(value, size) QString("%1").arg((value), (size) << 1, 16, \
    QChar('0')).toUpper()
typedef  unsigned char us;

using std::string;
using std::ios;
using std::ifstream;
using std::ofstream;
using std::map;


#endif // if defined __cplusplus
