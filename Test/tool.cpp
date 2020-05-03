#ifndef TOOL_CPP
#define TOOL_CPP

#include <QDebug>
#include <QString>

/**
 * debug __LINE__ 出现错误的行号
 * */
void error(QString msg, int line = 0) {
    if (line != 0) {
        qCritical() << "LINE " << line << " ERROR:" << msg << endl;
    } else {
        qCritical() << "ERROR:" << msg << endl;
    }
}

void report(QString msg, int line = 0) {
    if (line != 0) {
        qDebug() << "LINE " << line << " ERROR:" << msg << endl;
    } else {
        qDebug() << "Message: " << msg << endl;
    }
}

/** 输入指针 输入大小
 *  输出指针内容的byte!
 *  */
void show(void *src, int size) {
    char *p = (char *)src;

    for (int i = 0; i < size; i++) {
        if (i % 16 == 0) {
            qDebug() << endl;
        }
        qDebug("%02x ", (unsigned char)*p);
        p++;
    }
}
# endif
