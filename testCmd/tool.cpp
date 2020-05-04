#include"tool.h"
/**
 * debug __LINE__
 * */
void error(QString msg, int line) {
    if (line != 0) {
        qCritical() << "LINE " << line << " ERROR:" << msg << endl;
    } else {
        qCritical() << "ERROR:" << msg << endl;
    }
}

void report(QString msg, int line) {
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

