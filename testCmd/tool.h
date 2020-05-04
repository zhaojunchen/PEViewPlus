#ifndef TOOL_H
#define TOOL_H

#include <QDebug>
#include <QString>
// error only for debug
void error(QString msg, int line = 0);
void report(QString msg, int line = 0);

void show(void *src, int size);
#endif // TOOL_H
