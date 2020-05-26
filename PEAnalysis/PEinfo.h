#ifndef PEINFO_H
#define PEINFO_H

class PEinfo {
public:

    static QString pe_name;
    static qint32 pe_section;
    static QStringList pe_digest;
};
// init static member
QString PEinfo::pe_name = "";
qint32  PEinfo::pe_section = -1;
QStringList PEinfo::pe_digest;

#endif // PEINFO_H
