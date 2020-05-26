#ifndef DATA_H
#define DATA_H

class details {
public:
    bool type;// false is rawdata
    QStringList va;
    QStringList data;
    QStringList value;
    QStringList desc;
    details(bool _type = false) :type(_type) {}
    ~details() {}
};

#endif // DATA_H
