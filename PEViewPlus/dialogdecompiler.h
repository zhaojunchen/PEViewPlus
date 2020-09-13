#ifndef DIALOGDECOMPILER_H
#define DIALOGDECOMPILER_H

#include <QDialog>

namespace Ui {
class DialogDecompiler;
}

class DialogDecompiler : public QDialog {
    Q_OBJECT

public:

    explicit DialogDecompiler(QWidget *parent,
                              QString  _decomplier_string);
    ~DialogDecompiler();

private:

    Ui::DialogDecompiler *ui;
    QString decomplier_stirng;
};

#endif // DIALOGDECOMPILER_H
