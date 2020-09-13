#include "dialogdecompiler.h"
#include "ui_dialogdecompiler.h"

DialogDecompiler::DialogDecompiler(QWidget *parent, QString  _decomplier_string) :
    QDialog(parent),
    ui(new Ui::DialogDecompiler), decomplier_stirng(_decomplier_string)
{
    ui->setupUi(this);

    ui->textBrowser->setText(decomplier_stirng);
    setWindowTitle("Decompiler");

}

DialogDecompiler::~DialogDecompiler()
{
    delete ui;
}
