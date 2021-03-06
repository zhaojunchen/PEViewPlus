#include "mainwindow.h"

#include "Disassembly.h"
int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    MainWindow   w;

    w.show();
    unsigned char code_32[72] = {
        0x31, 0xD2, 0x52, 0x68, 0x63, 0x61, 0x6C, 0x63, 0x54, 0x59, 0x52, 0x51,
        0x64, 0x8B, 0x72, 0x30,
        0x8B, 0x76, 0x0C, 0x8B, 0x76, 0x0C, 0xAD, 0x8B, 0x30, 0x8B, 0x7E, 0x18,
        0x8B, 0x5F, 0x3C, 0x8B,
        0x5C, 0x3B, 0x78, 0x8B, 0x74, 0x1F, 0x20, 0x01, 0xFE, 0x8B, 0x54, 0x1F,
        0x24, 0x0F, 0xB7, 0x2C,
        0x17, 0x42, 0x42, 0xAD, 0x81, 0x3C, 0x07, 0x57, 0x69, 0x6E, 0x45, 0x75,
        0xF0, 0x8B, 0x74, 0x1F,
        0x1C, 0x01, 0xFE, 0x03, 0x3C, 0xAE, 0xFF, 0xD7
    };
    auto dis = code_disassembly((unsigned char *)code_32, 72);
    cout << dis;

    return a.exec();
}
