#-------------------------------------------------
#
# Project created by QtCreator 2020-04-28T13:40:54
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = PEViewPlus

#   添加 预编译
PRECOMPILED_HEADER = pch.h

TEMPLATE = app
# https://blog.csdn.net/huhaowa/article/details/82822109
QMAKE_CXXFLAGS_RELEASE = -O2 -MD -GL
QMAKE_CXXFLAGS_DEBUG = -Zi -MDd

# The following define makes your compiler emit warnings if you use
# any feature of Qt which has been marked as deprecated (the exact warnings
# depend on your compiler). Please consult the documentation of the
# deprecated API in order to know how to port your code away from it.
DEFINES += QT_DEPRECATED_WARNINGS
# WIN64 is 64 bits
# You can also make your code fail to compile if you use deprecated APIs.
# In order to do so, uncomment the following line.
# You can also select to disable deprecated APIs only up to a certain version of Qt.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

CONFIG += c++17

SOURCES += \
        dialogdecompiler.cpp \
        main.cpp \
        mainwindow.cpp \
        treeitem.cpp \
        treemodel.cpp \
        uthenticode.cpp

HEADERS += \
        Disassembly.h \
        PE.h \
        PeInject.h \
        dialogdecompiler.h \
        mainwindow.h \
        pch.h \
        treeitem.h \
        treemodel.h \
        uthenticode.h

FORMS += \
        dialogdecompiler.ui \
        mainwindow.ui

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target

RESOURCES += \
    logo.qrc

LIB_VERSION = x86
DEFINES += LIB_VERSION
INCLUDEPATH += $$PWD/include/
INCLUDEPATH += $$PWD/lib/

LIBS += $$PWD/lib/$$LIB_VERSION/openssl/openssl.lib
LIBS += $$PWD/lib/$$LIB_VERSION/openssl/libcrypto_static.lib
LIBS += $$PWD/lib/$$LIB_VERSION/windows/WS2_32.lib
LIBS += $$PWD/lib/$$LIB_VERSION/windows/User32.lib
LIBS += $$PWD/lib/$$LIB_VERSION/windows/AdvAPI32.lib
LIBS += $$PWD/lib/$$LIB_VERSION/capstone/capstone_static.lib


