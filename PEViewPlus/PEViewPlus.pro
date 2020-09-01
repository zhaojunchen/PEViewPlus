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

CONFIG += c++11

SOURCES += \
        main.cpp \
        mainwindow.cpp \
        treeitem.cpp \
        treemodel.cpp

HEADERS += \
        include/Disassembly.h \
        include/add.h \
        mainwindow.h \
        pch.h \
        treeitem.h \
        treemodel.h

FORMS += \
        mainwindow.ui

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target


# STATIC LIB ctrl+f to find $$PWD/x64(if 64 bit else fdo nothing) and replace them with $$PWD/x64

#win32:CONFIG(release, debug|release): LIBS += -L$$PWD/x64/ -lStaticLib
#else:win32:CONFIG(debug, debug|release): LIBS += -L$$PWD/x64/ -lStaticLibd

#INCLUDEPATH += $$PWD/x64
#DEPENDPATH += $$PWD/x64

#win32-g++:CONFIG(release, debug|release): PRE_TARGETDEPS += $$PWD/x64/libStaticLib.a
#else:win32-g++:CONFIG(debug, debug|release): PRE_TARGETDEPS += $$PWD/x64/libStaticLibd.a
#else:win32:!win32-g++:CONFIG(release, debug|release): PRE_TARGETDEPS += $$PWD/x64/StaticLib.lib
#else:win32:!win32-g++:CONFIG(debug, debug|release): PRE_TARGETDEPS += $$PWD/x64/StaticLibd.lib

#win32:CONFIG(release, debug|release): LIBS += -L$$PWD/x64/ -lDisassembly
#else:win32:CONFIG(debug, debug|release): LIBS += -L$$PWD/x64/ -lDisassemblyd

#INCLUDEPATH += $$PWD/x64
#DEPENDPATH += $$PWD/x64

#win32-g++:CONFIG(release, debug|release): PRE_TARGETDEPS += $$PWD/x64/libDisassembly.a
#else:win32-g++:CONFIG(debug, debug|release): PRE_TARGETDEPS += $$PWD/x64/libDisassemblyd.a
#else:win32:!win32-g++:CONFIG(release, debug|release): PRE_TARGETDEPS += $$PWD/x64/Disassembly.lib
#else:win32:!win32-g++:CONFIG(debug, debug|release): PRE_TARGETDEPS += $$PWD/x64/Disassemblyd.lib
