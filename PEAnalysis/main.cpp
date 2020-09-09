#include "details.h"
#include "PEAnalysis.h"
#include "PEinfo.h"
int main(int argc, char *argv[]) {
#ifndef _WIN64
    QCoreApplication    a(argc, argv);
    QVector<QByteArray> t = init("C:/test.exe");


    cout << PEinfo::pe_section;
    PEinfo::pe_digest.push_back("PEname");


    // init_listView();
    details detail = init_option_header(0x400110, t[3]);
    cout << PEinfo::pe_section;

    //    for (int i = 0; i < detail.va.size(); ++i) {
    //        if (detail.type == 1) {
    //            cout << detail.va[i] << "\t " << detail.data[i] << "\t" <<
    //                detail.desc[i] << "\t" << detail.value[i];
    //        } else {
    //            cout << detail.va[i] << "\t " << detail.data[i] << "\t" <<
    //                detail.desc[i];
    //        }


    //        /*qDebug("%s %s %s", detail.va[i], detail.data[i],
    // detail.desc[i]);*/
    //    }

    QString desc =
        "EXPORT Table,IMPORT Table,RESOURCE Table,EXCEPTION Table,CERTIFICATE Table,BASE RELOCATION Table,DEBUG Directory,Architecture Specific Data,GLOBAL POINTER Register,TLS Table,LOAD CONFIGURATION Table,BOUND IMPORT Table,IMPORT Address table,DELAY IMPORT Descriptors,CLI Header,";
    QStringList s = desc.split(",");
    cout << s.length();


    //    cout << "it is msvc32!";
#else // ifndef _WIN64
      //    cout << "it is msvc64";
#endif // ifndef _WIN64
    printf("123");


    printf("%s", "\n end debug cout");

    return a.exec();
}
