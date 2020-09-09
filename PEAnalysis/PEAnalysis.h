#ifndef PEANALYSIS_H
#define PEANALYSIS_H

#include "details.h"
#include "tools.h"
#include "PEinfo.h"

// PE文件解构 https://blog.csdn.net/adam001521/article/details/84658708
// Qt Hex View
#ifndef __WIN64

details init_rawData(int               startVa,
                     const QByteArray& byte);

// 二进制byte数组转化为可显示的字符串
QStringList QByteArrayToACSIIString(const QByteArray& byte);


// 原始数据显示
details init_rawData(int startVa, const QByteArray& byte) {
    details b;
    auto    byteSize = byte.size();
    int     turn = (byteSize % 16 == 0) ? byteSize / 16 : byteSize / 16 + 1;

    // VA init
    for (int i = 0; i < turn; i++) {
        b.va.append(Addr(startVa, 4));
        startVa += 16;
    }

    // RAW init
    QString raw = byte.toHex(' ').toUpper();

    // 48 QString QString::mid(int position, int n = -1) const
    int i;

    for (i = 0; i < turn - 1; ++i) {
        b.data.append(raw.mid(i * 48, 48));
    }

    b.data.append(raw.mid(i * 48));

    b.value = QByteArrayToACSIIString(byte);

    return b;
}

QVector<QByteArray>init(const QString& _file) {
    const string file = _file.toStdString();

    ifstream in (file, ios::binary);

    if (!in) {
        perror("file open error");
        exit(-1);
    }
    QVector<QByteArray> result;

    in.seekg(0, in.end);
    const size_t fileSize = in.tellg();
    in.seekg(0, in.beg); // 定位到文件开始
    us *content = new us[fileSize];
    memset(content, 0, fileSize);
    in.read(reinterpret_cast<char *>(content), fileSize);
    in.close();
    bool ispe32 = isPE32(content);
    bool ispe64 = isPE64(content);

    if (!ispe32 && ispe64) {
        cout << "The File is not a PE file";
        exit(-1);
    }

    if (ispe64) {
        cout << "The file is pe64 please open it with pe64";
        exit(-1);
    }

    // PE FILE
    QByteArray peFile((char *)content, fileSize);
    result.push_back(peFile);

    // DOS HEADER
    PIMAGE_DOS_HEADER pimage_dos_header = (PIMAGE_DOS_HEADER)content;

    QByteArray dosHeader((char *)content, sizeof(IMAGE_DOS_HEADER));
    result.push_back(dosHeader);

    // DOS dosStub
    QByteArray dosStub(((char *)pimage_dos_header + sizeof(IMAGE_DOS_HEADER)),
                       pimage_dos_header->e_lfanew - sizeof(IMAGE_DOS_HEADER));
    result.push_back(dosStub);

    // NT HEADER
    PIMAGE_NT_HEADERS32 pimage_nt_headers32 =
        (PIMAGE_NT_HEADERS32)((char *)pimage_dos_header + pimage_dos_header->
                              e_lfanew);
    QByteArray ntHeader((char *)(pimage_nt_headers32),
                        sizeof(IMAGE_NT_HEADERS32));
    result.push_back(ntHeader);

    auto numberOfSection = pimage_nt_headers32->FileHeader.NumberOfSections;
    auto size_nt_header = sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) +
                          pimage_nt_headers32
                          ->FileHeader.SizeOfOptionalHeader;

    // section table
    PIMAGE_SECTION_HEADER pimage_section_header =
        (PIMAGE_SECTION_HEADER)((char *)pimage_nt_headers32 + size_nt_header);
    QVector<DWORD> rawSize(numberOfSection);
    QVector<DWORD> rawStart(numberOfSection);

    DWORD t;

    for (auto i = 0; i < numberOfSection; ++i) {
        QByteArray sectionHeader((char *)pimage_section_header,
                                 sizeof(IMAGE_SECTION_HEADER));
        t = pimage_section_header->SizeOfRawData;
        rawSize[i] = (t % 0x200 == 0) ? t : ((t / 0x200) + 1) * 0x200;
        rawStart[i] = pimage_section_header->PointerToRawData;
        pimage_section_header++;
        result.push_back(sectionHeader);
    }

    // section
    char *sectionStart = (char *)pimage_section_header;

    for (int i = 0; i < numberOfSection; ++i) {
        QByteArray section((char *)content + rawStart[i], rawSize[i]);
        sectionStart += rawSize[i];
        result.push_back(section);
    }
    delete[]content;
    return result;
}



QVector<details>init_listView() {
    QVector<QByteArray> raw = init("C:/test.exe");

    // DOS Header
    QByteArray pe_byte = raw.at(0);
    QByteArray dos_byte = raw.at(1);
    QByteArray stub_byte = raw.at(2);
    QByteArray nt_byte = raw.at(3);
    PIMAGE_DOS_HEADER   dos = (PIMAGE_DOS_HEADER)dos_byte.data();
    PIMAGE_NT_HEADERS32 nt = (PIMAGE_NT_HEADERS32)nt_byte.data();

    // DWORD signature = nt->Signature;
    IMAGE_FILE_HEADER file = nt->FileHeader;
    IMAGE_OPTIONAL_HEADER32 option = nt->OptionalHeader;
    QVector<PIMAGE_SECTION_HEADER> sectionTable;
    auto numberSection = file.NumberOfSections;

    QVector<PIMAGE_SECTION_HEADER> sectiontable;

    sectiontable.reserve(numberSection);

    for (int i = 0; i < numberSection; ++i) {
        PIMAGE_SECTION_HEADER p = (PIMAGE_SECTION_HEADER)raw.at(4 + i).data();
        sectiontable.push_back(p);
    }
    details b = init_rawData(0x400040, stub_byte);

    for (int i = 0; i < b.va.size(); ++i) {
        cout << b.va.at(i);
    }

    for (int i = 0; i < b.data.size(); ++i) {
        cout << b.data.at(i);
    }

    for (int i = 0; i < b.value.size(); ++i) {
        cout << b.value.at(i);
    }
    QVector<details> s;

    // 各位阶段初始化
    return s;
}

QStringList QByteArrayToACSIIString(const QByteArray& byte) {
    QStringList result;
    QString     s;

    s.reserve(16);
    char space = '.';
    char ch = byte.at(0);
    ch = (ch >= 0x20 && ch <= 0x7E) ? ch : space;
    s.append(ch);
    int i;

    for (i = 1; i < byte.size(); ++i) {
        if (i % 16 == 0) {
            result.push_back(s);
            s.clear();
        }
        ch = byte.at(i);

        if ((ch >= 0x20) && (ch <= 0x7E)) {
            s.append(ch);
        }
        else {
            s.append(space);
        }
    }

    if ((i % 16 != 0) && !s.isEmpty()) {
        result.push_back(s);
    }
    return result;
}

/*
 * 一些列初始化函数
 */

// DOS头数据初始化
details init_dosHeader(int startVa, QByteArray byte) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)byte.data();
    details detail(true);

    //  存储每一项的数据大小
    QVector<int> it_size;
    it_size.reserve(30);
    QVector<int> it_value;
    it_size.reserve(30);

    auto it0 = dos->e_magic;
    auto it1 = dos->e_cblp;
    auto it2 = dos->e_cp;
    auto it3 = dos->e_crlc;
    auto it4 = dos->e_cparhdr;
    auto it5 = dos->e_minalloc;
    auto it6 = dos->e_maxalloc;
    auto it7 = dos->e_ss;
    auto it8 = dos->e_sp;
    auto it9 = dos->e_csum;
    auto it10 = dos->e_ip;
    auto it11 = dos->e_cs;
    auto it12 = dos->e_lfarlc;
    auto it13 = dos->e_ovno;
    auto it14 = dos->e_res[0];
    auto it15 = dos->e_res[1];
    auto it16 = dos->e_res[2];
    auto it17 = dos->e_res[3];

    auto it18 = dos->e_oemid;
    auto it19 = dos->e_oeminfo;

    auto it20 = dos->e_res2[0];
    auto it21 = dos->e_res2[1];
    auto it22 = dos->e_res2[2];
    auto it23 = dos->e_res2[3];
    auto it24 = dos->e_res2[4];
    auto it25 = dos->e_res2[5];
    auto it26 = dos->e_res2[6];
    auto it27 = dos->e_res2[7];
    auto it28 = dos->e_res2[8];
    auto it29 = dos->e_res2[9];

    auto it30 = dos->e_lfanew;

    it_size.push_back(sizeof(it0));
    it_size.push_back(sizeof(it1));
    it_size.push_back(sizeof(it2));
    it_size.push_back(sizeof(it3));
    it_size.push_back(sizeof(it4));
    it_size.push_back(sizeof(it5));
    it_size.push_back(sizeof(it6));
    it_size.push_back(sizeof(it7));
    it_size.push_back(sizeof(it8));
    it_size.push_back(sizeof(it9));
    it_size.push_back(sizeof(it10));
    it_size.push_back(sizeof(it11));
    it_size.push_back(sizeof(it12));
    it_size.push_back(sizeof(it13));
    it_size.push_back(sizeof(it14));
    it_size.push_back(sizeof(it15));
    it_size.push_back(sizeof(it16));
    it_size.push_back(sizeof(it17));
    it_size.push_back(sizeof(it18));
    it_size.push_back(sizeof(it19));
    it_size.push_back(sizeof(it20));
    it_size.push_back(sizeof(it21));
    it_size.push_back(sizeof(it22));
    it_size.push_back(sizeof(it23));
    it_size.push_back(sizeof(it24));
    it_size.push_back(sizeof(it25));
    it_size.push_back(sizeof(it26));
    it_size.push_back(sizeof(it27));
    it_size.push_back(sizeof(it28));
    it_size.push_back(sizeof(it29));
    it_size.push_back(sizeof(it30));

    it_value.push_back(it0);
    it_value.push_back(it1);
    it_value.push_back(it2);
    it_value.push_back(it3);
    it_value.push_back(it4);
    it_value.push_back(it5);
    it_value.push_back(it6);
    it_value.push_back(it7);
    it_value.push_back(it8);
    it_value.push_back(it9);
    it_value.push_back(it10);
    it_value.push_back(it11);
    it_value.push_back(it12);
    it_value.push_back(it13);
    it_value.push_back(it14);
    it_value.push_back(it15);
    it_value.push_back(it16);
    it_value.push_back(it17);
    it_value.push_back(it18);
    it_value.push_back(it19);
    it_value.push_back(it20);
    it_value.push_back(it21);
    it_value.push_back(it22);
    it_value.push_back(it23);
    it_value.push_back(it24);
    it_value.push_back(it25);
    it_value.push_back(it26);
    it_value.push_back(it27);
    it_value.push_back(it28);
    it_value.push_back(it29);
    it_value.push_back(it30);

    // VA初始化
    for (auto item : it_size) {
        detail.va.append(Addr(startVa, 4));
        startVa += item;
    }

    // 初始化desc
    QString desc =
        "Signature,Bytes on Last Page of File,Pages in File,Relocations,Size of Header in Paragraphs,Minimum Extra Paragraphs,Maximum Extra Paragraphs,Initial(relative)ss,Initial SP,Checksum,Initial P,Initial(relative)CS,Offset to relocation table,Overlay Number,Resered,Resered,Resered,Resered,OEM Identifier,OEM Information,Resered,Resered,Resered,Resered,Resered,Resered,Resered,Resered,Resered,Resered,Offset to New exe header";

    detail.desc = desc.split(",");

    // 初始化data
    for (int i = 0; i < it_value.size(); ++i) {
        detail.data.push_back(QString("%1").arg(it_value[i], it_size[i] << 1, 16,
                                                QChar('0')).toUpper());
    }

    // 初始化value
    if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
        detail.value.push_back("IMAGE_DOS_SIGNATURE_MZ");
    }
    else {
        detail.value.push_back("");
    }

    for (int i = 0; i < detail.va.size() - 1; i++) {
        detail.value.push_back("");
    }

    return detail;
}

// dos stub 初始化

// NT头 签名初始化(传入NT header)
details init_nt_signature(int start, const QByteArray& byte) {
    PIMAGE_NT_HEADERS32 p = (PIMAGE_NT_HEADERS32)byte.data();

    p->Signature;
    details detail(true);
    detail.va.push_back(QString("%1").arg(start, 8, 16, QChar('0')).toUpper());
    detail.data.push_back(QString("%1").arg(p->Signature,
                                            sizeof(p->Signature) << 1, 16,
                                            QChar('0')).toUpper());
    detail.desc.push_back("SIGNATURE");

    if (p->Signature == IMAGE_NT_SIGNATURE) {
        detail.value.push_back("IMAGE_NT_SIGNATURE_PE");
    }
    else {
        detail.value.push_back("");
    }
    return detail;
}

details init_nt_file_header(int startVa, const QByteArray& byte) {
    details d(true);
    PIMAGE_NT_HEADERS32 nt = (PIMAGE_NT_HEADERS32)byte.data();
    PIMAGE_FILE_HEADER  p = &(nt->FileHeader);

    QVector<int> it_size;

    it_size.reserve(10);
    QVector<int> it_value;
    it_size.reserve(10);

    auto it0 = p->Machine;
    auto it1 = p->NumberOfSections;
    auto it2 = p->TimeDateStamp;
    auto it3 = p->PointerToSymbolTable;
    auto it4 = p->NumberOfSymbols;
    auto it5 = p->SizeOfOptionalHeader;
    auto it6 = p->Characteristics;

    it_value.push_back(it0);
    it_value.push_back(it1);
    it_value.push_back(it2);
    it_value.push_back(it3);
    it_value.push_back(it4);
    it_value.push_back(it5);
    it_value.push_back(it6);

    it_size.push_back(sizeof(it0));
    it_size.push_back(sizeof(it1));
    it_size.push_back(sizeof(it2));
    it_size.push_back(sizeof(it3));
    it_size.push_back(sizeof(it4));
    it_size.push_back(sizeof(it5));
    it_size.push_back(sizeof(it6));

    // VA初始化
    for (auto item : it_size) {
        d.va.append(Addr(startVa, 4));
        startVa += item;
    }

    // 初始化data
    for (int i = 0; i < it_value.size(); ++i) {
        d.data.push_back(Addr(it_value[i], it_size[i]));
    }

    // 初始化desc
    QString desc =
        "Machine,NumberOfSections,TimeDateStamp,PointerToSymbolTable,NumberOfSymbols,SizeOfOptionalHeader,Characteristics";
    d.desc = desc.split(",");

    // 初始化va
    if (p->Machine == IMAGE_FILE_32BIT_MACHINE) {
        d.value.push_back("IMAGE_FILE_32BIT_MACHINE");
    }
    else {
        d.value.push_back("IMAGE_FILE_MACHINE_UNKNOW");
    }
    return d;
}

details init_option_header(int startVa, const QByteArray& byte) {
    details d(true);
    PIMAGE_NT_HEADERS32 nt = (PIMAGE_NT_HEADERS32)byte.data();
    PIMAGE_OPTIONAL_HEADER32 p = &(nt->OptionalHeader);

    QString desc =
        "Magic,MajorLinkerVersion,MinorLinkerVersion,SizeOfCode,SizeOfInitializedData,SizeOfUninitializedData,AddressOfEntryPoint,BaseOfCode,BaseOfData,ImageBase,SectionAlignment,FileAlignment,MajorOperatingSystemVersion,MinorOperatingSystemVersion,MajorImageVersion,MinorImageVersion,MajorSubsystemVersion,MinorSubsystemVersion,Win32VersionValue,SizeOfImage,SizeOfHeaders,CheckSum,Subsystem,DllCharacteristics,SizeOfStackReserve,SizeOfStackCommit,SizeOfHeapReserve,SizeOfHeapCommit,LoaderFlags,NumberOfRvaAndSizes";

    d.desc = desc.split(",");

    QVector<int> it_size;

    it_size.reserve(30);
    QVector<int> it_value;
    it_size.reserve(30);

    auto it0 = p->Magic;
    auto it1 = p->MajorLinkerVersion;
    auto it2 = p->MinorLinkerVersion;
    auto it3 = p->SizeOfCode;
    auto it4 = p->SizeOfInitializedData;
    auto it5 = p->SizeOfUninitializedData;
    auto it6 = p->AddressOfEntryPoint;
    auto it7 = p->BaseOfCode;
    auto it8 = p->BaseOfData;
    auto it9 = p->ImageBase;
    auto it10 = p->SectionAlignment;
    auto it11 = p->FileAlignment;
    auto it12 = p->MajorOperatingSystemVersion;
    auto it13 = p->MinorOperatingSystemVersion;
    auto it14 = p->MajorImageVersion;
    auto it15 = p->MinorImageVersion;
    auto it16 = p->MajorSubsystemVersion;
    auto it17 = p->MinorSubsystemVersion;
    auto it18 = p->Win32VersionValue;
    auto it19 = p->SizeOfImage;
    auto it20 = p->SizeOfHeaders;
    auto it21 = p->CheckSum;
    auto it22 = p->Subsystem;
    auto it23 = p->DllCharacteristics;
    auto it24 = p->SizeOfStackReserve;
    auto it25 = p->SizeOfStackCommit;
    auto it26 = p->SizeOfHeapReserve;
    auto it27 = p->SizeOfHeapCommit;
    auto it28 = p->LoaderFlags;
    auto it29 = p->NumberOfRvaAndSizes;
    it_value.push_back(it0);
    it_value.push_back(it1);
    it_value.push_back(it2);
    it_value.push_back(it3);
    it_value.push_back(it4);
    it_value.push_back(it5);
    it_value.push_back(it6);
    it_value.push_back(it7);
    it_value.push_back(it8);
    it_value.push_back(it9);
    it_value.push_back(it10);
    it_value.push_back(it11);
    it_value.push_back(it12);
    it_value.push_back(it13);
    it_value.push_back(it14);
    it_value.push_back(it15);
    it_value.push_back(it16);
    it_value.push_back(it17);
    it_value.push_back(it18);
    it_value.push_back(it19);
    it_value.push_back(it20);
    it_value.push_back(it21);
    it_value.push_back(it22);
    it_value.push_back(it23);
    it_value.push_back(it24);
    it_value.push_back(it25);
    it_value.push_back(it26);
    it_value.push_back(it27);
    it_value.push_back(it28);
    it_value.push_back(it29);
    it_size.push_back(sizeof(it0));
    it_size.push_back(sizeof(it1));
    it_size.push_back(sizeof(it2));
    it_size.push_back(sizeof(it3));
    it_size.push_back(sizeof(it4));
    it_size.push_back(sizeof(it5));
    it_size.push_back(sizeof(it6));
    it_size.push_back(sizeof(it7));
    it_size.push_back(sizeof(it8));
    it_size.push_back(sizeof(it9));
    it_size.push_back(sizeof(it10));
    it_size.push_back(sizeof(it11));
    it_size.push_back(sizeof(it12));
    it_size.push_back(sizeof(it13));
    it_size.push_back(sizeof(it14));
    it_size.push_back(sizeof(it15));
    it_size.push_back(sizeof(it16));
    it_size.push_back(sizeof(it17));
    it_size.push_back(sizeof(it18));
    it_size.push_back(sizeof(it19));
    it_size.push_back(sizeof(it20));
    it_size.push_back(sizeof(it21));
    it_size.push_back(sizeof(it22));
    it_size.push_back(sizeof(it23));
    it_size.push_back(sizeof(it24));
    it_size.push_back(sizeof(it25));
    it_size.push_back(sizeof(it26));
    it_size.push_back(sizeof(it27));
    it_size.push_back(sizeof(it28));
    it_size.push_back(sizeof(it29));

    // VA初始化
    for (auto item : it_size) {
        d.va.append(Addr(startVa, 4));
        startVa += item;
    }

    // 初始化data
    for (int i = 0; i < it_value.size(); ++i) {
        d.data.push_back(QString("%1").arg(it_value[i], it_size[i] << 1, 16,
                                           QChar('0')).toUpper());
    }

    // 初始化value TODO 暂时设置为null
    d.value.reserve(50);

    for (int i = 0; i < it_size.length(); ++i) {
        d.value.push_back("");
    }


    // directory指向首个引入PIMAGE_DATA_DIRECTORY
    PIMAGE_DATA_DIRECTORY directory =
        reinterpret_cast<PIMAGE_DATA_DIRECTORY>((reinterpret_cast<char *>(p) +
                                                 96));

    //    DWORD   VirtualAddress;
    //    DWORD   Size;
    // 初始化 目录表

    desc =
        "EXPORT Table,IMPORT Table,RESOURCE Table,EXCEPTION Table,CERTIFICATE Table,BASE RELOCATION Table,DEBUG Directory,Architecture Specific Data,GLOBAL POINTER Register,TLS Table,LOAD CONFIGURATION Table,BOUND IMPORT Table,IMPORT Address table,DELAY IMPORT Descriptors,CLI Header,";
    QStringList desclist = desc.split(",");

    for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; ++i) {
        d.desc.push_back("RVA");
        d.data.push_back(Addr(directory->VirtualAddress, 4));
        d.desc.push_back("Size");
        d.data.push_back(Addr(directory->Size, 4));

        d.va.push_back(Addr(startVa, 4));
        startVa += 4;
        d.va.push_back(Addr(startVa, 4));
        startVa += 4;

        d.value.push_back(desclist[i]);
        d.value.push_back("");

        directory++;
    }


    return d;
}

// details init_section_header(int startVa, const QByteArray& b) {
//    PIMAGE_SECTION_HEADER p = (PIMAGE_SECTION_HEADER)b.data();


// }

#else // ifndef __WIN64

#endif // ifndef __WIN64

#endif // PEANALYSIS_H
