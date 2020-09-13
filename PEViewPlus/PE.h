#pragma once
#include "pch.h"

class Node {
public:

    QString head;
    QStringList addr;
    QStringList data;
    QStringList value;
    QStringList desc;
    bool hasDesc;
    bool isSubTreeNode;

    Node(QString _head, bool _hasDesc = false,
         bool  _isSubTreeNode = false) : head(_head), hasDesc(_hasDesc),
        isSubTreeNode(
            _isSubTreeNode) {}

    ~Node() {}
};

#define Unknown "Unknown"
inline void judge(Node *node) {
    if (node->hasDesc) {
        Q_ASSERT(
            node->data.size() == node->addr.size() && node->value.size() == node->desc.size() &&
            node->data.size() == node->value.size());
    } else {
        Q_ASSERT(
            node->data.size() == node->addr.size() &&
            node->data.size() == node->value.size());
    }
}

class PE {
public:

    QString file_name;
    size_t file_size;
    const us *content;
    QVector<Node *>nodes;
    QStringList treeList;
    int startVA = 0;
    int index_section_rdata; // rdata拥有IAT和INT 需要记住相应的位置
    int index_reloc_table;
    int index_sectionEAT;

    PIMAGE_DOS_HEADER dos_header;

    // size is sizeof(IMAGE_DOS_HEADER)
    // DosStud  is start at dos_header+sizeof(IMAGE_DOS_HEADER) size is
    // (dos_header->e_lfanew-sizeof(IMAGE_DOS_HEADER))
    PIMAGE_NT_HEADERS32 nt_header; // (PIMAGE_NT_HEADERS32)((char*)dos_header+(dos_header->e_lfanew))
    PIMAGE_DATA_DIRECTORY data_directory;
    PIMAGE_SECTION_HEADER section_header;

    ~PE() {
        // 删除文件堆空间
        delete[]content;

        // 删除node节点堆空间
        for (auto it:this->nodes) {
            delete it;
        }
        nodes.clear();
    }

    template<typename T>
    QString mapToValue(const unordered_map<T, QString>& mp, const T& target) {
        auto it = mp.find(target);

        if (it != mp.end()) {
            return it->second;
        } else {
            return Unknown;
        }
    }

    PE(QString _file) : file_name(_file) {
        // 文件初始化
        init(file_name);

        // 构造初始化
        init_pe_allnodes();
    }

    // 使用pe文件 初始化PE类及其成员变量
    void init(const QString& _file) {
        const string file = _file.toStdString();

        ifstream in (file, ios::binary);

        if (!in) {
            perror("file open error");
            exit(-1);
        }

        in.seekg(0, in.end);
        this->file_size = in.tellg();
        in.seekg(0, in.beg); // 定位到文件开始
        us *file_content = new us[file_size];
        memset(file_content, 0, file_size);
        in.read(reinterpret_cast<char *>(file_content), file_size);
        in.close();
        this->content = file_content;

        startVA = 0;

        // DOS HEADER
        dos_header = (PIMAGE_DOS_HEADER)content;

        // NT  HEADER
        nt_header =
            (PIMAGE_NT_HEADERS32)((char *)dos_header + (dos_header->e_lfanew));

        // nt_header->Signature;
        // nt_header->FileHeader
        // nt_header->OptionalHeader;

        auto size_nt_header = sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) +
                              nt_header->FileHeader.SizeOfOptionalHeader;

        // auto numberOfSection = nt_header->FileHeader.NumberOfSections;
        data_directory = nt_header->OptionalHeader.DataDirectory;
        section_header =
            (PIMAGE_SECTION_HEADER)((char *)nt_header + size_nt_header);
    }

    // 地址的偏移暂时实现VA和RVA_offset的显示
    // 初始化整个PE文件显示
    Node* init_pe_file() {
        auto index = file_name.length() - 1;

        for (; index >= 0; index--) {
            if ((file_name[index] == '\\') || (file_name[index] == '/')) {
                break;
            }
        }


        Node *node = new Node(file_name.mid(index + 1), false, false);

        // Node *node = new Node(file_name, false, false);

        auto raw_offset = 0;
        auto raw_size = file_size;
        auto RVA_offset = raw_offset;

        // auto RVA_size = raw_size;

        fillContent(node, raw_offset, raw_size, RVA_offset, startVA);
        return node;
    }

    // 初始化dos头显示
    // 问题已解决
    Node* init_dos_header() {
        Node *node = new Node("IMAGE_DOS_HEADER", true, false);

        // 使用静态局部变量
        const static QStringList desc =
        { "Magic number",
          "Bytes on last page of file",
          "Pages in file",
          "Relocations",
          "Size of header in paragraphs",
          "Minimum extra paragraphs needed",
          "Maximum extra paragraphs needed",
          "Initial (relative) SS value",
          "Initial SP value",
          "Checksum",
          "Initial IP value",
          "Initial (relative) CS value",
          "File address of relocation table",
          "Overlay number",
          "Reserved words",                   "Reserved words",
          "Reserved words",
          "Reserved words",
          "OEM identifier (for e_oeminfo)",
          "OEM information; e_oemid specific",
          "Reserved words",
          "Reserved words",
          "Reserved words",                   "Reserved words",
          "Reserved words",
          "Reserved words",                   "Reserved words",
          "Reserved words",
          "Reserved words",                   "Reserved words",
          "File address of new exe header" };

        node->desc = desc;
        Q_ASSERT(node->desc.size() == 31);
        QVector<int> it_size;
        QVector<int> it_value;
        int RVA = startVA;
        it_size.reserve(31);
        it_size.reserve(31);

        auto it0 = dos_header->e_magic;
        auto it1 = dos_header->e_cblp;
        auto it2 = dos_header->e_cp;
        auto it3 = dos_header->e_crlc;
        auto it4 = dos_header->e_cparhdr;
        auto it5 = dos_header->e_minalloc;
        auto it6 = dos_header->e_maxalloc;
        auto it7 = dos_header->e_ss;
        auto it8 = dos_header->e_sp;
        auto it9 = dos_header->e_csum;
        auto it10 = dos_header->e_ip;
        auto it11 = dos_header->e_cs;
        auto it12 = dos_header->e_lfarlc;
        auto it13 = dos_header->e_ovno;
        auto it14 = dos_header->e_res[0];
        auto it15 = dos_header->e_res[1];
        auto it16 = dos_header->e_res[2];
        auto it17 = dos_header->e_res[3];

        auto it18 = dos_header->e_oemid;
        auto it19 = dos_header->e_oeminfo;

        auto it20 = dos_header->e_res2[0];
        auto it21 = dos_header->e_res2[1];
        auto it22 = dos_header->e_res2[2];
        auto it23 = dos_header->e_res2[3];
        auto it24 = dos_header->e_res2[4];
        auto it25 = dos_header->e_res2[5];
        auto it26 = dos_header->e_res2[6];
        auto it27 = dos_header->e_res2[7];
        auto it28 = dos_header->e_res2[8];
        auto it29 = dos_header->e_res2[9];

        auto it30 = dos_header->e_lfanew;

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

        node->addr.reserve(31);
        node->data.reserve(31);

        for (int i = 0; i < it_value.size(); i++) {
            node->addr.push_back(Addr(RVA, 4));
            RVA += it_size[i];

            node->data.push_back(Addr(it_value[i], it_size[i]));
        }

        // 特殊处理
        node->value.push_back("IMAGE_DOS_SIGNATURE_MZ");
        int dis = node->addr.size() - node->value.size();

        while (dis--) {
            node->value.push_back("");
        }

        return node;
    }

    Node* init_dos_stub() {
        Node *node = new Node("IMAGE_DOS_STUB", false, false);
        auto  raw_offset = sizeof(IMAGE_DOS_HEADER);
        auto  raw_size = dos_header->e_lfanew - sizeof(IMAGE_DOS_HEADER);
        auto  RVA_offset = raw_offset;

        fillContent(node, raw_offset, raw_size, RVA_offset, startVA);
        return node;
    }

    Node* init_nt_header(int startVA = 0) {
        Node *node = new Node("IMAGE_NT_HEADERS", false, false);
        auto  size_nt_header = sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) +
                               nt_header->FileHeader.SizeOfOptionalHeader;

        auto raw_offset = dos_header->e_lfanew;
        auto raw_size = size_nt_header;
        auto RVA_offset = raw_offset;

        fillContent(node, raw_offset, raw_size, RVA_offset, startVA);

        return node;
    }

    Node* init_nt_headers_signature(int startVA = 0) {
        Node *node = new Node("Signature", true, true);
        int   RVA = dos_header->e_lfanew + startVA;

        node->addr.push_back(Addr(RVA, 4));
        node->data.push_back(Addr(nt_header->Signature,
                                  sizeof(nt_header->Signature)));
        node->desc.push_back("Signature");
        node->value.push_back("IMAGE_NT_HEADER_SIGNATURE");
        return node;
    }

    Node* init_nt_headers_file_header() {
        Node *node = new Node("IMAGE_FILE_HEADER", true, true);

        /*
                WORD    Machine;
                WORD    NumberOfSections;
                DWORD   TimeDateStamp;
                DWORD   PointerToSymbolTable;
                DWORD   NumberOfSymbols;
                WORD    SizeOfOptionalHeader;
                WORD    Characteristics;
         */
        const static QStringList desc =
        { "Machine",              "NumberOfSections",
          "TimeDateStamp",
          "PointerToSymbolTable",
          "NumberOfSymbols",      "SizeOfOptionalHeader",
          "Characteristics" };

        node->desc = desc;
        const auto header = &nt_header->FileHeader;
        int N = 7;
        QVector<int> it_size;
        it_size.reserve(N);
        QVector<int> it_value;
        it_value.reserve(N);

        auto it0 = header->Machine;
        auto it1 = header->NumberOfSections;
        auto it2 = header->TimeDateStamp;
        auto it3 = header->PointerToSymbolTable;
        auto it4 = header->NumberOfSymbols;
        auto it5 = header->SizeOfOptionalHeader;
        auto it6 = header->Characteristics;

        it_size.push_back(sizeof(it0));
        it_size.push_back(sizeof(it1));
        it_size.push_back(sizeof(it2));
        it_size.push_back(sizeof(it3));
        it_size.push_back(sizeof(it4));
        it_size.push_back(sizeof(it5));
        it_size.push_back(sizeof(it6));

        it_value.push_back(it0);
        it_value.push_back(it1);
        it_value.push_back(it2);
        it_value.push_back(it3);
        it_value.push_back(it4);
        it_value.push_back(it5);
        it_value.push_back(it6);

        int RVA = dos_header->e_lfanew + sizeof(nt_header->Signature) + startVA;

        for (int i = 0; i < N; i++) {
            node->addr.push_back(Addr(RVA, 4));
            RVA += it_size[i];
            node->data.push_back(Addr(it_value[i], it_size[i]));
        }

        // 设置 Machine字段
        const static unordered_map<WORD,
                                   QString> mp_Machine =
        {   { 0,
            "IMAGE_FILE_MACHINE_UNKNOWN"                                   },
            { 0x0001,
              "IMAGE_FILE_MACHINE_TARGET_HOST"                                },
            { 0x014c,
              "IMAGE_FILE_MACHINE_I386"                                       },
            { 0x0162,
              "IMAGE_FILE_MACHINE_R3000"                                      },
            { 0x0166,
              "IMAGE_FILE_MACHINE_R4000"                                      },
            { 0x0168,
              "IMAGE_FILE_MACHINE_R10000"                                     },
            { 0x0169,
              "IMAGE_FILE_MACHINE_WCEMIPSV2"                                  },
            { 0x0184,
              "IMAGE_FILE_MACHINE_ALPHA"                                      },
            { 0x01a2,
              "IMAGE_FILE_MACHINE_SH3"                                        },
            { 0x01a3,
              "IMAGE_FILE_MACHINE_SH3DSP"                                     },
            { 0x01a4,
              "IMAGE_FILE_MACHINE_SH3E"                                       },
            { 0x01a6,
              "IMAGE_FILE_MACHINE_SH4"                                        },
            { 0x01a8,
              "IMAGE_FILE_MACHINE_SH5"                                        },
            { 0x01c0,
              "IMAGE_FILE_MACHINE_ARM"                                        },
            { 0x01c2,
              "IMAGE_FILE_MACHINE_THUMB"                                      },
            { 0x01c4,
              "IMAGE_FILE_MACHINE_ARMNT"                                      },
            { 0x01d3,
              "IMAGE_FILE_MACHINE_AM33"                                       },
            { 0x01F0,
              "IMAGE_FILE_MACHINE_POWERPC"                                    },
            { 0x01f1,
              "IMAGE_FILE_MACHINE_POWERPCFP"                                  },
            { 0x0200,
              "IMAGE_FILE_MACHINE_IA64"                                       },
            { 0x0266,
              "IMAGE_FILE_MACHINE_MIPS16"                                     },
            { 0x0284,
              "IMAGE_FILE_MACHINE_ALPHA64"                                    },
            { 0x0366,
              "IMAGE_FILE_MACHINE_MIPSFPU"                                    },
            { 0x0466,
              "IMAGE_FILE_MACHINE_MIPSFPU16"                                  },
            { 0x0520,
              "IMAGE_FILE_MACHINE_TRICORE"                                    },
            { 0x0CEF,
              "IMAGE_FILE_MACHINE_CEF"                                        },
            { 0x0EBC,
              "IMAGE_FILE_MACHINE_EBC"                                        },
            { 0x8664,
              "IMAGE_FILE_MACHINE_AMD64"                                      },
            { 0x9041,
              "IMAGE_FILE_MACHINE_M32R"                                       },
            { 0xAA64,
              "IMAGE_FILE_MACHINE_ARM64"                                      },
            { 0xC0EE,
              "IMAGE_FILE_MACHINE_CEE"                                  } };

        node->value.push_back(mapToValue(mp_Machine, header->Machine));

        for (int i = 0; i < desc.size() - 1; i++) {
            node->value.push_back("");
        }

        // 对character的特殊处理
        // 同时还要保证 Addr desc value data 这4个vector长度的一致性
        // data addr desc 已经对齐 并且他们的长度均为7
        // 设置value的Machine type的值

        const static unordered_map<WORD,
                                   QString> mp_Characteristics =
        {   { 0x0001, "IMAGE_FILE_RELOCS_STRIPPED"         },
            { 0x0002, "IMAGE_FILE_EXECUTABLE_IMAGE"        },
            { 0x0004, "IMAGE_FILE_LINE_NUMS_STRIPPED"      },
            { 0x0008, "IMAGE_FILE_LOCAL_SYMS_STRIPPED"     },
            { 0x0010, "IMAGE_FILE_AGGRESIVE_WS_TRIM"       },
            { 0x0020, "IMAGE_FILE_LARGE_ADDRESS_AWARE"     },
            { 0x0080, "IMAGE_FILE_BYTES_REVERSED_LO"       },
            { 0x0100, "IMAGE_FILE_32BIT_MACHINE"           },
            { 0x0200, "IMAGE_FILE_DEBUG_STRIPPED"          },
            { 0x0400, "IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP" } };

        WORD factor = 0x0001;
        WORD charcter = header->Characteristics;
        WORD target;
        QString ret;

        for (int i = 0; i < 16; i++) {
            target = factor & charcter;
            ret = mapToValue(mp_Characteristics, target);

            if (ret != Unknown) {
                node->desc.push_back(Addr(target, 2));
                node->value.push_back(ret);
            }
            factor = factor << 1;
        }

        int dis = node->desc.size() - node->addr.size();

        while (dis-- > 0) {
            node->addr.push_back("");
            node->data.push_back("");
        }

        Q_ASSERT(
            node->data.size() == node->addr.size() && node->value.size() == node->desc.size() &&
            node->data.size() == node->value.size());
        return node;
    }

    Node* init_nt_headers_optional_header(int startVA = 0) {
        Node *node = new Node("IMAGE_OPTIONAL_HEADER", true, true);
        auto  header = &nt_header->OptionalHeader;
        int   N = 24; // Magic to CheckSum
        QVector<int> it_size;

        it_size.reserve(N);
        QVector<int> it_value;
        it_value.reserve(N);

        // 24
        const static QStringList desc = { "Magic",
                                          "MajorLinkerVersion",
                                          "MinorLinkerVersion",
                                          "SizeOfCode",
                                          "SizeOfInitializedData",
                                          "SizeOfUninitializedData",
                                          "AddressOfEntryPoint",
                                          "BaseOfCode",
                                          "BaseOfData",
                                          "ImageBase",
                                          "SectionAlignment",
                                          "FileAlignment",
                                          "MajorOperatingSystemVersion",
                                          "MinorOperatingSystemVersion",
                                          "MajorImageVersion",
                                          "MinorImageVersion",
                                          "MajorSubsystemVersion",
                                          "MinorSubsystemVersion",
                                          "Win32VersionValue",
                                          "SizeOfImage",
                                          "SizeOfHeaders",
                                          "CheckSum",
                                          "Subsystem",
                                          "Dll Characteristics" };
        node->desc = desc;

        auto it0 = header->Magic;
        auto it1 = header->MajorLinkerVersion;
        auto it2 = header->MinorLinkerVersion;
        auto it3 = header->SizeOfCode;
        auto it4 = header->SizeOfInitializedData;
        auto it5 = header->SizeOfUninitializedData;
        auto it6 = header->AddressOfEntryPoint;
        auto it7 = header->BaseOfCode;
        auto it8 = header->BaseOfData;
        auto it9 = header->ImageBase;
        auto it10 = header->SectionAlignment;
        auto it11 = header->FileAlignment;
        auto it12 = header->MajorOperatingSystemVersion;
        auto it13 = header->MinorOperatingSystemVersion;
        auto it14 = header->MajorImageVersion;
        auto it15 = header->MinorImageVersion;
        auto it16 = header->MajorSubsystemVersion;
        auto it17 = header->MinorSubsystemVersion;
        auto it18 = header->Win32VersionValue;
        auto it19 = header->SizeOfImage;
        auto it20 = header->SizeOfHeaders;
        auto it21 = header->CheckSum;
        auto it22 = header->Subsystem;
        auto it23 = header->DllCharacteristics;

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
        int RVA = dos_header->e_lfanew + sizeof(nt_header->Signature) +
                  sizeof(nt_header->FileHeader) + startVA;

        for (int i = 0; i < N; i++) {
            node->addr.push_back(Addr(RVA, 4));
            RVA += it_size[i];
            node->data.push_back(Addr(it_value[i], it_size[i]));
        }

        // value对齐：
        const static unordered_map<WORD,
                                   QString> mp_Magic =
        {   { 0x10b, "IMAGE_NT_OPTIONAL_HDR32_MAGIC" },
            { 0x20b, "IMAGE_NT_OPTIONAL_HDR64_MAGIC" },
            { 0x107, "IMAGE_ROM_OPTIONAL_HDR_MAGIC"  } };
        node->value.push_back(mapToValue(mp_Magic, header->Magic));

        for (int i = 0; i < N - 3; i++) { // 0~21  1~22
            node->value.push_back("");
        }
        const static unordered_map<WORD,
                                   QString> mp_Subsystem =
        {   { 0,
            "IMAGE_SUBSYSTEM_UNKNOWN"                                                     },
            { 1,
              "IMAGE_SUBSYSTEM_NATIVE"                                                        },
            { 2,
              "IMAGE_SUBSYSTEM_WINDOWS_GUI"                                                    },
            { 3,
              "IMAGE_SUBSYSTEM_WINDOWS_CUI"                                                     },
            { 5,
              "IMAGE_SUBSYSTEM_OS2_CUI"                                                          },
            { 7,
              "IMAGE_SUBSYSTEM_POSIX_CUI"                                                         },
            { 8,
              "IMAGE_SUBSYSTEM_NATIVE_WINDOWS"                                                     },
            { 9,
              "IMAGE_SUBSYSTEM_WINDOWS_CE_GUI"                                                      },
            { 10,
              "IMAGE_SUBSYSTEM_EFI_APPLICATION"                                                     },
            { 11,
              "IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER"                                             },
            { 12,
              "IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER"                                                  },
            { 13,
              "IMAGE_SUBSYSTEM_EFI_ROM"                                                             },
            { 14,
              "IMAGE_SUBSYSTEM_XBOX"                                                                },
            { 16,
              "IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION"                                            },
            { 17,
              "IMAGE_SUBSYSTEM_XBOX_CODE_CATALOG"                                                   } };
        node->value.push_back(mapToValue(mp_Subsystem,
                                         header->Subsystem));
        node->value.push_back("DLL characters as follows");

        const static unordered_map<WORD, QString> mp_DllCharacteristics{
            { 0x0020, "IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA" },
            { 0x0040, "IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE" },
            { 0x0080, "IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY" },
            { 0x0100, "IMAGE_DLLCHARACTERISTICS_NX_COMPAT" },
            { 0x0200, "IMAGE_DLLCHARACTERISTICS_NO_ISOLATION" },
            { 0x0400, "IMAGE_DLLCHARACTERISTICS_NO_SEH" },
            { 0x0800, "IMAGE_DLLCHARACTERISTICS_NO_BIND" },
            { 0x1000, "IMAGE_DLLCHARACTERISTICS_APPCONTAINER" },
            { 0x2000, "IMAGE_DLLCHARACTERISTICS_WDM_DRIVER" },
            { 0x4000, "IMAGE_DLLCHARACTERISTICS_GUARD_CF" },
            { 0x8000, "IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE" } };

        WORD factor = 0x0001;
        WORD charcter = header->DllCharacteristics;
        WORD target;
        QString ret;

        for (int i = 0; i < 16; i++) {
            target = factor & charcter;
            ret = mapToValue(mp_DllCharacteristics, target);

            if (ret != Unknown) {
                node->desc.push_back(Addr(target, 2));
                node->value.push_back(ret);
            }
            factor = factor << 1;
        }
        int dis = node->desc.size() - node->addr.size();

        while (dis--) {
            node->addr.push_back("");
            node->data.push_back("");
        }

        // judge4

        it_size.clear();
        it_value.clear();
        N = 6; //
        it_size.reserve(N);
        it_value.reserve(N);

        // 请使用新的 it0 因为在it0第一次使用auto初始化时就确定了大小
        auto it0_1 = header->SizeOfStackReserve;
        auto it1_1 = header->SizeOfStackCommit;
        auto it2_1 = header->SizeOfHeapReserve;
        auto it3_1 = header->SizeOfHeapCommit;
        auto it4_1 = header->LoaderFlags;
        auto it5_1 = header->NumberOfRvaAndSizes;

        it_size.push_back(sizeof(it0_1));
        it_size.push_back(sizeof(it1_1));
        it_size.push_back(sizeof(it2_1));
        it_size.push_back(sizeof(it3_1));
        it_size.push_back(sizeof(it4_1));
        it_size.push_back(sizeof(it5_1));

        it_value.push_back(it0_1);
        it_value.push_back(it1_1);
        it_value.push_back(it2_1);
        it_value.push_back(it3_1);
        it_value.push_back(it4_1);
        it_value.push_back(it5_1);
        const static QStringList desc1 = { "SizeOfStackReserve",
                                           "SizeOfStackCommit",
                                           "SizeOfHeapReserve",
                                           "SizeOfHeapCommit",
                                           "LoaderFlags",
                                           "NumberOfRvaAndSizes" };

        for (int i = 0; i < N; i++) {
            node->addr.push_back(Addr(RVA, 4));
            RVA += it_size[i];
            node->data.push_back(Addr(it_value[i], it_size[i]));
            node->value.push_back("");
            node->desc.push_back(desc1[i]);
        }

        // data_directory
        N = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
        PIMAGE_DATA_DIRECTORY p = header->DataDirectory;

        for (int i = 0; i < N; i++) {
            node->addr.push_back(Addr(RVA, 4));
            node->data.push_back(Addr(p->VirtualAddress, 4));
            node->desc.push_back("RVA");
            RVA += 4;
            node->addr.push_back(Addr(RVA, 4));
            node->data.push_back(Addr(p->Size, 4));
            node->desc.push_back("Size");
            RVA += 4;
            p++;
        }
        const static QStringList desc_data_directory = { "Export table",
                                                         "Import table",
                                                         "Resource table",
                                                         "Exception table",
                                                         "Certificate table",
                                                         "Base relation table",
                                                         "Debugging information starting",
                                                         "Architecture-specific data",
                                                         "Global pointer register",
                                                         "Thread local storage",
                                                         "Load configuration table",
                                                         "Bound import table",
                                                         "Import address table",
                                                         "Delay import descriptor",
                                                         "CLR Runtime Header",
                                                         "Reserved" };

        for (int i = 0; i < N; i++) {
            node->value.push_back(desc_data_directory[i]);
            node->value.push_back("");
        }

        return node;
    }

    // 初始化节表
    QVector<Node *>init_section_header() {
        auto p = section_header;
        int  NumberOfSections = nt_header->FileHeader.NumberOfSections;
        QVector<Node *> ret;
        QString name;
        int     RVA;

        for (int i = 0; i < NumberOfSections; i++) {
            name = "IMAGE_SECTION_HEADER " + QString((char *)p->Name);
            Node *node = new Node(name, true, false);

            // ********************//
            RVA = (us *)p - content;

            // ********************//
            init_section_header_1(RVA, node, p);
            p++;
            ret.push_back(node);
        }
        return ret;
    }

    // 辅助 init_section_header
    void init_section_header_1(int RVA, Node *node,
                               PIMAGE_SECTION_HEADER header) {
        RVA += startVA;

        // 设置Name
        node->addr.push_back(Addr(RVA, 4));
        RVA += 4;
        node->addr.push_back(Addr(RVA, 4));
        RVA += 4;

        QByteArray byte = QByteArray((char *)header->Name, 8);
        QString    hex_byte = byte.toHex(' ').toUpper();

        node->data.push_back(hex_byte.mid(0, 12));
        node->data.push_back(hex_byte.mid(12, 12));

        node->desc.push_back("Name");
        node->desc.push_back("");

        node->value.push_back(QString::fromLocal8Bit(byte));
        node->value.push_back("");

        // 9个项目

        // 设置余下元素
        const static QStringList desc = {
            "VirtualAddress",       "RVA",                  "SizeOfRawData",
            "PointerToRawData",
            "PointerToRelocations", "PointerToLinenumbers", "NumberOfRelocations",
            "NumberOfLinenumbers",  "Characteristics" };

        for (auto item : desc) {
            node->desc.append(item);
        }
        int N = 9;
        QVector<int> it_size;
        it_size.reserve(N);
        QVector<int> it_value;
        it_value.reserve(N);

        auto it0 = header->Misc.VirtualSize;
        auto it1 = header->VirtualAddress;
        auto it2 = header->SizeOfRawData;
        auto it3 = header->PointerToRawData;
        auto it4 = header->PointerToRelocations;
        auto it5 = header->PointerToLinenumbers;
        auto it6 = header->NumberOfRelocations;
        auto it7 = header->NumberOfLinenumbers;
        auto it8 = header->Characteristics;

        it_size.push_back(sizeof(it0));
        it_size.push_back(sizeof(it1));
        it_size.push_back(sizeof(it2));
        it_size.push_back(sizeof(it3));
        it_size.push_back(sizeof(it4));
        it_size.push_back(sizeof(it5));
        it_size.push_back(sizeof(it6));
        it_size.push_back(sizeof(it7));
        it_size.push_back(sizeof(it8));

        it_value.push_back(it0);
        it_value.push_back(it1);
        it_value.push_back(it2);
        it_value.push_back(it3);
        it_value.push_back(it4);
        it_value.push_back(it5);
        it_value.push_back(it6);
        it_value.push_back(it7);
        it_value.push_back(it8);

        for (int i = 0; i < N; i++) {
            node->addr.push_back(Addr(RVA, 4));
            RVA += it_size[i];
            node->data.push_back(Addr(it_value[i], it_size[i]));
        }

        // 对齐value
        for (int i = 0; i < N; i++) {
            node->value.push_back("");
        }
        DWORD   factor = 0x00000001;
        DWORD   charcter = header->Characteristics;
        DWORD   target;
        QString ret;
        int     len = sizeof(header->Characteristics) << 3;
        const static unordered_map<DWORD, QString> mp_characteristics = {
            { 0x00000020, "IMAGE_SCN_CNT_CODE"               },
            { 0x00000040, "IMAGE_SCN_CNT_INITIALIZED_DATA"   },
            { 0x00000080, "IMAGE_SCN_CNT_UNINITIALIZED_DATA" },
            { 0x00000100, "IMAGE_SCN_LNK_OTHER"              },
            { 0x00000200, "IMAGE_SCN_LNK_INFO"               },
            { 0x00000800, "IMAGE_SCN_LNK_REMOVE"             },
            { 0x00001000, "IMAGE_SCN_LNK_COMDAT"             },
            { 0x00004000, "IMAGE_SCN_NO_DEFER_SPEC_EXC"      },
            { 0x00008000, "IMAGE_SCN_MEM_FARDATA"            },
            { 0x00020000, "IMAGE_SCN_MEM_16BIT"              },
            { 0x00040000, "IMAGE_SCN_MEM_LOCKED"             },
            { 0x00080000, "IMAGE_SCN_MEM_PRELOAD"            },
            { 0x00100000, "IMAGE_SCN_ALIGN_1BYTES"           },
            { 0x00200000, "IMAGE_SCN_ALIGN_2BYTES"           },
            { 0x00300000, "IMAGE_SCN_ALIGN_4BYTES"           },
            { 0x00400000, "IMAGE_SCN_ALIGN_8BYTES"           },
            { 0x00500000, "IMAGE_SCN_ALIGN_16BYTES"          },
            { 0x00600000, "IMAGE_SCN_ALIGN_32BYTES"          },
            { 0x00700000, "IMAGE_SCN_ALIGN_64BYTES"          },
            { 0x00800000, "IMAGE_SCN_ALIGN_128BYTES"         },
            { 0x00900000, "IMAGE_SCN_ALIGN_256BYTES"         },
            { 0x00A00000, "IMAGE_SCN_ALIGN_512BYTES"         },
            { 0x00B00000, "IMAGE_SCN_ALIGN_1024BYTES"        },
            { 0x00C00000, "IMAGE_SCN_ALIGN_2048BYTES"        },
            { 0x00D00000, "IMAGE_SCN_ALIGN_4096BYTES"        },
            { 0x00E00000, "IMAGE_SCN_ALIGN_8192BYTES"        },
            { 0x00F00000, "IMAGE_SCN_ALIGN_MASK"             },
            { 0x01000000, "IMAGE_SCN_LNK_NRELOC_OVFL"        },
            { 0x02000000, "IMAGE_SCN_MEM_DISCARDABLE"        },
            { 0x04000000, "IMAGE_SCN_MEM_NOT_CACHED"         },
            { 0x08000000, "IMAGE_SCN_MEM_NOT_PAGED"          },
            { 0x10000000, "IMAGE_SCN_MEM_SHARED"             },
            { 0x20000000, "IMAGE_SCN_MEM_EXECUTE"            },
            { 0x40000000, "IMAGE_SCN_MEM_READ"               },
            { 0x80000000, "IMAGE_SCN_MEM_WRITE"              },
            { 0x00000001, "IMAGE_SCN_SCALE_INDEX"            } };

        for (int i = 0; i < len; i++) {
            target = factor & charcter;
            ret = mapToValue(mp_characteristics, target);

            if (ret != Unknown) {
                node->desc.push_back(Addr(target, 4));
                node->value.push_back(ret);
            }
            factor = factor << 1;
        }
        int dis = node->desc.size() - node->addr.size();

        while (dis--) {
            node->addr.push_back("");
            node->data.push_back("");
        }
    }

    QVector<Node *>init_section() {
        auto header = section_header;
        int  NumberOfSections = nt_header->FileHeader.NumberOfSections;
        QString name;
        QVector<Node *> ret;

        for (int i = 0; i < NumberOfSections; i++) {
            name = "SECTION " + QString((char *)header->Name);
            Node *node = new Node(name, false, false);

            // 实际大小是 Misc 的 VirtualSize(但是也不一定)   SizeOfRawData文件的大小
            auto raw_offset = header->PointerToRawData;
            auto raw_size = header->SizeOfRawData;
            auto RVA_offset = header->VirtualAddress;

            fillContent(node, raw_offset, raw_size, RVA_offset, startVA);

            header++;
            ret.push_back(node);
        }
        return ret;
    }

    QVector<Node *>init_rdata() {
        Node *node_IAT = new Node("Import Address Table", true, true);
        Node *node_INT = new Node("Import Name Table", true, true);
        Node *node_IDT = new Node("Import Descriptor Table", true, true);

        // 1 ：定位导入表
        // 2 : 解析第一个IID项, 根据IID中的第4个字段定位DLL的名称
        // 3 : 根据IID项的第5个字段DLL对应的IAT项的起始地址
        // 4 : 根据IAT中的指针定位到相应API函数名称字符串
        // 5 : 通过GetProcAddress获取API函数的地址并填充到IAT中
        // 6 : 当定位到的IAT项为零的时候表示该DLL的API函数地址获取完毕了, 接着继续解析第二个IID, 重复上面的步骤。
        // 引入描述符表 IID  IMAGE_IMPORT_DESCRIPTOR
        auto IID_RVA = data_directory[1].VirtualAddress;
        auto IID_SIZE = data_directory[1].Size;
        int  N_IID = (IID_SIZE / 20) - 1;

        // 确定RVA所在的段
        auto p = section_header;
        auto N = nt_header->FileHeader.NumberOfSections;

        // Import
        this->index_section_rdata = 0;

        for (int i = 0; i < N; i++) {
            if ((IID_RVA >= p->VirtualAddress) &&
                (IID_RVA < p->VirtualAddress + p->SizeOfRawData)) {
                break;
            }
            p++;
            this->index_section_rdata++;
        }

        // RVA_Address - (p->)
        auto dis = p->VirtualAddress - p->PointerToRawData;
        auto IID_file_offset = IID_RVA - dis;
        PIMAGE_IMPORT_DESCRIPTOR IID =
            (PIMAGE_IMPORT_DESCRIPTOR)(content + IID_file_offset);

        for (int i = 0; i < N_IID; i++) {
            QString dllName = (char *)(content + (IID->Name - dis));

            // (FIRSTTRUNK)IAT函数加载地址  (ORIGNALFIRST_TRUNK)INT函数的导入序号
            // 组合为IMAGE_IMPORT_BY_NAME
            // cout << dllName;
            const static QStringList desc =
            { "Import Name Table RVA", "Time Data Stamp", "Forward Chain",
              "Name RVA",              "Import Address Table RVA" };

            for (int i = 0; i < 5; i++) { // all element is 4 bytes
                node_IDT->addr.push_back(Addr(IID_RVA, 4));
                node_IDT->desc.push_back(desc[i]);

                if (i == 3) {
                    node_IDT->value.push_back(dllName);
                } else {
                    node_IDT->value.push_back("");
                }
                IID_RVA += 4;
            }
            node_IDT->data.push_back(Addr(IID->OriginalFirstThunk, 4));
            node_IDT->data.push_back(Addr(IID->TimeDateStamp, 4));
            node_IDT->data.push_back(Addr(IID->ForwarderChain, 4));
            node_IDT->data.push_back(Addr(IID->Name, 4));
            node_IDT->data.push_back(Addr(IID->FirstThunk, 4));

            node_IDT->addr.push_back("");
            node_IDT->data.push_back("");
            node_IDT->desc.push_back("");
            node_IDT->value.push_back("");

            node_IAT->addr.push_back("");
            node_INT->addr.push_back("");

            node_IAT->data.push_back("");
            node_IAT->desc.push_back("Import function table as follows");
            node_IAT->value.push_back(dllName);

            PIMAGE_THUNK_DATA32 INT =
                (PIMAGE_THUNK_DATA32)(content + (IID->OriginalFirstThunk - dis));

            // PIMAGE_THUNK_DATA32 IAT = (PIMAGE_THUNK_DATA32)(content +
            // (IID->FirstThunk - dis));
            // 对于可执行文件而言，IAT中的IMAGE_THUNK_DATA中存储的要么是Ordinal，要么是AddressOfData。
            // 怎么判断IMAGE_THUNK_DATA中存储的是Ordinal(函数序号) 还是
            // AddressOfData(指向IMAGE_IMPORT_BYNAME) 呢？
            // 众所周知，在32bit的机器上，地址空间是00000000 - FFFFFFFF,
            // 一般而言，其中00000000 - 7FFFFFFF是用户空间，其它是系统空间。
            // 于是，看IMAGE_THUNK_DATA的最高位，如果是1，就是Ordinal，否则就是AddressOfData。
            // 未初始化的时候IAT和INT是一样的在初始化后 IAT变为函数的实际地址  INT可以重建IAT故而叫做 orignal
            // thunk
            DWORD value;

            // 全为0的时候结束循环
            WORD hint;
            PIMAGE_IMPORT_BY_NAME pName;
            QString functionName;

            auto RVA_IAT = IID->FirstThunk + startVA;

            auto RVA_INT = IID->OriginalFirstThunk + startVA;

            while ((value = INT->u1.Ordinal) != 0) {
                if ((value & 0x80000000) != 0) { // Ordinal
                    // cout << "do nothing";
                    node_IAT->value.push_back(Unknown);
                } else {                         // AddressOfData
                                                 // 函数名字的地址
                    pName = (PIMAGE_IMPORT_BY_NAME)(content + (value - dis));
                    hint = pName->Hint;
                    functionName = (char *)pName + 2;

                    // node->data 为thunk的值
                    // cout << Addr(RVA, 4) << hint << "\t" << functionName;
                    node_IAT->value.push_back(functionName);
                }

                node_IAT->addr.push_back(Addr(RVA_IAT, 4));
                node_INT->addr.push_back(Addr(RVA_INT, 4));

                node_IAT->data.push_back(Addr(value, 4));
                node_IAT->desc.push_back("Hint/Name");

                INT++;
            }

            node_IAT->addr.push_back("");
            node_INT->addr.push_back("");
            node_IAT->data.push_back("");
            node_IAT->desc.push_back("");
            node_IAT->value.push_back("");
            IID++;
        }
        node_INT->data = node_IAT->data;
        node_INT->value = node_IAT->value;
        node_INT->desc = node_IAT->desc;
        QVector<Node *> ret;
        ret.reserve(3);

        ret.push_back(node_IDT);
        ret.push_back(node_IAT);
        ret.push_back(node_INT);

        // judge(node_IDT);
        // judge(node_IAT);
        // judge(node_IDT);

        // cout << node_IDT->addr.size();
        // cout << node_IDT->data.size();
        // cout << node_IDT->desc.size();
        // cout << node_IDT->value.size();

        // cout << node_INT->addr.size();
        // cout << node_INT->data.size();
        // cout << node_INT->desc.size();
        // cout << node_INT->value.size();

        // cout << node_IAT->addr.size();
        // cout << node_IAT->data.size();
        // cout << node_IAT->desc.size();
        // cout << node_IAT->value.size();
        return ret;
    }

    Node* init_reloc_table() {
        int size = data_directory[5].Size;

        if (size == 0) return nullptr;

        Node *node = new Node("IMAGE_BASE_RELOCATION", true, true);
        int   IDR_RVA = data_directory[5].VirtualAddress;

        // IMAGE_BASE_RELOCATION
        // PIMAGE_BASE_RELOCATION ibr
        this->index_reloc_table = 0;
        int  N = nt_header->FileHeader.NumberOfSections;
        auto p = section_header;
        this->index_reloc_table = 0;

        for (int i = 0; i < N; i++) {
            if ((IDR_RVA >= p->VirtualAddress) &&
                (IDR_RVA < (p->VirtualAddress + p->SizeOfRawData))) {
                break;
            }
            p++;
            this->index_reloc_table++;
        }
        auto dis = p->VirtualAddress - p->PointerToRawData;

        // auto IDR_file_offset = IDR_RVA - dis;

        PIMAGE_BASE_RELOCATION pIbr =
            (PIMAGE_BASE_RELOCATION)(content + (IDR_RVA - dis));
        int   count, i;
        WORD  type_value_high_4, type_value_low_12;
        WORD *type;
        const static int fix_head = 8;
        const static unordered_map<WORD,
                                   QString> desc =
        {   { 0,
            "  IMAGE_REL_BASE_ABSOLUTE"                                    },
            { 3,
              "  IMAGE_REL_BASE_HIGHLOW"                                     },
            { 10,
              "  IMAGE_REL_BASE_DIR64"                                     } };
        DWORD IDR_RVA_BAKE;
        DWORD base;

        while (size > 0) {
            // 资源节块的四个起始内容
            IDR_RVA_BAKE = IDR_RVA + startVA;
            node->addr.push_back(Addr(IDR_RVA_BAKE, 4));
            IDR_RVA_BAKE += 4;
            node->addr.push_back(Addr(IDR_RVA_BAKE, 4));
            IDR_RVA_BAKE += 4;

            // cout << Addr(pIbr->VirtualAddress, 4);
            // cout << Addr(pIbr->SizeOfBlock, 4);
            node->data.push_back(Addr(pIbr->VirtualAddress, 4));
            node->data.push_back(Addr(pIbr->SizeOfBlock, 4));

            node->desc.push_back("RVA if Block");
            node->desc.push_back("Size of Block");
            node->value.push_back("");
            node->value.push_back("");

            count = (pIbr->SizeOfBlock - fix_head) >> 1;
            type = (WORD *)((char *)pIbr + fix_head);
            base = pIbr->VirtualAddress;

            for (i = 0; i < count; i++) {
                type_value_high_4 = (((*type) >> 12) & 0x000f);
                type_value_low_12 = (*type) & 0x0fff;
                node->addr.push_back(Addr(IDR_RVA_BAKE, 4));
                node->data.push_back(Addr(*type, 2));
                node->desc.push_back("RVA Type");
                node->value.push_back(Addr(base + type_value_low_12 + startVA,
                                           4) + mapToValue(desc,
                                                           type_value_high_4));

                // cout << Addr(*type, 2);
                type++;
                IDR_RVA_BAKE += 2;
            }

            size -= pIbr->SizeOfBlock;
            IDR_RVA += pIbr->SizeOfBlock;
            pIbr = (PIMAGE_BASE_RELOCATION)(content + (IDR_RVA - dis));
        }
        return node;
    }

    QVector<Node *>init_edata() {
        auto IED_RVA = data_directory[0].VirtualAddress;
        auto IED_SIZE = data_directory[0].Size;
        QVector<Node *> ret;

        if (IED_SIZE == 0) return ret;

        Node *node_EAT = new Node("Export Address Table", true, true);
        Node *node_ENT = new Node("Export Name Pointer Table", true, true);
        Node *node_EOT = new Node("Export order Table", true, true);
        Node *node_EDT = new Node("Export Descriptor Table", true, true);

        ret.reserve(4);
        ret.push_back(node_EDT);
        ret.push_back(node_EAT);
        ret.push_back(node_ENT);
        ret.push_back(node_EOT);

        // 确定RVA所在的段
        auto p = section_header;
        auto N = nt_header->FileHeader.NumberOfSections;

        // Import
        this->index_sectionEAT = 0;

        for (int i = 0; i < N; i++) {
            if ((IED_RVA >= p->VirtualAddress) &&
                (IED_RVA < p->VirtualAddress + p->SizeOfRawData)) {
                break;
            }
            p++;
            this->index_sectionEAT++;
        }
        int dis = p->VirtualAddress - p->PointerToRawData;
        int IED_file_offset = IED_RVA - dis;

        // RVA_Address - (p->)

        PIMAGE_EXPORT_DIRECTORY EDT =
            (PIMAGE_EXPORT_DIRECTORY)(content + IED_file_offset);
        N = 11; // EDT成员个数
        int RVA = data_directory[0].VirtualAddress + startVA;

        QString dllName = (char *)(content + (EDT->Name - dis));

        // (FIRSTTRUNK)IAT函数加载地址  (ORIGNALFIRST_TRUNK)INT函数的导入序号
        // 组合为IMAGE_IMPORT_BY_NAME
        // cout << "dll name :" << dllName;
        const static QStringList desc = { "Characteristics",
                                          "TimeDateStamp",
                                          "MajorVersion",
                                          "MinorVersion",
                                          "Name",
                                          "Base",
                                          "NumberOfFunctions",
                                          "NumberOfNames",
                                          "AddressOfFunctions",
                                          "AddressOfNames",
                                          "AddressOfNameOrdinals" };

        QVector<int> it_value;
        QVector<int> it_size;

        it_size.reserve(N);
        it_value.reserve(N);

        auto it0 = EDT->Characteristics;
        auto it1 = EDT->TimeDateStamp;
        auto it2 = EDT->MajorVersion;
        auto it3 = EDT->MinorVersion;
        auto it4 = EDT->Name;
        auto it5 = EDT->Base;
        auto it6 = EDT->NumberOfFunctions;
        auto it7 = EDT->NumberOfNames;
        auto it8 = EDT->AddressOfFunctions;
        auto it9 = EDT->AddressOfNames;
        auto it10 = EDT->AddressOfNameOrdinals;

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

        for (int i = 0; i < N; i++) {
            node_EDT->addr.push_back(Addr(RVA, 4));
            node_EDT->data.push_back(Addr(it_value[i], it_size[i]));

            if (i == 4) {
                node_EDT->value.push_back(dllName);
            } else {
                node_EDT->value.push_back("");
            }
            node_EDT->desc.push_back(desc[i]);
        }

        // EDT 解析完成
        // 开始解析ENT表
        QString functoinName;
        auto    N_Name = EDT->NumberOfNames; // N_Function =
                                             // EDT->NumberOfFunctions;
        DWORD *funName = (DWORD *)(content + (EDT->AddressOfNames - dis));
        WORD  *funIndex = (WORD *)(content + (EDT->AddressOfNameOrdinals - dis));

        // cout << "N_Function " << N_Name << "N_Name" << N_Name;

        // 初始化ENT EOT
        auto EOT_RVA = EDT->AddressOfNameOrdinals + startVA;
        auto ENT_RVA = EDT->AddressOfNames + startVA;

        for (int i = 0; i < N_Name; i++) {
            functoinName = (char *)(content + (*funName - dis));
            node_EOT->addr.push_back(Addr(EOT_RVA, 4));
            node_ENT->addr.push_back(Addr(ENT_RVA, 4));
            node_EOT->data.push_back(Addr(*funIndex, 2));
            node_ENT->data.push_back(Addr(*funName, 4));
            node_EOT->desc.push_back("Function ordinal");
            node_ENT->desc.push_back("Function Name PVA");
            node_EOT->value.push_back(Addr(*funIndex, 2) + functoinName);
            node_ENT->value.push_back(Addr(*funIndex, 2) + functoinName);

            // cout << "EOT Addr" << Addr(EDT->AddressOfNameOrdinals + i * 2 +
            // startVA, 4)<<"EOTvalue"<<;
            // cout << "ENT Addr" << Addr(EDT->AddressOfNames + i * 4 + startVA,
            // 4);

            // cout << functoinName << " " << Addr(*funIndex, 2) << " " <<
            // Addr(*funName, 4);
            funName++;
            funIndex++;
            EOT_RVA += 2;
            ENT_RVA += 4;
        }

        auto   EAT_RVA = EDT->AddressOfFunctions;
        DWORD *addressOfFunctions =
            (DWORD *)(content + (EDT->AddressOfFunctions - dis));

        for (int i = 0, j = 0; i < EDT->NumberOfFunctions; i++) {
            node_EAT->addr.push_back(Addr(EAT_RVA, 4));
            node_EAT->data.push_back(Addr(*addressOfFunctions, 4));

            if (*addressOfFunctions != 0) {
                node_EAT->desc.push_back("Function RVA");
                node_EAT->value.push_back(node_EOT->value[j]);
                j++;
            } else {
                node_EAT->desc.push_back("");
                node_EAT->value.push_back("");
            }
            addressOfFunctions++;
            EAT_RVA += 4;
        }

        // always true: N_Name <= N_FUnction

        return ret;
    }

    void init_pe_allnodes() {
        // rdata拥有IAT和INT 需要记住相应的位置
        this->index_section_rdata = -1;
        this->index_reloc_table = -1;
        this->index_sectionEAT = -1;
        nodes.push_back(this->init_pe_file());
        nodes.push_back(this->init_dos_header());
        nodes.push_back(this->init_dos_stub());
        nodes.push_back(this->init_nt_header());
        nodes.push_back(this->init_nt_headers_signature());
        nodes.push_back(this->init_nt_headers_file_header());
        nodes.push_back(this->init_nt_headers_optional_header());

        auto section_table = this->init_section_header();

        for (int i = 0; i < section_table.size(); i++) {
            nodes.push_back(section_table[i]);
        }
        auto section = this->init_section();

        auto numberOfSection = this->nt_header->FileHeader.NumberOfSections;

        // 输入表
        auto rdataVector = this->init_rdata();

        // 输出表
        auto edataVector = this->init_edata();

        // 重定位节
        auto relocTable = this->init_reloc_table();

        for (int i = 0; i < numberOfSection; i++) {
            nodes.push_back(section[i]);

            // 重定位表
            if (i == this->index_reloc_table) {
                nodes.push_back(relocTable);
            }

            // 输入表
            if (i == this->index_section_rdata) {
                for (auto it : rdataVector) {
                    nodes.push_back(it);
                }
            }

            // 输出表(exe 一般没有)
            if (i == this->index_sectionEAT) {
                for (auto it : edataVector) {
                    nodes.push_back(it);
                }
            }
        }

        treeList.push_back(nodes[0]->head);
        QString onespace = " ";
        QString twospace = "  ";

        for (int i = 1; i < nodes.size(); i++) {
            if (nodes[i]->isSubTreeNode) {
                treeList.push_back(twospace + nodes[i]->head);
            } else {
                treeList.push_back(onespace + nodes[i]->head);
            }
        }
    }

    /* 产生解释内容  1. node节点 2. 文件偏移开始地址 3.文件块实际大小
     * node 节点
     * raw_offset 相对于文件的偏移
     * raw_size文件的实际尺寸
     * RVA_offset相对的内存布局地址
     * 内存布局的imageBase
     */
    void fillContent(Node *node,
                     int   raw_offset,
                     int   raw_size,
                     int   RVA_offset,
                     int   startVA = 0) {
        if (node->hasDesc == true) {
            return;
        }

        int turn = (raw_size % 16 == 0) ? raw_size / 16 : (raw_size / 16) + 1;
        us *c = (us *)content + raw_offset;

        QByteArray byte = QByteArray((char *)c, raw_size);
        QString    hex_byte = byte.toHex(' ').toUpper();
        RVA_offset += startVA; // 当前地址VA地址

        for (int i = 0; i < turn; i++) {
            //  c 指向此段的内容
            node->addr.append(Addr(RVA_offset, 4));
            RVA_offset += 16;
        }
        QString s;

        for (int i = 0; i < turn; i++) {
            s = hex_byte.mid(i * 48, 24);
            s += " ";
            s += hex_byte.mid(i * 48 + 24, 24);
            node->data.push_back(s);
        }

        stringToAcsII(c, raw_size, node);
    }

    void stringToAcsII(us *str, int size, Node *node) {
        int  integer = size / 16;
        int  remainder = size % 16;
        char space = '.';
        char ch;
        QString s;

        s.reserve(16);
        node->value.clear();
        int i, j, k;

        for (i = 0; i < integer; i++) {
            s.clear();
            k = i * 16;

            for (j = 0; j < 16; j++) {
                ch = str[k++];

                if ((ch >= 0x20) && (ch <= 0x7E)) {
                    s.append(ch);
                } else {
                    s.append(space);
                }
            }
            node->value.append(s);
        }
        s.clear();
        k = integer * 16;

        if (remainder > 0) {
            for (i = 0; i < remainder; i++) {
                ch = str[k++];

                if ((ch >= 0x20) && (ch <= 0x7E)) {
                    s.append(ch);
                } else {
                    s.append(space);
                }
            }
            node->value.append(s);
        }
    }

    void QByteArrayToACSIIString(const QByteArray& byte, Node *node) {
        QString s;

        s.reserve(16);
        char space = '.';
        char ch = byte.at(0);
        ch = (ch >= 0x20 && ch <= 0x7E) ? ch : space;
        s.append(ch);
        int i;

        for (i = 1; i < byte.size(); ++i) {
            if (i % 16 == 0) {
                node->value.push_back(s);
                s.clear();
            }
            ch = byte.at(i);

            if ((ch >= 0x20) && (ch <= 0x7E)) {
                s.append(ch);
            } else {
                s.append(space);
            }
        }

        if ((i % 16 != 0) && !s.isEmpty()) {
            node->value.push_back(s);
        }
    }

    void savenFile(QString& file, us *content) {
        ofstream f(file.toStdString(), ios::binary);

        if (f) {
            f.write((char *)content, file_size);
        } else {}
    }

    static int isPE(PVOID file_content) {
        PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)(file_content);

        // 计算PE头位置  PIMAGE_NT_HEADERS在64位下等价于PIMAGE_NT_HEADERS64
        PIMAGE_NT_HEADERS pNTHeader =
            (PIMAGE_NT_HEADERS)((char *)file_content + pDosHeader->e_lfanew);

        if ((pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) &&
            (pNTHeader->Signature != IMAGE_NT_SIGNATURE)) {
            return 0;
        }

        if (pNTHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
            // printf("64\n");
            return 64;

        if (pNTHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
            // printf("32\n");
            return 32;

        return 0;
    }

    static int file_isPE(const QString& file) {
        ifstream in (file.toStdString(), ios::binary);

        if (!in) {
            perror("file open error");
            exit(-1);
        }
        in.seekg(0, in.end);
        auto file_size = in.tellg();
        in.seekg(0, in.beg); // 定位到文件开始
        us *file_content = new us[file_size];
        memset(file_content, 0, file_size);
        in.read(reinterpret_cast<char *>(file_content), file_size);
        in.close();

        int ret = PE::isPE(file_content);
        delete[]file_content;
        return ret;
    }
};
