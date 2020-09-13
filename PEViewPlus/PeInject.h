# ifdef __cplusplus
extern "C" {
# endif

    int GetFileLength(FILE* pf, DWORD* Length);

    int MyReadFile(void** pFileAddress);

    int MyReadFile_V2(void** pFileAddress, PCHAR FilePath);

    int MyWriteFile(PVOID pFileAddress, DWORD FileSize, LPSTR FilePath);

    int FOA_TO_RVA(PVOID FileAddress, DWORD FOA, PDWORD pRVA);

    int RVA_TO_FOA(PVOID FileAddress, DWORD RVA, PDWORD pFOA);

    int checkFile(PVOID FileAddress);

    int PEInject(PVOID FileAddress, PDWORD FileLength, PCHAR FilePath);

    int PEInject_64(PVOID FileAddress, PDWORD FileLength, PCHAR FilePath);

    //QString inject(char oldFile[50], char newFile[50] = "C:/Users/ls/Desktop/inject_out.exe");//改一下路径

    QString pError(int num);

# ifdef __cplusplus
}
# endif

int GetFileLength(FILE* pf, DWORD* Length) {
    int ret = 0;

    fseek(pf, 0, SEEK_END);
    *Length = ftell(pf);
    fseek(pf, 0, SEEK_SET);

    return ret;
}

int MyReadFile(void** pFileAddress, PCHAR FilePath) {
    int ret = 0;
    DWORD Length = 0;
    //打开文件
    FILE* pf = fopen(FilePath, "rb");
    if (pf == NULL) {
        ret = -1;
        ////printf("func ReadFile() Error!\n");
        return ret;
    }

    //获取文件长度
    ret = GetFileLength(pf, &Length);
    if (ret != 0 && Length == -1) {
        ret = -2;
        ////printf("func GetFileLength() Error!\n");
        return ret;
    }

    //分配空间
    *pFileAddress = (PVOID)malloc(Length);
    if (*pFileAddress == NULL) {
        ret = -3;
        ////printf("func malloc() Error!\n");
        return ret;
    }
    memset(*pFileAddress, 0, Length);

    //读取文件进入内存
    fread(*pFileAddress, Length, 1, pf);

    fclose(pf);
    return ret;
}

int MyReadFile_V2(void** pFileAddress, PCHAR FilePath) {
    int ret = 0;
    DWORD Length = 0;
    //打开文件
    FILE* pf = fopen(FilePath, "rb");
    if (pf == NULL) {
        ret = -1;
        ////printf("filePath Error!\n");
        return ret;
    }

    //获取文件长度
    ret = GetFileLength(pf, &Length);
    if (ret != 0 && Length == -1) {
        ret = -2;
        ////printf("func GetFileLength() Error!\n");
        return ret;
    }

    //分配空间
    *pFileAddress = (PVOID)malloc(Length + 512);//（512）FIleAlignment  在不知道的情况下可以设大点
    if (*pFileAddress == NULL) {
        ret = -3;
        ////printf("func malloc() Error!\n");
        return ret;
    }
    memset(*pFileAddress, 0, Length + 512);

    //读取文件进入内存
    fread(*pFileAddress, Length, 1, pf);

    fclose(pf);
    return ret;
}

int MyWriteFile(PVOID pFileAddress, DWORD FileSize, LPSTR FilePath) {
    int ret = 0;

    FILE* pf = fopen(FilePath, "wb");
    if (pf == NULL) {
        ret = -5;
        ////printf("func fopen() error :%d!\n", ret);
        return ret;
    }

    fwrite(pFileAddress, FileSize, 1, pf);

    fclose(pf);

    return ret;
}

int FOA_TO_RVA(PVOID FileAddress, DWORD FOA, PDWORD pRVA) {
    int ret = 0;

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)(FileAddress);
    PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 4);
    PIMAGE_OPTIONAL_HEADER32 pOptionalHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pFileHeader + sizeof(IMAGE_FILE_HEADER));
    PIMAGE_SECTION_HEADER pSectionGroup = (PIMAGE_SECTION_HEADER)((DWORD)pOptionalHeader + pFileHeader->SizeOfOptionalHeader);

    //FOA在文件头中 或 SectionAlignment 等于 FileAlignment 时RVA等于FOA
    if (FOA < pOptionalHeader->SizeOfHeaders || pOptionalHeader->SectionAlignment == pOptionalHeader->FileAlignment) {
        *pRVA = FOA;
        return ret;
    }
    //FOA在节区中
    for (int i = 0; i < pFileHeader->NumberOfSections; i++) {
        if (FOA >= pSectionGroup[i].PointerToRawData && FOA < pSectionGroup[i].PointerToRawData + pSectionGroup[i].SizeOfRawData) {
            *pRVA = pSectionGroup[i].VirtualAddress + FOA - pSectionGroup[i].PointerToRawData;
            return ret;
        }
    }
    //没有找到地址
    ret = -4;
    ////printf("func FOA_TO_RVA() Error: %d 地址转换失败！\n", ret);
    return ret;
}

int RVA_TO_FOA(PVOID FileAddress, DWORD RVA, PDWORD pFOA) {
    int ret = 0;

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)(FileAddress);
    PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 4);
    PIMAGE_OPTIONAL_HEADER32 pOptionalHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pFileHeader + sizeof(IMAGE_FILE_HEADER));
    PIMAGE_SECTION_HEADER pSectionGroup = (PIMAGE_SECTION_HEADER)((DWORD)pOptionalHeader + pFileHeader->SizeOfOptionalHeader);

    //RVA在文件头中 或 SectionAlignment 等于 FileAlignment 时RVA等于FOA
    if (RVA < pOptionalHeader->SizeOfHeaders || pOptionalHeader->SectionAlignment == pOptionalHeader->FileAlignment) {
        *pFOA = RVA;
        return ret;
    }
    //RVA在节区中
    for (int i = 0; i < pFileHeader->NumberOfSections; i++) {
        if (RVA >= pSectionGroup[i].VirtualAddress && RVA < pSectionGroup[i].VirtualAddress + pSectionGroup[i].Misc.VirtualSize) {
            *pFOA = pSectionGroup[i].PointerToRawData + RVA - pSectionGroup[i].VirtualAddress;
            return ret;
        }
    }
    //没有找到地址
    ret = -4;
    ////printf("func RVA_TO_FOA() Error: %d 地址转换失败！\n", ret);
    return ret;
}


int checkFile(PVOID FileAddress) {
    int ret = 0;
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)(FileAddress);
    //计算PE头位置  PIMAGE_NT_HEADERS在64位下等价于PIMAGE_NT_HEADERS64
    PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((char*)FileAddress + pDosHeader->e_lfanew);
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE && pNTHeader->Signature != IMAGE_NT_SIGNATURE) {
        return ret;
    }
    if (pNTHeader->OptionalHeader.Magic == 0x20b)
        //printf("64\n");
        return 64;
    if (pNTHeader->OptionalHeader.Magic == 0x10b)
        //printf("32\n");
        return 32;
    return ret;
}

int PEInject(PVOID FileAddress, PDWORD FileLength, PCHAR FilePath) {
    int ret = 0;

    FILE* pf = fopen(FilePath, "rb");
    if (pf == NULL) {
        ret = -1;
        printf("func fopen() Error: %d\n", ret);
        return ret;
    }
    ret = GetFileLength(pf, FileLength);
    if (ret != 0 && *FileLength == -1) {
        ret = -2;
        printf("func GetFileLength() Error!\n");
        return ret;
    }
    // 初始化
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)(FileAddress);
    PIMAGE_NT_HEADERS32 pNtHeaders = (PIMAGE_NT_HEADERS32)((us*)FileAddress + pDosHeader->e_lfanew);
    PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)((us*)pDosHeader + pDosHeader->e_lfanew + 4);
    PIMAGE_OPTIONAL_HEADER32 pOptionalHeader = (PIMAGE_OPTIONAL_HEADER32)((us*)pFileHeader + sizeof(IMAGE_FILE_HEADER));

    WORD numberOfSections = pFileHeader->NumberOfSections;
    // 节表数
    pFileHeader->NumberOfSections = pFileHeader->NumberOfSections + 1;

    DWORD AddressOfEntryPoint = pOptionalHeader->AddressOfEntryPoint;

    WORD optionHeaderSize = pFileHeader->SizeOfOptionalHeader;
    //
    PIMAGE_SECTION_HEADER pimageSectionHeader = (PIMAGE_SECTION_HEADER)((us*)pOptionalHeader + optionHeaderSize);

    PIMAGE_SECTION_HEADER pSection = pimageSectionHeader + numberOfSections - 1;
    //
    DWORD lastSectionSizeInMem;

    // printf("%d", NumberOfSections);
    // 判断???
    if (pSection->SizeOfRawData % pOptionalHeader->SectionAlignment == 0) {
        lastSectionSizeInMem = pSection->SizeOfRawData;
    } else {
        lastSectionSizeInMem = ((pSection->SizeOfRawData / pOptionalHeader->SectionAlignment) + 1) * pOptionalHeader->SectionAlignment;
    }
    // 程序入口点
    DWORD NewAddressOfEntryPoint = pSection->VirtualAddress + lastSectionSizeInMem;
    pOptionalHeader->AddressOfEntryPoint = NewAddressOfEntryPoint;
    // shellcode在文件的偏移（最后一个节的文件起始地址+节大小）恰好等于文件原始大小
    // 这个地址就是新节的在文件的起始地址
    DWORD shellcodeInjectAddress = pSection->SizeOfRawData + pSection->PointerToRawData;

    pSection++;// 转到新建节
    // 设置新节的属性
    memset(pSection->Name, 0, 8);
    memcpy((char*)pSection->Name, ".new", 5);

    pSection->Misc.VirtualSize = pOptionalHeader->FileAlignment;
    pSection->VirtualAddress = NewAddressOfEntryPoint;
    pSection->SizeOfRawData = pOptionalHeader->FileAlignment;
    pSection->PointerToRawData = shellcodeInjectAddress;
    // 可读可写可执行
    pSection->Characteristics = 0xE00000E0;
    pOptionalHeader->SizeOfImage = NewAddressOfEntryPoint + pSection->Misc.VirtualSize;

    unsigned char* shell = (unsigned char*)((us*)FileAddress + shellcodeInjectAddress);

    char ShellCode[] =
        "\x31\xD2\x52\x68\x63\x61\x6C\x63\x54\x59\x52\x51\x64\x8B\x72\x30\x8B\x76\x0C\x8B\x76\x0C\xAD\x8B"
        "\x30\x8B\x7E\x18\x8B\x5F\x3C\x8B\x5C\x3B\x78\x8B\x74\x1F\x20\x01\xFE\x8B\x54\x1F\x24"
        "\x0F\xB7\x2C\x17\x42\x42\xAD\x81\x3C\x07\x57\x69\x6E\x45\x75\xF0\x8B\x74\x1F\x1C\x01\xFE\x03\x3C\xAE\xFF\xD7";
    // 参考 https://github.com/peterferrie/win-exec-calc-shellcode

    memcpy(shell, ShellCode, strlen(ShellCode));
    shell = shell + strlen(ShellCode);
    // shell 后续的JMP内容
    // \xE8\x00\x00\x00\x00 \x58 \x83\xE8\x4D \x2D\x00\x00\x00\x00 \x05\x00\x00\x00\x00 \xFF\xE0
    // call 0x00000000;
    // pop eax;
    // 防止字符串被截断
    memcpy(shell, "\xE8\x00\x00\x00\x00\x58", 6);
    shell = shell + 6;

    //sub eax,0x4d [strlen(ShellCode)+5]
    unsigned char cmd_1[] = "\x83\xE8\x4D";
    memcpy(shell, cmd_1, 3);
    shell = shell + 3;

    //sub eax,0x00000000;//
    //add eax,0x00000000;//
    //jmp eax;FFE0
    unsigned char cmd_2[13] = "\x2D\x00\x00\x00\x00\x05\x00\x00\x00\x00\xFF\xE0";
    memcpy(cmd_2 + 1, &NewAddressOfEntryPoint, 4);
    memcpy(cmd_2 + 6, &AddressOfEntryPoint, 4);
    memcpy(shell, cmd_2, 12);

    return ret;
}
int PEInject_64(PVOID FileAddress, PDWORD FileLength, PCHAR FilePath) {
    int ret = 0;

    FILE* pf = fopen(FilePath, "rb");
    if (pf == NULL) {
        ret = -1;
        printf("func fopen() Error: %d\n", ret);
        return ret;
    }
    ret = GetFileLength(pf, FileLength);
    if (ret != 0 && *FileLength == -1) {
        ret = -2;
        printf("func GetFileLength() Error!\n");
        return ret;
    }

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)(FileAddress);
    PIMAGE_NT_HEADERS64 pNtHeaders64 = (PIMAGE_NT_HEADERS64)((us*)FileAddress + pDosHeader->e_lfanew);;
    PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)((us*)pDosHeader + pDosHeader->e_lfanew + 4);
    PIMAGE_OPTIONAL_HEADER64 pOptionalHeader64 = (PIMAGE_OPTIONAL_HEADER64)((us*)pFileHeader + sizeof(IMAGE_FILE_HEADER));
    // 节表数
    WORD NumberOfSections = pFileHeader->NumberOfSections;

    pFileHeader->NumberOfSections = pFileHeader->NumberOfSections + 1;
    DWORD addressOfEntryPoint = pOptionalHeader64->AddressOfEntryPoint;

    WORD optionHeaderSize = pFileHeader->SizeOfOptionalHeader;

    PIMAGE_SECTION_HEADER pimageSectionHeader = (PIMAGE_SECTION_HEADER)((us*)pOptionalHeader64 + optionHeaderSize);
    PIMAGE_SECTION_HEADER pSection = pimageSectionHeader + NumberOfSections - 1;
    //
    DWORD lastSectionSizeInMem;

    if (pSection->SizeOfRawData % pOptionalHeader64->SectionAlignment == 0) {
        lastSectionSizeInMem = pSection->SizeOfRawData;
    } else {
        lastSectionSizeInMem = ((pSection->SizeOfRawData / pOptionalHeader64->SectionAlignment) + 1) * pOptionalHeader64->SectionAlignment;
    }
    // 程序入口点
    DWORD NewAddressOfEntryPoint = pSection->VirtualAddress + lastSectionSizeInMem;
    pOptionalHeader64->AddressOfEntryPoint = NewAddressOfEntryPoint;
    // shellcode在文件的偏移（最后一个节的文件起始地址+节大小）恰好等于文件原始大小
    // 这个地址就是新节的在文件的起始地址
    DWORD shellcodeInjectAddress = pSection->SizeOfRawData + pSection->PointerToRawData;

    pSection++;// 转到新建节
    // 设置新节的属性
    memset(pSection->Name, 0, 8);
    memcpy((char*)pSection->Name, ".new", 5);

    pSection->Misc.VirtualSize = pOptionalHeader64->FileAlignment;
    pSection->VirtualAddress = NewAddressOfEntryPoint;
    pSection->SizeOfRawData = pOptionalHeader64->FileAlignment;
    pSection->PointerToRawData = shellcodeInjectAddress;
    // 可读可写可执行
    pSection->Characteristics = 0xE00000E0;
    pOptionalHeader64->SizeOfImage = NewAddressOfEntryPoint + pSection->Misc.VirtualSize;

    unsigned char* shell = (unsigned char*)((us*)FileAddress + shellcodeInjectAddress);

    char ShellCode_64[] =
        "\x6A\x60\x5A\x68\x63\x61\x6C\x63\x54\x59\x48\x29\xD4\x65\x48\x8B"
        "\x32\x48\x8B\x76\x18\x48\x8B\x76\x10\x48\xAD\x48\x8B\x30\x48\x8B"
        "\x7E\x30\x03\x57\x3C\x8B\x5C\x17\x28\x8B\x74\x1F\x20\x48\x01\xFE"
        "\x8B\x54\x1F\x24\x0F\xB7\x2C\x17\x8D\x52\x02\xAD\x81\x3C\x07\x57"
        "\x69\x6E\x45\x75\xEF\x8B\x74\x1F\x1C\x48\x01\xFE\x8B\x34\xAE\x48"
        "\x01\xF7\x99\xFF\xD7";
    //参考 https://github.com/peterferrie/win-exec-calc-shellcode
    //后续jmp "\xE8\x00\x00\x00\x00 \x58 \x48\x83\xE8\x5A \x48\x2D\x44\x33\x22\x11 \x48\x05\x88\x77\x66\x55 \xFF\xE0"

    memcpy(shell, ShellCode_64, strlen(ShellCode_64));
    shell = shell + strlen(ShellCode_64);
    //CALL 	0x00000000;
    //POP 	rax;
    memcpy(shell, "\xE8\x00\x00\x00\x00\x58", 6);
    shell = shell + 6;
    //SUB  	rax, 0x5A;
    unsigned char cmd_1[] = "\x48\x83\xE8\x5A";//85+5=90  0x5a
    memcpy(shell, cmd_1, 4);
    shell = shell + 4;

    //SUB 	rax, 0x11223344;
    //ADD 	rax, 0x55667788;
    //JMP 	rax;
    unsigned char cmd_2[15] = "\x48\x2D\x44\x33\x22\x11\x48\x05\x88\x77\x66\x55\xFF\xE0";
    memcpy(cmd_2 + 2, &NewAddressOfEntryPoint, 4);
    memcpy(cmd_2 + 8, &addressOfEntryPoint, 4);
    memcpy(shell, cmd_2, 14);

    return ret;
}
QString pError(int num) {
    QString tmp;
    if (num == 0) {
        tmp = "Inject success!";
    } else {
        tmp = "Inject failed!";
    }
    return tmp;
}

//QString inject(char oldFile[50], char newFile[50] = "C:/Users/ls/Desktop/inject_out.exe")
int inject(QString oldF, QString newF = "C:/inject_out.exe") {
    int ret, ret_1;
    PVOID FileAddress = NULL;
    DWORD FileLength = 0;
    // QString result = "exit";

    //1、将文件读入到内存
    ret = MyReadFile_V2(&FileAddress, (PCHAR)oldF.toLatin1().data());
    if (ret != 0) {
        if (FileAddress != NULL)
            free(FileAddress);
        return ret;
    }
    //checkFile
    ret = checkFile(FileAddress);
    if (ret == 32) {
        ret_1 = PEInject(FileAddress, &FileLength, (PCHAR)oldF.toLatin1().data());
        if (ret_1 != 0) {
            if (FileAddress != NULL)
                free(FileAddress);
            return ret_1;
        }
    } else if (ret == 64) {
        ret_1 = PEInject_64(FileAddress, &FileLength, (PCHAR)oldF.toLatin1().data());
        if (ret_1 != 0) {
            if (FileAddress != NULL)
                free(FileAddress);
            return ret_1;
        }
    } else {
        if (FileAddress != NULL)
            free(FileAddress);
        return ret;
    }

    ret = MyWriteFile(FileAddress, FileLength + 512, newF.toLatin1().data());
    if (ret != 0) {
        if (FileAddress != NULL)
            free(FileAddress);
        return ret;
    }

    if (FileAddress != NULL)
        free(FileAddress);
    return ret;
}
