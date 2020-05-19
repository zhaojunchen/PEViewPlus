# define _CRT_SECURE_NO_WARNINGS
# include "PE.h"

int GetFileLength(FILE* pf, DWORD* Length)
{
	int ret = 0;

	fseek(pf, 0, SEEK_END);
	*Length = ftell(pf);
	fseek(pf, 0, SEEK_SET);

	return ret;
}

int MyReadFile(void** pFileAddress)
{
	int ret = 0;
	DWORD Length = 0;
	//打开文件
	FILE* pf = fopen(FILE_PATH, "rb");
	if (pf == NULL)
	{
		ret = -1;
		printf("func ReadFile() Error!\n");
		return ret;
	}

	//获取文件长度
	ret = GetFileLength(pf, &Length);
	if (ret != 0 && Length == -1)
	{
		ret = -2;
		printf("func GetFileLength() Error!\n");
		return ret;
	}

	//分配空间
	*pFileAddress = (PVOID)malloc(Length);
	if (*pFileAddress == NULL)
	{
		ret = -3;
		printf("func malloc() Error!\n");
		return ret;
	}
	memset(*pFileAddress, 0, Length);

	//读取文件进入内存
	fread(*pFileAddress, Length, 1, pf);

	fclose(pf);
	return ret;
}


int MyReadFile_V2(void** pFileAddress, PCHAR FilePath)
{
	int ret = 0;
	DWORD Length = 0;
	//打开文件
	FILE* pf = fopen(FilePath, "rb");
	if (pf == NULL)
	{
		ret = -1;
		printf("func ReadFile() Error!\n");
		return ret;
	}

	//获取文件长度
	ret = GetFileLength(pf, &Length);
	if (ret != 0 && Length == -1)
	{
		ret = -2;
		printf("func GetFileLength() Error!\n");
		return ret;
	}

	//分配空间
	*pFileAddress = (PVOID)malloc(Length);
	if (*pFileAddress == NULL)
	{
		ret = -3;
		printf("func malloc() Error!\n");
		return ret;
	}
	memset(*pFileAddress, 0, Length);

	//读取文件进入内存
	fread(*pFileAddress, Length, 1, pf);

	fclose(pf);
	return ret;
}

int MyWriteFile(PVOID pFileAddress, DWORD FileSize, LPSTR FilePath)
{
	int ret = 0;

	FILE* pf = fopen(FilePath, "wb");
	if (pf == NULL)
	{
		ret = -5;
		printf("func fopen() error :%d!\n", ret);
		return ret;
	}

	fwrite(pFileAddress, FileSize, 1, pf);

	fclose(pf);

	return ret;
}

int FOA_TO_RVA(PVOID FileAddress, DWORD FOA, PDWORD pRVA)
{
	int ret = 0;

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)(FileAddress);
	PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pFileHeader + sizeof(IMAGE_FILE_HEADER));
	PIMAGE_SECTION_HEADER pSectionGroup = (PIMAGE_SECTION_HEADER)((DWORD)pOptionalHeader + pFileHeader->SizeOfOptionalHeader);

	//FOA在文件头中 或 SectionAlignment 等于 FileAlignment 时RVA等于FOA
	if (FOA < pOptionalHeader->SizeOfHeaders || pOptionalHeader->SectionAlignment == pOptionalHeader->FileAlignment)
	{
		*pRVA = FOA;
		return ret;
	}
	//FOA在节区中
	for (int i = 0; i < pFileHeader->NumberOfSections; i++)
	{
		if (FOA >= pSectionGroup[i].PointerToRawData && FOA < pSectionGroup[i].PointerToRawData + pSectionGroup[i].SizeOfRawData)
		{
			*pRVA = pSectionGroup[i].VirtualAddress + FOA - pSectionGroup[i].PointerToRawData;
			return ret;
		}
	}
	//没有找到地址
	ret = -4;
	printf("func FOA_TO_RVA() Error: %d 地址转换失败！\n", ret);
	return ret;
}

int RVA_TO_FOA(PVOID FileAddress, DWORD RVA, PDWORD pFOA)
{
	int ret = 0;

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)(FileAddress);
	PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pFileHeader + sizeof(IMAGE_FILE_HEADER));
	PIMAGE_SECTION_HEADER pSectionGroup = (PIMAGE_SECTION_HEADER)((DWORD)pOptionalHeader + pFileHeader->SizeOfOptionalHeader);

	//RVA在文件头中 或 SectionAlignment 等于 FileAlignment 时RVA等于FOA
	if (RVA < pOptionalHeader->SizeOfHeaders || pOptionalHeader->SectionAlignment == pOptionalHeader->FileAlignment)
	{
		*pFOA = RVA;
		return ret;
	}
	//RVA在节区中
	for (int i = 0; i < pFileHeader->NumberOfSections; i++)
	{
		if (RVA >= pSectionGroup[i].VirtualAddress && RVA < pSectionGroup[i].VirtualAddress + pSectionGroup[i].Misc.VirtualSize)
		{
			*pFOA = pSectionGroup[i].PointerToRawData + RVA - pSectionGroup[i].VirtualAddress;
			return ret;
		}
	}
	//没有找到地址
	ret = -4;
	printf("func RVA_TO_FOA() Error: %d 地址转换失败！\n", ret);
	return ret;
}

//int RVA_TO_FOA_64() {};
//int FOA_TO_RVA_64() {};

int checkFile(PVOID FileAddress)
{
	int ret = 0;
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)(FileAddress);
	//计算PE头位置
	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)FileAddress + pDosHeader->e_lfanew);
	PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 4);
	PIMAGE_OPTIONAL_HEADER pOptionalHeader = (PIMAGE_OPTIONAL_HEADER)((DWORD)pFileHeader + sizeof(IMAGE_FILE_HEADER));
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE || pNTHeader->Signature != IMAGE_NT_SIGNATURE) 
	{
		printf("Not a pe file!\n");
		return -1;
	}
	//printf("%02X\n", pDosHeader->e_magic);
	//if (pNTHeader->Signature == 0x4550)
		//printf("okk2\n");
	//printf("%04X\n", pNTHeader->Signature);

	//简单返回32or64
	if (pOptionalHeader->Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
		return 64;
	if (pOptionalHeader->Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
		return 32;
	//0x0100  32 bit word machine. 0x2000   File is a DLL.
	//printf("%02X\n", pOptionalHeader->Magic);

	//判断是EXE还是DLL
	/*if ((pFileHeader->Characteristics & 0x3000) == 0x2000) {
		printf("DLL\n");
	}
	else
	{
		printf("EXE\n");
	}*/
	//if ((pFileHeader->Characteristics & 0x100) == 0x100)
		//printf("EXE\n");
	//printf("%02X\n", pFileHeader->Characteristics);
	return ret;
}
