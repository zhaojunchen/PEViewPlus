#pragma once
# ifndef _PE_H_
# define _PE_H_

# include "stdio.h"
# include "stdlib.h"
# include "windows.h"

# define FILE_PATH "C:/Users/ls/Desktop/hello.exe"
//# define FILE_PATH "C:/Users/ls/Desktop/proj4.dll"
//# define FILE_PATH "C:/Users/ls/Desktop/puiapi.dll"
//# define FILE_PATH "C:/Users/ls/Desktop/SteamSetup.exe"
//# define FILE_PATH "C:/Users/ls/Desktop/test64.exe"

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

# ifdef __cplusplus
}
# endif
# endif
