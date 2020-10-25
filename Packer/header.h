#pragma once
#include <Windows.h>
#include <stdio.h>
#include <strsafe.h>


typedef struct PESTRUCT
{
	IMAGE_DATA_DIRECTORY IAT;

	IMAGE_DATA_DIRECTORY ROC;

	PVOID mem_pe_base;

	PIMAGE_OPTIONAL_HEADER m_dwpOptHeader;

	DWORD OEP;

}Pestruct;

typedef struct STRUCTUNPACKER
{
	PVOID pNewDllTextSec;

	INT dwSecSize;

	DWORD unpackerStartfunc;

}StructUnPacker;


Pestruct InitStuct(Pestruct m_pestruct);

/**
* @brief Need save to file data
*/
//strlen(compreed data)
INT m_dwCompressedDataSize;



/**
* @brief class global variable
*/
BOOL IsDebug;
DWORD m_dwOldEntryPoint;
DWORD m_dwFileSize;
LPCSTR m_pSouceFile;
PVOID m_dwpPeBase;
PIMAGE_DOS_HEADER m_dwpDosHeader;
PIMAGE_NT_HEADERS m_dwpNTHeader;
PIMAGE_FILE_HEADER m_dwpFileHeader;
PIMAGE_OPTIONAL_HEADER m_dwpOptHeader;
PIMAGE_SECTION_HEADER m_dwpLastSec;
PVOID m_dwpNePeMem;

//Points to the compressed code
PVOID m_dwpComperedData;
//Points to the Section headers 
PVOID m_dwpSecheadersData;

LPWSTR DllPath = TEXT("C:\\Users\\Cray\\Desktop\\Packer\\Release\\Packdll.dll");
LPWSTR FilePath = TEXT("C:\\Users\\Cray\\Desktop\\Packer\\Release\\Mssb.exe");

/**
* @brief Functions
*/
PVOID LoadFile2Mem(LPWSTR m_pSouceFile);
BOOL Run(LPCSTR sourceFile);
VOID GetError(LPCSTR lpszFunction);
VOID EncryptExc(Pestruct);
VOID ClearI_AT_ROC(Pestruct);
StructUnPacker LoadPackdll();
VOID ConstructNewPE(Pestruct, StructUnPacker);

PIMAGE_DOS_HEADER GetDosHeader(PVOID m_dwpPeBase);
PIMAGE_NT_HEADERS GetNTHeader(PVOID m_dwpPeBase);
PIMAGE_FILE_HEADER GetFileHeader(PVOID m_dwpPeBase);
PIMAGE_OPTIONAL_HEADER GetOptHeader(PVOID m_dwpPeBase);
PIMAGE_SECTION_HEADER LastSecionheader(PVOID m_dwpPeBase);
PIMAGE_SECTION_HEADER GetSecionheader(PVOID m_dwpPeBase);
DWORD CalcCompreDataSize(PVOID m_dwpPeBase);
PVOID CompreData(PVOID m_dwpPeBase, INT m_compre_data_size);
VOID dprintf(LPCSTR pPrintf_mes);
PVOID SaveSecheader(PVOID m_dwpPeBase);
PVOID Copy2NewMem(PVOID m_dwpPeBase, INT m_dwCompressedDataSize, PVOID m_dwpComperedData, INT m_dwSizeOfDecMem, PVOID m_dwpDecMem);
INT GetAlignment(INT Alignment, INT FixValue);
PVOID UpdateHeader(PVOID m_dwpPeBase, INT m_firstsecsize);

int __CRTDECL mprintf(
	_In_z_ _Printf_format_string_ char const* const _Format,
	...);
