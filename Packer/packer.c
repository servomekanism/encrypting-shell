#include "header.h"



/**
* @brief GetLastError and printf chinese  info
* @param lpszFunction hint
*/
void GetError(LPCSTR lpszFunction)
{
	LPVOID lpMsgBuf;
	char Mes[1024] = { 0, };
	LPVOID lpDisplayBuf;
	DWORD dw = GetLastError();

	FormatMessageA(
		FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		dw,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPSTR)&lpMsgBuf,
		0, NULL);
	sprintf_s(Mes, 1024, "[!] %s failed with error 0x%x: %s\nProcess will Kill", lpszFunction, dw, lpMsgBuf);
	mprintf(Mes);
	getchar();
	ExitProcess(dw);
}

/**
* @brief Load soucer file to memory
* @param m_pSouceFile soucefile path
* @return new memory addr
*/
PVOID LoadFile2Mem(LPWSTR m_pSouceFile)
{
	HANDLE hFile = CreateFile(m_pSouceFile, GENERIC_READ, NULL, NULL, OPEN_EXISTING, NULL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		GetError("loadFileToMem_CrateFile!");
		return NULL;
	}

	DWORD m_dwFileSize = GetFileSize(hFile, NULL);

	PVOID pPeBase = malloc(m_dwFileSize * sizeof(BYTE));
	memset(pPeBase, 0, m_dwFileSize);

	DWORD dwRead = 0;

	ReadFile(hFile, pPeBase, m_dwFileSize, &dwRead, NULL);

	CloseHandle(hFile);

	return pPeBase;
}
/**
* @brief GetDosHeader
* @param m_dwpPeBase  pMemFile
* @return DosHeader
*/
PIMAGE_DOS_HEADER GetDosHeader(PVOID m_dwpPeBase)
{
	return (PIMAGE_DOS_HEADER)m_dwpPeBase;
}
/**
* @brief GetNTHeader
* @param m_dwpPeBase pMemFile
* @return Ntheader
*/
PIMAGE_NT_HEADERS GetNTHeader(PVOID m_dwpPeBase)
{
	return (PIMAGE_NT_HEADERS)((PBYTE)GetDosHeader(m_dwpPeBase)->e_lfanew + (DWORD)m_dwpPeBase);
}
/**
* @brief GetFileHeader
* @param m_dwpPeBase pMemFile
* @return FileHeader
*/
PIMAGE_FILE_HEADER GetFileHeader(PVOID m_dwpPeBase)
{
	return (PIMAGE_FILE_HEADER)((PBYTE)GetNTHeader(m_dwpPeBase) + 4);
}

/**
* @brief GetOptHeader
* @param m_dwpPeBase  pMemFile
* @return OptHeader
*/
PIMAGE_OPTIONAL_HEADER GetOptHeader(PVOID m_dwpPeBase)
{
	return (PIMAGE_OPTIONAL_HEADER)((PBYTE)GetFileHeader(m_dwpPeBase) + sizeof(IMAGE_FILE_HEADER));
}

/**
* @brief GetlastSec
* @param m_dwpPeBase  pMemFile
* @return The PE File LastSecionheader
*/
PIMAGE_SECTION_HEADER LastSecionheader(PVOID m_dwpPeBase)
{
	return (PIMAGE_SECTION_HEADER)((PBYTE)(IMAGE_FIRST_SECTION(GetNTHeader(m_dwpPeBase))) + sizeof(IMAGE_SECTION_HEADER) * (GetFileHeader(m_dwpPeBase)->NumberOfSections - 1));
}

/**
* @brief GetSecionheader
* @param m_dwpPeBase  pMemFile
* @return The PE File Secionheaders
*/
PIMAGE_SECTION_HEADER GetSecionheader(PVOID m_dwpPeBase)
{
	return IMAGE_FIRST_SECTION(GetNTHeader(m_dwpPeBase));
}

/**
* @brief calc File Size to exclude SizeOfHeaders, using to compression
* @param m_dwpPeBase pMemFile
* @return sizeofimage - SizeOfHeaders
*/
DWORD CalcCompreDataSize(PVOID m_dwpPeBase)
{
	PIMAGE_SECTION_HEADER pLastSec = LastSecionheader(m_dwpPeBase);
	DWORD BinFileSize = pLastSec->PointerToRawData + pLastSec->SizeOfRawData;
	return BinFileSize - GetOptHeader(m_dwpPeBase)->SizeOfHeaders;
}

/**
* @brief compression data
* @param m_dwpPeBase pMemFile
* @param m_dwcompre_data_size  want to compre data size
* @return
*/
PVOID CompreData(PVOID m_dwpPeBase, INT m_compre_data_size)
{
	INT m_max_dst_size = 0;

	PCHAR compressed_data = (PCHAR)malloc((size_t)m_max_dst_size);
	if (compressed_data == NULL)
	{
		GetError("CompreData_malloc");
		return NULL;
	}

	PCHAR m_psouce_data = (PCHAR)m_dwpPeBase + GetOptHeader(m_dwpPeBase)->SizeOfHeaders;

	m_dwCompressedDataSize = 0;

	if (m_dwCompressedDataSize <= 0)
	{
		GetError("CompreData_LZ4_compress_default");
		free(compressed_data);
		return NULL;
	}

	char tmp_print_info[MAX_PATH];
	FLOAT ratio = (FLOAT)m_dwCompressedDataSize / m_compre_data_size;
	sprintf_s(tmp_print_info, MAX_PATH, "ratio : %.2f\n", ratio);

	compressed_data = (PCHAR)realloc(compressed_data, m_dwCompressedDataSize);

	if (compressed_data == NULL)
	{
		GetError("CompreData_realloc");
		return NULL;
	}

	return compressed_data;
}



/**
* @brief Save the section headers
* @param m_dwpPeBase pPeBase
* @return Section headers
*/

PVOID SaveSecheader(PVOID m_dwpPeBase)
{
	PVOID m_psec = (PVOID)IMAGE_FIRST_SECTION(GetNTHeader(m_dwpPeBase));

	INT m_secSize = GetFileHeader(m_dwpPeBase)->NumberOfSections * sizeof(IMAGE_SECTION_HEADER);

	PVOID m_pSecCopy = malloc(m_secSize);

	if (m_pSecCopy == NULL)
	{
		GetError("SaveSecheader_malloc");
		return NULL;
	}

	memcpy_s(m_pSecCopy, m_secSize, m_psec, m_secSize);

	return m_pSecCopy;
}

/**
* @brief Gets alignment values based on size
* @param Alignment  FileAlignment or SectionAlignment
* @param FixValue Need to fix value
* @return fixed value
*/
INT GetAlignment(INT Alignment, INT FixValue)
{
	return FixValue % Alignment == 0 ? FixValue : (FixValue / Alignment + 1) * Alignment;

}

/**
* @brief 修改节个数 、待后续补充
* @param m_dwpPeBase
* @param m_firstsecsize
* @return
*/
PVOID UpdateHeader(PVOID m_dwpPeBase, INT m_firstsecsize)
{
	INT m_sizeofheader = GetOptHeader(m_dwpPeBase)->SizeOfHeaders;
	PVOID m_ppeheader = malloc(m_sizeofheader);
	if (m_ppeheader == NULL)
	{
		GetError("m_dwpPeBase_malloc");
		return NULL;
	}
	memcpy_s(m_ppeheader, m_sizeofheader, m_dwpPeBase, m_sizeofheader);

	GetFileHeader(m_ppeheader)->NumberOfSections = 2;
	PIMAGE_SECTION_HEADER m_psec = GetSecionheader(m_ppeheader);

	*(m_psec->Name) = (char)"0Ops!";

	m_psec->SizeOfRawData = m_firstsecsize;

	*(m_psec[1].Name) = (char)"MyPack!";

	return m_ppeheader;
}

//加密代码段，加密方式 Key = timestap^0x12344321
VOID EncryptExc(Pestruct m_pestruct)
{
	DWORD start = 0;
	DWORD end = 0;
	PDWORD FileStart = 0;
	DWORD Encryptsize = 0;
	INT i = 0;

	DWORD encryptKey =
		GetFileHeader(m_pestruct.mem_pe_base)->TimeDateStamp;
	
	encryptKey = encryptKey ^ 0x12344321;

	DWORD entrypoint =
		m_pestruct.m_dwpOptHeader->AddressOfEntryPoint;

	PIMAGE_SECTION_HEADER Psec = IMAGE_FIRST_SECTION(GetNTHeader(m_pestruct.mem_pe_base));
	INT SecNumber = GetFileHeader(m_pestruct.mem_pe_base)->NumberOfSections;

	for( ; SecNumber > 0  ; SecNumber--)
	{
		start = Psec->VirtualAddress;
		end = Psec->VirtualAddress + Psec->SizeOfRawData;

		if ( entrypoint > start &
			entrypoint < end )
		{
			Encryptsize = Psec->SizeOfRawData;

			FileStart = 
			 (PCHAR)(m_pestruct.mem_pe_base) + Psec->PointerToRawData ;

			break;
		}
		Psec++;
	}

	for (i = 0; 4 * i < Encryptsize;i++)
	{
		*FileStart = *FileStart ^ encryptKey;

		encryptKey = encryptKey + *FileStart;

		FileStart++;

	}
	
}


VOID ClearI_AT_ROC(Pestruct m_pestruct)
{

	m_pestruct.m_dwpOptHeader->DataDirectory[1].VirtualAddress = 0; 
	m_pestruct.m_dwpOptHeader->DataDirectory[1].Size = 0; 

	m_pestruct.m_dwpOptHeader->DataDirectory[5].VirtualAddress = 0;
	m_pestruct.m_dwpOptHeader->DataDirectory[5].Size = 0;

	//不清理import address Table directory 程序会加载不起来
	m_pestruct.m_dwpOptHeader->DataDirectory[12].VirtualAddress = 0;
	m_pestruct.m_dwpOptHeader->DataDirectory[12].Size = 0;

}

PVOID Copy2NewMem(PVOID m_dwpPeBase, INT m_dwCompressedDataSize, PVOID m_dwpComperedData, INT m_dwSizeOfDecMem, PVOID m_dwpDecMem)
{
	INT m_sizeofheaders = GetOptHeader(m_dwpPeBase)->SizeOfHeaders;

	INT m_firstsecsize = GetAlignment(GetOptHeader(m_dwpPeBase)->FileAlignment, m_dwCompressedDataSize);

	INT m_newpesize = m_sizeofheaders + m_firstsecsize;

	PVOID m_ppeheader = UpdateHeader(m_dwpPeBase, m_firstsecsize);

	PVOID m_pnewpe = malloc(m_newpesize + m_dwSizeOfDecMem);

	if (m_pnewpe == NULL)
	{
		GetError("Copy2NewMem_malloc");
		return NULL;
	}

	//copy Headers
	memcpy_s(m_pnewpe, m_newpesize, m_ppeheader, m_sizeofheaders);

	//copy compreed data
	memcpy_s((PBYTE)m_pnewpe + m_sizeofheaders, m_newpesize, m_dwpComperedData, m_dwCompressedDataSize);

	//copy Dec data
	memcpy_s((PBYTE)m_pnewpe + m_firstsecsize, m_newpesize, m_dwpDecMem, m_dwSizeOfDecMem);

	free(m_ppeheader);

	return m_pnewpe;

}
//保存IDA和ROC
Pestruct InitStuct(Pestruct m_pestruct)
{

	m_pestruct.m_dwpOptHeader =
		GetOptHeader(m_pestruct.mem_pe_base);   //保存内存中的PE
	
	m_pestruct.OEP = m_pestruct.m_dwpOptHeader->AddressOfEntryPoint;//保存原始入口点RVA

	m_pestruct.IAT =
		m_pestruct.m_dwpOptHeader->DataDirectory[1]; // IDA表项

	m_pestruct.ROC =
		m_pestruct.m_dwpOptHeader->DataDirectory[5]; // 重定位表项


	return m_pestruct;
}

//导入packdll的代码段到内存
StructUnPacker LoadPackdll()
{
	StructUnPacker spack;

	HMODULE PDllBase = LoadLibrary(DllPath);

	DWORD unpackerStartfunc = (DWORD)GetProcAddress(PDllBase, "start");

	PIMAGE_SECTION_HEADER pFristSec = IMAGE_FIRST_SECTION(GetNTHeader((PVOID)PDllBase));

	INT dwSecSize = pFristSec->SizeOfRawData;

	PCHAR pDllTextSec = (PCHAR)PDllBase + pFristSec->VirtualAddress;

	PCHAR pNewDllTextSec = malloc(dwSecSize);

	memcpy_s(pNewDllTextSec, dwSecSize, pDllTextSec, dwSecSize);

	//内存中是VA 要先减去基值,然后减去这个节的va，就能得到这个导出函数在节内的偏移
	spack.unpackerStartfunc = unpackerStartfunc - (DWORD)PDllBase - (DWORD)pFristSec->VirtualAddress ;

	spack.dwSecSize = dwSecSize;

	spack.pNewDllTextSec = pNewDllTextSec;

	return spack;

}


VOID ConstructNewPE(Pestruct m_pestruct , StructUnPacker  m_StrucUnPacker)
{
	INT NumberOfSections =
		GetNTHeader(m_pestruct.mem_pe_base)->FileHeader.NumberOfSections;

	PIMAGE_SECTION_HEADER pFirstSec =
		IMAGE_FIRST_SECTION(GetNTHeader(m_pestruct.mem_pe_base));
	
	PIMAGE_SECTION_HEADER plastSec = 
		(PCHAR)pFirstSec + (NumberOfSections - 1) * sizeof(IMAGE_SECTION_HEADER);
	
	INT PeFileSize = (PCHAR)plastSec->PointerToRawData + plastSec->SizeOfRawData;
	
	INT SumNewPESize = PeFileSize + GetAlignment(m_pestruct.m_dwpOptHeader->FileAlignment, m_StrucUnPacker.dwSecSize) ;


	//增加最后一个节的信息
	IMAGE_SECTION_HEADER pNewSec = {0,};

	memcpy_s(pNewSec.Name, 8, "packer!", 8);

	pNewSec.PointerToRawData = PeFileSize;

	pNewSec.SizeOfRawData = GetAlignment(m_pestruct.m_dwpOptHeader->FileAlignment, m_StrucUnPacker.dwSecSize);

	pNewSec.VirtualAddress = m_pestruct.m_dwpOptHeader->SizeOfImage;

	pNewSec.Misc.VirtualSize = m_StrucUnPacker.dwSecSize;

	pNewSec.Characteristics = 0x60000020;

	*(PIMAGE_SECTION_HEADER)((PCHAR)plastSec + sizeof(IMAGE_SECTION_HEADER)) = pNewSec;


	//保存PE基本数据到PE的 DOS头中
	PCHAR pDos2 = (PCHAR)m_pestruct.mem_pe_base + 2;

	memcpy_s(pDos2, 0x400, &m_pestruct, sizeof(m_pestruct));


	m_pestruct.m_dwpOptHeader->SizeOfImage =
		(PCHAR)pNewSec.VirtualAddress + GetAlignment(m_pestruct.m_dwpOptHeader->SectionAlignment, m_StrucUnPacker.dwSecSize);

	//sec++
	PIMAGE_NT_HEADERS pNT = GetNTHeader(m_pestruct.mem_pe_base);

	pNT->FileHeader.NumberOfSections = pNT->FileHeader.NumberOfSections + 1;
	
	pNT->OptionalHeader.AddressOfEntryPoint = pNewSec.VirtualAddress + m_StrucUnPacker.unpackerStartfunc;

	PCHAR pNewPE = malloc(SumNewPESize);

	ZeroMemory(pNewPE, SumNewPESize);

	//拷贝被加密代码
	memcpy_s(pNewPE, SumNewPESize, m_pestruct.mem_pe_base, PeFileSize);

	memcpy_s(pNewPE + PeFileSize, SumNewPESize, m_StrucUnPacker.pNewDllTextSec, m_StrucUnPacker.dwSecSize);

	FILE* fp = fopen("outFile.exe", "wb");

	fwrite(pNewPE, 1, SumNewPESize, fp);

	fclose(fp);


}


BOOL Run(LPWSTR sourceFile)
{

	Pestruct m_pestruct;

	//m_dwpPeBase = LoadFile2Mem(m_pSouceFile);
	m_pestruct.mem_pe_base = LoadFile2Mem(sourceFile);

	m_pestruct = InitStuct(m_pestruct);

	EncryptExc(m_pestruct);

	ClearI_AT_ROC(m_pestruct);

	//INT m_CompreDataSize = (INT)CalcCompreDataSize(m_dwpPeBase);

	//m_dwpComperedData = CompreData(m_dwpPeBase, m_CompreDataSize);

	//m_dwpSecheadersData = SaveSecheader(m_dwpPeBase);

	//INT m_dwSizeOfDec = 0x400;

	//PVOID m_dwpDecMem = malloc(m_dwSizeOfDec);//要修改为解壳的代码
	
	StructUnPacker m_StrucUnPacker = LoadPackdll();

	ConstructNewPE(m_pestruct, m_StrucUnPacker);

	//m_dwpNePeMem = Copy2NewMem(m_dwpPeBase, m_dwCompressedDataSize, m_dwpComperedData, m_dwSizeOfDec, m_dwpDecMem);

	return TRUE;
}


int main()
{

#ifdef _DEBUG
	IsDebug = TRUE;
#endif 

	Run(FilePath);
	return 0;

}


int __CRTDECL mprintf(
	_In_z_ _Printf_format_string_ char const* const _Format,
	...)
{
	if (IsDebug)
	{
		int _Result;
		va_list _ArgList;
		__crt_va_start(_ArgList, _Format);
		_Result = _vfprintf_l(stdout, _Format, NULL, _ArgList);
		__crt_va_end(_ArgList);
		return _Result;
	}
	else
	{
		return NULL;
	}
}
