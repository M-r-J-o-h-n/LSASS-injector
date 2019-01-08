#include "Injector.h"
#include <vector>
#include <iostream>
#include "Logger.h"

using namespace std;
extern Logger logger;

#define RELOC_FLAG32(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_HIGHLOW)
#define RELOC_FLAG64(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_DIR64)
#define Normal_Function_Length 0x1000

#ifdef _WIN64
#define RELOC_FLAG RELOC_FLAG64
#else
#define RELOC_FLAG RELOC_FLAG32
#endif

#ifdef _DEBUG
#define USE_CREATE_THREAD
#endif

DWORD Shellcode(MANUAL_MAPPING_DATA * pData)
{
	if (!pData)
		return 0;

	if (pData->Signal != 2) {
		pData->Signal = 1;
		return 0;
	}

	BYTE * pBase = reinterpret_cast<BYTE*>(pData->pModuleBase);
	auto * pOpt = &reinterpret_cast<IMAGE_NT_HEADERS*>(pBase + reinterpret_cast<IMAGE_DOS_HEADER*>(pBase)->e_lfanew)->OptionalHeader; //Copy&Paste is bad

	auto _LoadLibraryA = pData->pLoadLibraryA;
	auto _GetProcAddress = pData->pGetProcAddress;
	auto _DllMain = reinterpret_cast<f_DLL_ENTRY_POINT>(pBase + pOpt->AddressOfEntryPoint);

	BYTE * LocationDelta = pBase - pOpt->ImageBase;
	if (LocationDelta)
	{
		if (!pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
			return 0;

		auto * pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
		while (pRelocData->VirtualAddress)
		{
			UINT AmountOfEntries = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
			WORD * pRelativeInfo = reinterpret_cast<WORD*>(pRelocData + 1);

			for (UINT i = 0; i != AmountOfEntries; ++i, ++pRelativeInfo)
			{
				if (RELOC_FLAG(*pRelativeInfo))
				{
					UINT_PTR * pPatch = reinterpret_cast<UINT_PTR*>(pBase + pRelocData->VirtualAddress + ((*pRelativeInfo) & 0xFFF));
					*pPatch += reinterpret_cast<UINT_PTR>(LocationDelta);
				}
			}
			pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(pRelocData) + pRelocData->SizeOfBlock);
		}
	}
	
	if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
	{
		auto * pImportDescr = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		while (pImportDescr->Name)
		{
			char * szMod = reinterpret_cast<char*>(pBase + pImportDescr->Name);
			HINSTANCE hDll = _LoadLibraryA(szMod);

			ULONG_PTR * pThunkRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDescr->OriginalFirstThunk);
			ULONG_PTR * pFuncRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDescr->FirstThunk);

			if (!pThunkRef)
				pThunkRef = pFuncRef;

			for (; *pThunkRef; ++pThunkRef, ++pFuncRef)
			{
				if (IMAGE_SNAP_BY_ORDINAL(*pThunkRef))
				{
					*pFuncRef = reinterpret_cast<ULONG_PTR>(_GetProcAddress(hDll, reinterpret_cast<char*>(*pThunkRef & 0xFFFF)));
				}
				else
				{
					auto * pImport = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(pBase + (*pThunkRef));
					*pFuncRef = reinterpret_cast<ULONG_PTR>(_GetProcAddress(hDll, pImport->Name));
				}
			}
			++pImportDescr;
		}
	}
	
	if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size)
	{
		auto * pTLS = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
		auto * pCallback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(pTLS->AddressOfCallBacks);
		for (; pCallback && *pCallback; ++pCallback)
			(*pCallback)(pBase, DLL_PROCESS_ATTACH, nullptr);
	}

	_DllMain(&(pData->injectionFlag), DLL_PROCESS_ATTACH, pData->pDllParam);

	if(pData->injectionFlag)
		pData->Signal = 0;  //SUCCESS
	else
		pData->Signal = 1;  //FAILURE
	return 0;
}

BYTE* Readfile(const char* DllPath, size_t* filesize) {
	BYTE* pDll = nullptr;

	if (GetFileAttributesA(DllPath) == INVALID_FILE_ATTRIBUTES) //파일 존재 확인
	{
		cout << DllPath << endl << "doesn't Exist" << endl;
		return false;
	}

	std::ifstream File(DllPath, std::ios::binary | std::ios::ate);  //파일 읽기

	if (File.fail())                                                  //실패 체크
	{
		File.close();
		return NULL;
	}

	auto FileSize = File.tellg();  //파일 끝으로 이동
	if(filesize)
		*filesize = FileSize;
	pDll = new BYTE[static_cast<UINT_PTR>(FileSize)];             //파일을 메모리에 올리기 위해 메모리 할당
	if (!pDll)
	{
		File.close();
		return NULL;
	}

	File.seekg(0, std::ios::beg);
	File.read(reinterpret_cast<char*>(pDll), FileSize);
	File.close();

	if (reinterpret_cast<IMAGE_DOS_HEADER*>(pDll)->e_magic != 0x5A4D) //"MZ"         //PE 파일 체크
	{
		delete[] pDll;
		return NULL;
	}

	return pDll;
}

bool ManualMap(HANDLE hProc, const char * szProxyDLL, const char * szTargetDLL, DLL_PARAM* pDllparam, DWORD pid)
{
	BYTE *	pLocalProxyDllfile = nullptr;  // 내 프로세스
	BYTE *	pLocalTargeDllfile = nullptr;

	BYTE *	pRemoteProxyBase = nullptr;  // 상대방 프로세스
	BYTE *	pRemoteTargetDllFile = nullptr;

	if (!(pLocalProxyDllfile = Readfile(szProxyDLL, NULL)))
		return false;

	size_t targetdllsize = 0;
	if (!(pLocalTargeDllfile = Readfile(szTargetDLL, &targetdllsize)))
		return false;

	IMAGE_NT_HEADERS * pProxyNtHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(pLocalProxyDllfile + reinterpret_cast<IMAGE_DOS_HEADER*>(pLocalProxyDllfile)->e_lfanew);
	IMAGE_OPTIONAL_HEADER * pProxyOptHeader = &pProxyNtHeader->OptionalHeader;
	IMAGE_FILE_HEADER * pProxyFileHeader = &pProxyNtHeader->FileHeader;

#ifdef _WIN64
	if (pProxyFileHeader->Machine != IMAGE_FILE_MACHINE_AMD64)
	{
		delete[] pLocalProxyDllfile;
		return false;
	}
#else
	if (pOldFileHeader->Machine != IMAGE_FILE_MACHINE_I386)
	{
		delete[] pSrcData;
		return false;
	}
#endif
	//타겟 프로세스에 메모리 할당
	pRemoteProxyBase = reinterpret_cast<BYTE*>(VirtualAllocEx(hProc, reinterpret_cast<void*>(pProxyOptHeader->ImageBase), pProxyOptHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
	if (!pRemoteProxyBase)
	{
		pRemoteProxyBase = reinterpret_cast<BYTE*>(VirtualAllocEx(hProc, nullptr, pProxyOptHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
		if (!pRemoteProxyBase)
			return false;
	}

	pRemoteTargetDllFile = reinterpret_cast<BYTE*>(VirtualAllocEx(hProc, nullptr, targetdllsize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
	if (!pRemoteTargetDllFile)
		return false;


	if (!WriteProcessMemory(hProc, pRemoteTargetDllFile, pLocalTargeDllfile, targetdllsize, nullptr)) { //타겟 DLL 작성
		std::cout << "WriteProcessMemory -> 타겟 dll 쓰기 오류 : " << GetLastError() << std::endl;
		return false;
	}

	if (!WriteProcessMemory(hProc, pRemoteProxyBase, pLocalProxyDllfile, pProxyOptHeader->SizeOfHeaders, nullptr)) { // PE 헤더 작성
		std::cout << "WriteProcessMemory -> PE헤더 작성 오류 : " << GetLastError() << std::endl; 
		return false;
	}

	auto * pSectionHeader = IMAGE_FIRST_SECTION(pProxyNtHeader);

	for (UINT i = 0; i != pProxyFileHeader->NumberOfSections; ++i, ++pSectionHeader)
	{
		if (pSectionHeader->SizeOfRawData)
		{
			if (!WriteProcessMemory(hProc, pRemoteProxyBase + pSectionHeader->VirtualAddress, pLocalProxyDllfile + pSectionHeader->PointerToRawData, pSectionHeader->SizeOfRawData, nullptr))
			{
				delete[] pLocalProxyDllfile;
				VirtualFreeEx(hProc, pRemoteProxyBase, 0, MEM_RELEASE);
				return false;
			}
			if ((pSectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE) == IMAGE_SCN_MEM_EXECUTE) {    //EXECUTE 이 있을 시 페이지 속성 변경
				DWORD oldProtection = 0;
				VirtualProtectEx(hProc, pRemoteProxyBase + pSectionHeader->VirtualAddress, pSectionHeader->SizeOfRawData, PAGE_EXECUTE_READWRITE, &oldProtection);
			}
		}
	}

	delete[] pLocalProxyDllfile;  // no more need 
	delete[] pLocalTargeDllfile;  // no more need
	///////////////////////////////////////////////////파일준비끝///////////////////////////////////////////////////////////////////////////////////////////////////////////////



	// DllMain용 패러미터 준비+할당+쓰기
	BYTE* pDllMainParam = reinterpret_cast<BYTE*>(VirtualAllocEx(hProc, nullptr, sizeof(DLL_PARAM), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)); // Create Mapping data in game
	pDllparam->pTargetDllBuffer = pRemoteTargetDllFile;
	if (!WriteProcessMemory(hProc, pDllMainParam, pDllparam, sizeof(DLL_PARAM), nullptr)) {
		std::cout << "WriteProcessMemory -> DLL 패러미터 작성 오류 : " << GetLastError() << std::endl; 
		return false;
	}
	// 매핑 패러미터용 준비+할당+쓰기
	MANUAL_MAPPING_DATA data{ 0 };
	data.pLoadLibraryA = LoadLibraryA;
	data.pGetProcAddress = reinterpret_cast<f_GetProcAddress>(GetProcAddress);
	data.Signal = 2;  // waiting
	data.pModuleBase = pRemoteProxyBase;
	data.pDllParam = pDllMainParam;
	data.injectionFlag = false;
	data.Lock = 0;
	BYTE* pMappingData = reinterpret_cast<BYTE*>(VirtualAllocEx(hProc, nullptr, sizeof(MANUAL_MAPPING_DATA), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)); // Create Mapping data in game
	if (!WriteProcessMemory(hProc, pMappingData, &data, sizeof(MANUAL_MAPPING_DATA), nullptr)) {
		std::cout << "WriteProcessMemory -> pMappingData 작성 오류 : " << GetLastError() << std::endl;
		return false;
	}
	
	/*쉘코드 타겟 프로세스에 쓰기
	EIP를 변경해서 쓰레드 하이재킹이 가능하기는 하지만 문제는 인자 전달을 해야 하는데 레지스터 셋팅은 non volatile 레지스터만 가능하다.
	그렇기 때문에 무조건 쉘코드를 사용할 수 밖에 없다.
	*/


	/*
	IF INCREMENTAL LINK IS ON USE BELOW FUNCTION TO CALCULATE RIGHT ADDRESS;

	BYTE* pShellCodeAddress = reinterpret_cast<BYTE*>(Shellcode);
	pShellCodeAddress += *(DWORD*)(pShellCodeAddress + 1) + 0x5;
	*/

	BYTE preShellCode[] =  // Multi Thread Safe Function Hooking ShellCode
	{
		0xA0, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,       // +0   mov         al,byte ptr [LockAddress]  
		0x3C, 0x01,                                                 // +9   cmp         al,1  
		0x0F, 0x84, 0x8A, 0x00, 0x00, 0x00,                         // +11  je          ThreadSafe 
		0xB0, 0x01,                                                 // +17  mov         al,1  
		0xA2, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,       // +19  mov         byte ptr [LockAddress],al  
		0x51,                                                       // +28  push        rcx  
		0x52,                                                       // +29  push        rdx  
		0x41, 0x50,                                                 // +30  push        r8  
		0x41, 0x51,                                                 // +32  push        r9  
		0x41, 0x52,                                                 // +34  push        r10  
		0x41, 0x53,                                                 // +36  push        r11  
		0x48, 0x33, 0xD2,                                           // +38  xor         rdx,rdx  
		0x48, 0x8B, 0xC4,                                           // +41  mov         rax,rsp  
		0x48, 0xC7, 0xC1, 0x10, 0x00, 0x00, 0x00,                   // +44  mov         rcx,10h  
		0x48, 0xF7, 0xF1,                                           // +51  div         rax,rcx  
		0x48, 0xB9, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, // +54  mov         rcx,pMappingData  
		0x48, 0xB8, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, // +64  mov         rax,pShellCode   
		0x48, 0x83, 0xFA, 0x00,                                     // +74  cmp         rdx,0  
		0x74, 0x0C,                                                 // +78  je          NoAlign 
		0x48, 0x83, 0xEC, 0x28,                                     // +80  sub         rsp,28h  
		0xFF, 0xD0,                                                 // +84  call        rax  
		0x48, 0x83, 0xC4, 0x28,                                     // +86  add         rsp,28h  
		0xEB, 0x0A,                                                 // +90  jmp         CleanUP
		//NoAlign
		0x48, 0x83, 0xEC, 0x20,                                     // +92  sub         rsp,20h  
		0xFF, 0xD0,                                                 // +96  call        rax  
		0x48, 0x83, 0xC4, 0x20,                                     // +98  add         rsp,20h  
		//CleanUP
		0x48, 0xBE, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, // +102  mov         rsi, pNtUserPeekMessageOriginalBYTE  
		0x48, 0xBF, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, // +112  mov         rdi, pHookFunction     
		0x48, 0x8B, 0xC7,                                           // +122  mov         rax,rdi  
		0x48, 0xC7, 0xC1, 0x0C, 0x00, 0x00, 0x00,                   // +125  mov         rcx,0Ch  
		0xF3, 0xA4,                                                 // +132  rep movs    byte ptr [rdi],byte ptr [rsi]  
		0x41, 0x5B,                                                 // +134  pop         r11  
		0x41, 0x5A,                                                 // +136  pop         r10  
		0x41, 0x59,                                                 // +138  pop         r9  
		0x41, 0x58,                                                 // +140  pop         r8  
		0x5A,                                                       // +142  pop         rdx  
		0x59,                                                       // +143  pop         rcx  
		0xB0, 0x02,                                                 // +144  mov         al,2  
		0xA2, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,       // +146  mov         byte ptr [LockAddress],al  
		//ThreadSafe
		0xA0, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,       // +155  mov         al,byte ptr [LockAddress]  
		0x3C, 0x02,                                                 // +164  cmp         al,2  
		0x75, 0xF3,                                                 // +166  jne         ThreadSafe
		0xFF, 0xE0,                                                 // +168  jmp         rax  
	};

	BYTE NtOpenProcessOriginalBYTE[12] = {
		0x4C, 0x8B, 0xD1, 0xB8, 0x26, 0x00, 0x00, 0x00, 0xF6, 0x04, 0x25, 0x08
	};

	BYTE NtOpenProcessBYTEPATCH[12] =
	{
		0x48, 0xB8, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88,  // +0   mov         rax,8888888888888888h  
		0x50,                                                        // +10  push        rax  
		0xC3                                                         // +11  ret  
	};


	LPVOID pShellcode = VirtualAllocEx(
		hProc,
		nullptr,
		sizeof(preShellCode) + sizeof(NtOpenProcessOriginalBYTE) + Normal_Function_Length,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE);

	if (!pShellcode)
	{
		VirtualFreeEx(hProc, pRemoteProxyBase, 0, MEM_RELEASE);
		VirtualFreeEx(hProc, pRemoteTargetDllFile, 0, MEM_RELEASE);
		VirtualFreeEx(hProc, pDllMainParam, 0, MEM_RELEASE);
		VirtualFreeEx(hProc, pMappingData, 0, MEM_RELEASE);
		return false;
	}

	LoadLibrary("ntdll.dll");
	LPVOID TargetFunction = GetProcAddress(GetModuleHandle("ntdll.dll"), "NtOpenProcess");
	*(DWORD64*)(preShellCode + 1) = (DWORD64)(pMappingData + sizeof(MANUAL_MAPPING_DATA) - 1);
	*(DWORD64*)(preShellCode + 20) = (DWORD64)(pMappingData + sizeof(MANUAL_MAPPING_DATA) - 1);
	*(DWORD64*)(preShellCode + 147) = (DWORD64)(pMappingData + sizeof(MANUAL_MAPPING_DATA) - 1);
	*(DWORD64*)(preShellCode + 156) = (DWORD64)(pMappingData + sizeof(MANUAL_MAPPING_DATA) - 1);
	*(DWORD64*)(preShellCode + 56) = (DWORD64)pMappingData;										//save MappingData
	*(DWORD64*)(preShellCode + 66) = (DWORD64)((BYTE*)pShellcode + sizeof(preShellCode) + sizeof(NtOpenProcessOriginalBYTE));  //ShellCode Address
	*(DWORD64*)(preShellCode + 104) = (DWORD64)((BYTE*)pShellcode + sizeof(preShellCode));
	*(DWORD64*)(preShellCode + 114) = (DWORD64)(TargetFunction);

	WriteProcessMemory(hProc, pShellcode, preShellCode, sizeof(preShellCode), nullptr);
	WriteProcessMemory(hProc, (BYTE*)pShellcode + sizeof(preShellCode), NtOpenProcessOriginalBYTE, sizeof(NtOpenProcessOriginalBYTE), nullptr);
	WriteProcessMemory(hProc, (BYTE*)pShellcode + sizeof(preShellCode) + sizeof(NtOpenProcessOriginalBYTE), Shellcode, Normal_Function_Length, nullptr);

	DWORD OldProtection = 0;
	if (!VirtualProtectEx(hProc, TargetFunction, 12, PAGE_EXECUTE_READWRITE, &OldProtection))   // 페이지를 수정할 수 있게 바꾼다.
		return false;

	*(DWORD64*)(NtOpenProcessBYTEPATCH + 2) = (DWORD64)pShellcode;
	WriteProcessMemory(hProc, TargetFunction, NtOpenProcessBYTEPATCH, sizeof(NtOpenProcessBYTEPATCH), nullptr);

	MANUAL_MAPPING_DATA data_checked = { 0 };
	do
	{
		ReadProcessMemory(hProc, pMappingData, &data_checked, sizeof(MANUAL_MAPPING_DATA), nullptr);
		Sleep(10);
	} while (data_checked.Signal == 2);  //waiting  
	logger.LogString("ManualMap Free Memories");
	Sleep(100);

	VirtualProtectEx(hProc, TargetFunction, 12, OldProtection, &OldProtection);
	VirtualFreeEx(hProc, pRemoteTargetDllFile, 0, MEM_RELEASE);
	VirtualFreeEx(hProc, pDllMainParam, 0, MEM_RELEASE);
	VirtualFreeEx(hProc, pMappingData, 0, MEM_RELEASE);
	VirtualFreeEx(hProc, pRemoteProxyBase, 0, MEM_RELEASE);
	VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE);

	return data_checked.Signal ? false : true; // 0이면 성공이르므로 true 반환, 1이면 실패이므로 false 반환
}