#pragma once
#include <Windows.h>
#include <iostream>
#include <fstream>
#include <TlHelp32.h>

using f_LoadLibraryA = HINSTANCE(__stdcall *)(const char * lpLibFilename);
using f_GetProcAddress = FARPROC(__stdcall *)(HINSTANCE hModule, const char * lpProcName);
using f_DLL_ENTRY_POINT = BOOL(WINAPI*)(void * hDll, DWORD dwReason, void * pReserved);

struct MANUAL_MAPPING_DATA
{
	f_LoadLibraryA		pLoadLibraryA;
	f_GetProcAddress	pGetProcAddress;
	BYTE			    Signal;    // 0 is success, 1 is fail, 2 is wating
	LPVOID pModuleBase;
	LPVOID pDllParam;
	BOOL injectionFlag;
	BYTE Lock;  // 0 not initialized and unlocked, 1 Locked&initializing, 2 free to go to original // to make thread safe
};

struct DLL_PARAM {  //char 배열이니까 헷깔리지 말자
	LPVOID pTargetDllBuffer;
	LPVOID addressOfHookFunction;
	char TargetProcessName[20];
};

bool ManualMap(HANDLE hProc, const char * szDllFile, const char * szTargetDLL, DLL_PARAM* pDllparam, DWORD pid = 0);



