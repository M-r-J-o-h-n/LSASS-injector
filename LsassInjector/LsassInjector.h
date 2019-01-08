#pragma once
#include <Windows.h>
#include <fstream>
#include <TlHelp32.h>

using f_LoadLibraryA = HINSTANCE (__stdcall *)(const char * lpLibFilename);
using f_GetProcAddress = FARPROC (__stdcall *)(HINSTANCE hModule, const char * lpProcName);
using f_DLL_ENTRY_POINT = BOOL(WINAPI*)(void * hDll, DWORD dwReason, void * pReserved);
using f_RtlAddFunctionTable = BOOLEAN(WINAPI *)(PRUNTIME_FUNCTION, DWORD, DWORD64);

struct MANUAL_MAPPING_DATA
{
	f_LoadLibraryA		pLoadLibraryA;
	f_GetProcAddress	pGetProcAddress;
	f_RtlAddFunctionTable pRtlAddFunctionTable;
	BYTE			Signal;    // 0 is success, 1 is fail, 2 is wating
	LPVOID ModuleBase;
};

struct DLL_PARAM {  //char 배열이니까 헷깔리지 말자
	LPVOID pTargetDllBuffer;
	LPVOID addressOfHookFunction;
	char TargetProcessName[20];
};

bool ManualMap(HANDLE hProc, DLL_PARAM * DllParam);

