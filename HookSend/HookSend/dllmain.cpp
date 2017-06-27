#include <stdlib.h>
#include <stdio.h>
#include <Windows.h>
#include <cstdio>


//int test();
DWORD hookIAT(const char* funcName, DWORD newfunc);
void WINAPI newSendFunction(SOCKET s, const char *buf, int len, int flags);

typedef DWORD(WINAPI _origSend)(SOCKET s, const char *buf, int len, int flags);
_origSend* originalSend;



//int test()
//{
//	OutputDebugString(L"[+] Starting to inject IAT Hook into host process\n");
//	printf("[+] Starting to inject DLL to hook send function");
//	originalSend = (_origSend*)hookIAT("Send", (DWORD)&newSendFunction);
//
//	return 0;
//}

void WINAPI newSendFunction(SOCKET s, const char *buf, int len, int flags) {
	OutputDebugString(L"Send Hook Worked!\n");
	printf("Hooking Send!Ws2_32.dll Function Worked!\n");
	MessageBoxA(NULL, "Successfully Hooked Send!Ws32_32.dll Function\n", "Send Hook Initialised", MB_OK | MB_TOPMOST);
	//	std::getchar();
	originalSend(s, buf, len, flags);
}

DWORD WINAPI runHook(LPVOID lpParam) {
	
	// run your hooking code
	OutputDebugString(L"[+] Starting to inject IAT Hook into host process\n");
	printf("[+] Starting to inject DLL to hook send function");
	originalSend = (_origSend*)hookIAT("Send", (DWORD)&newSendFunction);;
	return 1;
}


BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		MessageBoxA(NULL, "IAT Hooking DLL Attached!\n", "Send Hook Initialised", MB_OK | MB_TOPMOST);
		CreateThread(NULL, 0, &runHook, NULL, 0, NULL);
		break;
	}
	return TRUE;
}


DWORD hookIAT(const char* funcName, DWORD newFunc)
{
	PIMAGE_DOS_HEADER dos;
	PIMAGE_OPTIONAL_HEADER opt;
	PIMAGE_IMPORT_DESCRIPTOR ImpDesc;


	//Get Base Address of Image
	OutputDebugString(L"[+] Obtaining Base Address of Module\n");
	DWORD baseaddress = (DWORD)GetModuleHandle(NULL);

	//Start parsing the PE Header
	OutputDebugString(L"[+] Parsing PE HEader\n");
	dos = (PIMAGE_DOS_HEADER)baseaddress;
	//Check if DOS Header is valid
	if (dos->e_magic != 0x5A4D) {
		//No valid DOS header so terminate
		return 0;
	}

	opt = (PIMAGE_OPTIONAL_HEADER)(baseaddress + dos->e_lfanew + 24);
	if (opt->Magic != 267) {
		//No valid Opt Header so return
		return 0;
	}

	//Check the IAT is still there
	auto IAT = opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	if (IAT.Size == 0 || IAT.VirtualAddress == 0) {
		return 0;
	}

	//Start traversing the IAT
	ImpDesc = (PIMAGE_IMPORT_DESCRIPTOR)(baseaddress + IAT.VirtualAddress);

	while (ImpDesc->FirstThunk) {
		auto thunkData = (PIMAGE_THUNK_DATA)(baseaddress + ImpDesc->OriginalFirstThunk);
		int n = 0;
		while (thunkData->u1.Function) {
			//Locate Specified Function and place hook
			char* importFuncName = (char*)(baseaddress + (DWORD)thunkData->u1.AddressOfData + 2);
			if (strcmp(importFuncName, funcName) == 0) {
				auto vfTable = (PDWORD)(baseaddress + ImpDesc->FirstThunk);
				DWORD original = vfTable[n];
				//Change memory protection
				DWORD oldProt;
				VirtualProtect((LPVOID)&vfTable[n], sizeof(DWORD), PAGE_READWRITE, &oldProt);

				//Place Hook
				vfTable[n] = newFunc;
				MessageBoxA(NULL, "Hooking Send Worked!\n", "Send Hook Initialised", MB_OK | MB_TOPMOST);

				//Change memory protections back to what it was originally
				VirtualProtect((LPVOID)&vfTable[n], sizeof(DWORD), oldProt, NULL);
				return original;
			}
			n++;
			thunkData++;
		}
		ImpDesc++;
	}
}

