// DLLInjector.cpp : Defines the entry point for the console application.
//

#include <Windows.h>
#include <stdio.h>

int main(int argc,char *argv[])
{
	printf("[+] DLL Injector initialised\n");
	
	//write DLL name to memory
//	wchar_t* dllName = L"C:\\Users\\wb\\Documents\\Visual Studio 2017\\Projects\\HookSend\\Debug\\x64\\HookSend.dll";
	wchar_t* dllName = L"C:\\Users\\wb\\Documents\\Visual Studio 2017\\Projects\\HookSend\\Debug\\HookSend.dll";

	printf("[+] Writing DLL Path to remote process memory\n");
	int dllnamelength = wcslen(dllName) + 1;
	//DWORD targetPID = (DWORD)argv[1];
	DWORD targetPID =1144;
	BOOL isWow64 = FALSE;

	//Obtain Handle to Target Process
	HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, NULL, targetPID);

	//Check is Process is Wow64
	IsWow64Process(process, &isWow64);
	printf("Error Code: %d", GetLastError());
	if (isWow64 == TRUE) {
		printf("[+] x86 Process identified\n ");
		//Would like additional functionality here to load binary dll from disk into memory and verify whether it is 64 or 32 bit
		//Worth adding here as well that from a 32 bit program you can't tamper with module info of 64 bit process
	}
	else {
		printf("[+] x64 Process identified\n");
	}
	//Allocate memory for string in remote thread
	LPVOID remoteString = VirtualAllocEx(process, NULL, dllnamelength * 2, MEM_COMMIT, PAGE_EXECUTE);
	printf("Error Code: %d\n", GetLastError());

	//Write string into remote thread
	WriteProcessMemory(process, remoteString, dllName, dllnamelength * 2, NULL);

	printf("Error Code: %d\n", GetLastError());
	//Now we need to find the address of LoadLibraryW()
	
	printf("[+] Locating the memory address of LoadLibrary\n");
	HMODULE kern32 = GetModuleHandleA("kernel32.dll");

	//Retrieve PTR to LoadLibraryW edition
	LPVOID lladdr = GetProcAddress(kern32, "LoadLibraryW");
	
	//Create a thread to call LoadLibraryW and load the library
 
	printf("[+] Creating a thread in remote process\n");
	HANDLE	thread = CreateRemoteThread(process, NULL, NULL, (LPTHREAD_START_ROUTINE)lladdr, remoteString, NULL, NULL);

	printf("Error Code: %d\n", GetLastError());
	//Wait for the thread to finish loading and tidy up
	WaitForSingleObject(thread, INFINITE);
	
	CloseHandle(thread);

    return 0;
}



