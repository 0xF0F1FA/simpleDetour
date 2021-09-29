
#include <Windows.h>
#include <iostream>
#include "detours.h"
#include "sigscan.h"
typedef int(__cdecl *sum)(int x, int y);
DWORD AddressOfSum = 0;
int h_sum(int x, int y)
{
	std::cout << "x:" << x << "           " << "y:" << y << std::endl;
	return x + y;
}


BOOL WINAPI DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved)
{
	// store the address of sum() in testprogram.exe here.

	if (dwReason == DLL_PROCESS_ATTACH)
	{
		// We will use signature scanning to find the function that we want to hook
		// we will find the function in IDA pro and create a signature from it:

		SigScan Scanner;

		// testprogram.exe is the name of the main module in our target process
		AddressOfSum = Scanner.FindPattern("AppToHook.exe", "\x55\x8B\xEC\x8B\x45\x08\x03\x45\x0C", "xxxxxxxxx");

		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());

		// this will hook the function
		DetourAttach(&(LPVOID&)AddressOfSum, &h_sum);

		DetourTransactionCommit();
	}
	else if (dwReason == DLL_PROCESS_DETACH)
	{
		// unhook
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());

		// this will hook the function
		DetourDetach(&(LPVOID&)AddressOfSum, &h_sum);

		DetourTransactionCommit();
	}
	return TRUE;
}
