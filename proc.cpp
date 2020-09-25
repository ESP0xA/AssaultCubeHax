#include "proc.h"

DWORD GetProcId(const wchar_t* procName)
{
	DWORD procId = 0;
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap != INVALID_HANDLE_VALUE)
	{
		PROCESSENTRY32 procEntry;
		procEntry.dwSize = sizeof(procEntry);

		if (Process32First(hSnap, &procEntry))
		{
			do
			{
				if (!_wcsicmp(procEntry.szExeFile, procName))
				{
					procId = procEntry.th32ProcessID;
					break;
				}
			} while (Process32Next(hSnap, &procEntry));

		}
	}
	CloseHandle(hSnap);
	return procId;
}
/* Return				  Base address of module belongs to the process.
 * Param modBaseAddr      The base address of module belongs to the process.
 * Param hSnap            Handle to the snapshot of the specified process, as well as the modules used by this process.
 * Param modEntry         An entry from a list of the modules belonging to the specified process.
 * Param 
 * Param 
 */ 
uintptr_t GetModuleBaseAddress(DWORD procId, const wchar_t* modName)
{
	uintptr_t modBaseAddr = 0;
	//  Take a snapshot of all modules in the specified process. 
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, procId);
	if (hSnap != INVALID_HANDLE_VALUE)
	{	
		/*	typedef struct tagMODULEENTRY32 {
				DWORD   dwSize;
				DWORD   th32ModuleID;
				DWORD   th32ProcessID;
				DWORD   GlblcntUsage;
				DWORD   ProccntUsage;
				BYTE    *modBaseAddr;
				DWORD   modBaseSize;
				HMODULE hModule;
				char    szModule[MAX_MODULE_NAME32 + 1];
				char    szExePath[MAX_PATH];
			} MODULEENTRY32;
		 */
		MODULEENTRY32 modEntry;
		//  Set the size of the structure before using it. 
		modEntry.dwSize = sizeof(modEntry);
		//  Retrieve information about the first module associated with this process.
		//  Returns TRUE if the first entry of the module list has been copied to the buffer.
		if (Module32First(hSnap, &modEntry))
		{
			do
			{	//  Makes sure this is the module we need.
				//  Returns 0 if equal.
				if (!_wcsicmp(modEntry.szModule, modName))
				{
					modBaseAddr = (uintptr_t)modEntry.modBaseAddr;
					break;
				}
			} while (Module32Next(hSnap, &modEntry));  //  Until information about the next module been retrieved.
		}
	}
	// Must clean up the snapshot object! 
	CloseHandle(hSnap);
	return modBaseAddr;
}

uintptr_t FindDMAAddy(HANDLE hProc, uintptr_t ptr, std::vector<unsigned int> offsets)
{
	uintptr_t addr = ptr;
	for (unsigned int i = 0; i < offsets.size(); ++i)
	{
		// Copies the data in the specified address range from the address space of the specified process into the specified buffer of the current process. 
		// Addr -> Addr
		// the `sizeof(addr)` can be replaced by `sizeof(uintptr_t)`
		// the `0` can be replaced by `nullptr`
		ReadProcessMemory(hProc, (BYTE*)addr, &addr, sizeof(addr), 0);
		addr += offsets[i];
	}
	return addr;
}