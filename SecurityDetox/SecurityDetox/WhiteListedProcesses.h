#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <wtsapi32.h>
#include <tchar.h>
#include <psapi.h>
#include <unordered_map>
#include <deque>

using namespace std;

/*unordered_map<string, string> Products = {
	{"Bitdefender", "atcuf64.dll"},
	{"Bitdenfender", "atcuf32.dll"},
	{"Bitdefender", "bdhkm64.dll" },
};*/

deque<string> ListModulesByProcess(HANDLE hProcess) {
	deque<string> modules = {};
	modules.begin();
	// Get the list of all the modules loaded in the current process
	HMODULE hMods[1024];
	DWORD cbNeeded;
	unsigned int i;

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


int getPIDbyProcName(const string& procName) {
	int pid = 0;
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32W pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32W);
	if (Process32FirstW(hSnap, &pe32) != FALSE) {
		while (pid == 0 && Process32NextW(hSnap, &pe32) != FALSE) {
			wstring wideProcName(procName.begin(), procName.end());
			if (wcscmp(pe32.szExeFile, wideProcName.c_str()) == 0) {
				pid = pe32.th32ProcessID;
			}
		}
	}
	CloseHandle(hSnap);
	return pid;
}

string getProcessNameByPID(int pid) {
	wchar_t szProcessName[MAX_PATH];
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
	if (hProcess == NULL) {
		return "";
	}

	if (GetModuleFileNameExW(hProcess, NULL, szProcessName, MAX_PATH) != 0) {
		wstring wideProcessName(szProcessName);
		CloseHandle(hProcess);
		return string(wideProcessName.begin(), wideProcessName.end()).substr(wideProcessName.find_last_of(L'\\') + 1);
	}

	CloseHandle(hProcess);
	return "";
}


