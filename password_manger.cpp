#include "password_manger.h"
#include <Windows.h>
#include <accctrl.h>

void gen_account_ini()
{
	// Checking first if the class is already initialized

	// Sanity check to ensure that function pointers are not initialized if
	// running process is a WoW64 process
	// Status wow64Status = isWow64Process();
	/*if (wow64Status.ok()) {
		return ;
	}*/

	// Checking if the input DLL is already mapped to memory before loading it.
	// If mapped module is not found, LoadLibraryExA() gets called to load the
	// module from system32 folder.
	bool increasedRefCount = false;
	HMODULE dllHandle = GetModuleHandleA(kTargetSCEDLL.c_str());
	if (dllHandle == nullptr) {
		// Library was not there in memory already, so we are loading here it and
		// freeing it on the class destructor
		increasedRefCount = true;
		dllHandle = LoadLibraryExA(
			kTargetSCEDLL.c_str(), NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
	}

	// An invalid module handle means that the DLL couldn't be loaded
	if (dllHandle == nullptr) {
		return ;
	}

	// Getting the address to exported SceFreeMemory function
	PVOID sceFreeMemoryAddr = GetProcAddress(dllHandle, kSceFreeMemoryFn.c_str());
	if (sceFreeMemoryAddr == nullptr) {
		if (increasedRefCount) {
			FreeLibrary(dllHandle);
		}
		return ;
	}

	// Getting the address to exported SceGetSecurityProfileInfo function
	PVOID sceGetProfileInforAddr =
		GetProcAddress(dllHandle, kSceGetSecProfileInfoFn.c_str());
	if (sceGetProfileInforAddr == nullptr) {
		if (increasedRefCount) {
			FreeLibrary(dllHandle);
		}
		return ;
	}

	// Assigning the address of the exports in memory so they can be called thru
	// function pointers that match the target function prototypes
	auto sceFreeMemory_ = static_cast<SceFreeMemoryPtr>(sceFreeMemoryAddr);

	auto sceGetSecurityProfileInfo_ =
		static_cast<GetSecProfileInfoFnPtr>(sceGetProfileInforAddr);

	// Assigning the handle to the loaded library if ref counter was increased
	//if (increasedRefCount) {
	//	handleSceDLL_ = dllHandle;
	//}
	PVOID workProfileData = nullptr;
	sceGetSecurityProfileInfo_(
		nullptr, kSceSystemFlag, kSceAreaAllFlag, &workProfileData, nullptr);

	auto data = reinterpret_cast<SceProfileInfo*>(workProfileData);
	
	sceFreeMemory_(data, kSceAreaAllFlag);
	LocalFree(data);
	if (increasedRefCount) {
		FreeLibrary(dllHandle);
	}
	return ;

}