#include <Shlwapi.h>
#include <shellapi.h>
#include "test.h"

#pragma comment(lib,"shlwapi.lib")

GpSecurityManager::GpSecurityManager()
{
	isneedSceFree = false;
}

GpSecurityManager::~GpSecurityManager()
{
	if (_data_ != nullptr) {
		if (isneedSceFree) {
			SceFreeMemory(_data_, kSceAreaAllFlag);
		}
		else
		{
			free(_data_);
		}
		_data_ = nullptr;
	}

}

bool GpSecurityManager::GetGpSecInfo(GpSecInfo & secInfo)
{
	bool bRet = false;
	secInfo.init();
	if (GetGpConfig())
	{
		secInfo.MaxPasswdAge = _data_->MaximumPasswordAge;
		secInfo.MinPasswdAge = _data_->MinimumPasswordAge;
		secInfo.MinPasswdLen = _data_->MinimumPasswordLength;
		secInfo.PasswdComplexity = _data_->PasswordComplexity;
		secInfo.PasswdHistSize = _data_->PasswordHistorySize;
		secInfo.bChecked = true;
		bRet = true;
	}
	return bRet;
}

bool GpSecurityManager::GetGpSecInfoEx(GpSecInfo & secInfo)
{
	bool bRet = false;
	secInfo.init();
	if (GenGpConfigFile())
	{
		if (ParseGpConfigFileToGpSecInfo())
		{
			secInfo.MaxPasswdAge = _data_->MaximumPasswordAge;
			secInfo.MinPasswdAge = _data_->MinimumPasswordAge;
			secInfo.MinPasswdLen = _data_->MinimumPasswordLength;
			secInfo.PasswdComplexity = _data_->PasswordComplexity;
			secInfo.PasswdHistSize = _data_->PasswordHistorySize;
			secInfo.bChecked = true;
			bRet = true;
		}
	}

	return bRet;
}

bool GpSecurityManager::GetGpSecInfoEx1(GpSecInfo & secInfo)
{
	bool bRet = false;
	SAMPR_DOMAIN_INFO_BUFFER buffer = { 0 };
	if (GetGpConfigEx(buffer))
	{
		secInfo.bChecked = true;
		secInfo.MaxPasswdAge = buffer.Password.MaxPasswordAge.QuadPart;
		secInfo.MinPasswdAge = buffer.Password.MinPasswordAge.QuadPart;
		secInfo.MinPasswdLen = buffer.Password.MinPasswordLength;
		secInfo.PasswdComplexity = buffer.Password.PasswordProperties;
		secInfo.PasswdHistSize = buffer.Password.PasswordHistoryLength;
		bRet = true;
	}

	return bRet;
}

bool GpSecurityManager::GenGpConfigFile(const std::wstring & wsPath)
{
	bool bRet = false;
	std::wstring iniPath = wsPath;
	if (wsPath.empty() || !PathFileExists(wsPath.c_str()))
	{
		wchar_t modulePath[MAX_PATH];
		GetModuleFileName(NULL, modulePath, MAX_PATH);
		PathRemoveFileSpec(modulePath);
		iniPath = modulePath;
		iniPath += L"\\gp_policy.ini";
		std::wstring wsDebugStr = __FUNCTIONW__;
		wsDebugStr += L" inipath:" + iniPath;
		OutputDebugString(wsDebugStr.c_str());
	}
	std::wstring cmdStr = L" /export /cfg \"" + iniPath + L"\"";
	::ShellExecute(NULL, L"runas", L"secedit.exe", cmdStr.c_str(), NULL, SW_SHOWNORMAL);
	if (PathFileExists(iniPath.c_str()))
	{
			bRet = true;
	}
	return bRet;
}

bool GpSecurityManager::ParseGpConfigFileToGpSecInfo(const std::wstring &wsPath)
{
	std::wstring iniPath = wsPath;
	if (wsPath.empty() || !PathFileExists(wsPath.c_str()))
	{
		wchar_t modulePath[MAX_PATH];
		GetModuleFileName(NULL, modulePath, MAX_PATH);
		PathRemoveFileSpec(modulePath);
		iniPath = modulePath;
		iniPath += L"\\gp_policy.ini";
		std::wstring wsDebugStr = __FUNCTIONW__;
		wsDebugStr += L" inipath:" + iniPath;
		OutputDebugString(wsDebugStr.c_str());
	}

	_data_ = (PSCE_PROFILE_INFO)malloc(sizeof(SCE_PROFILE_INFO));
	if (_data_ == nullptr)
	{
		return false;
	}

	memset(_data_, 0, sizeof(SCE_PROFILE_INFO));

	WCHAR MinimumPasswordAge[10] = { 0 };
	GetPrivateProfileString(L"System Access", L"MinimumPasswordAge", L"0", MinimumPasswordAge, 10, iniPath.c_str());
	_data_->MinimumPasswordAge = _wtoi64(MinimumPasswordAge);

	WCHAR MaximumPasswordAge[10] = { 0 };
	GetPrivateProfileString(L"System Access", L"MaximumPasswordAge", L"0", MaximumPasswordAge, 10, iniPath.c_str());
	_data_->MaximumPasswordAge = _wtoi64(MaximumPasswordAge);

	WCHAR MinimumPasswordLength[10] = { 0 };
	GetPrivateProfileString(L"System Access", L"MinimumPasswordLength", L"0", MinimumPasswordLength, 10, iniPath.c_str());
	_data_->MinimumPasswordLength = _wtoi64(MinimumPasswordLength);

	WCHAR PasswordComplexity[10] = { 0 };
	GetPrivateProfileString(L"System Access", L"PasswordComplexity", L"0", PasswordComplexity, 10, iniPath.c_str());
	_data_->PasswordComplexity = _wtoi64(PasswordComplexity);

	WCHAR PasswordHistorySize[10] = { 0 };
	GetPrivateProfileString(L"System Access", L"PasswordHistorySize", L"0", PasswordHistorySize, 10, iniPath.c_str());
	_data_->PasswordHistorySize = _wtoi64(PasswordHistorySize);
	if (PathFileExists(iniPath.c_str())) {
		DeleteFile(iniPath.c_str());
		return true;
	}
	else
	{
		return false;
	}
}

bool GpSecurityManager::GetGpConfig()
{
	bool bRet = false;
	SCETYPE type = SCE_ENGINE_SYSTEM;
	_data_ = nullptr;
	auto ret = SceGetSecurityProfileInfo(nullptr, type, kSceAreaAllFlag, &_data_, nullptr);
	if (ret == 0){
		if (_data_ != nullptr) { // ret == 0 代表成功
			bRet = true;
			isneedSceFree = true;
		}
		else
		{
			SceFreeMemory(_data_, kSceAreaAllFlag);
			_data_ = nullptr;
		}
	}
	else
	{
		_data_ = nullptr;
	}

	return bRet;
}

bool GpSecurityManager::GetGpConfigEx(SAMPR_DOMAIN_INFO_BUFFER & buff)
{
	bool bRet = false;

	NTSTATUS status;
	UNICODE_STRING serverName;
	SAMPR_HANDLE hServerHandle = NULL, hDomainHandle = NULL;
	LSA_HANDLE hPolicy = NULL;
	LSA_OBJECT_ATTRIBUTES ObjectAttributes;
	PPOLICY_ACCOUNT_DOMAIN_INFO DomainInfo = NULL;

	buff = { 0 };
	
	ZeroMemory(&ObjectAttributes, sizeof(ObjectAttributes));

	do {
		HMODULE ntdll = ::GetModuleHandle(L"ntdll.dll");

		RtlInitUnicodeStringFunction RtlInitUnicodeString = NULL;
		if (ntdll == NULL) {
			break;
		}
		RtlInitUnicodeString = reinterpret_cast<RtlInitUnicodeStringFunction>(GetProcAddress(ntdll, "RtlInitUnicodeString"));
		if (RtlInitUnicodeString != NULL) {
			RtlInitUnicodeString(&serverName, L"");
		}
		else {
			break;
		}

		status = LsaOpenPolicy(NULL, &ObjectAttributes, POLICY_VIEW_LOCAL_INFORMATION, &hPolicy);
		status = LsaQueryInformationPolicy(hPolicy, PolicyAccountDomainInformation, (PVOID*)&DomainInfo);

		status = SamConnect(&serverName, &hServerHandle, SAM_SERVER_CONNECT | SAM_SERVER_ENUMERATE_DOMAINS | SAM_SERVER_LOOKUP_DOMAIN, FALSE);
		if (ERROR_SUCCESS != status)
		{
			printf("SamConnect error (?) %08x\n", status);
			break;
		}

		status = SamOpenDomain(hServerHandle, DOMAIN_READ_PASSWORD_PARAMETERS, DomainInfo->DomainSid, &hDomainHandle);
		if (ERROR_SUCCESS != status)
		{
			printf("SamOpenDomain Builtin (?) %08x\n", status);
			break;
		}

		status = SamQueryInformationDomain(hDomainHandle, DomainPasswordInformation, (PSAMPR_DOMAIN_INFO_BUFFER*)&buff);
		if (ERROR_SUCCESS != status)
		{
			printf("SamQueryInformation failed with %08x\n", status);
			break;
		}

		bRet = true;
	} while (false);

	if (hDomainHandle != NULL)
	{
		SamCloseHandle(hDomainHandle);
	}
	if (hServerHandle != NULL) {
		SamCloseHandle(hServerHandle);
	}

	if (hPolicy != NULL) {
		LsaClose(hPolicy);
	}

	if (DomainInfo != NULL) {
		LsaFreeMemory(DomainInfo);
	}

	return bRet;
}


int main()
{
		GpSecurityManager mgr;
		GpSecInfo info;
		mgr.GetGpSecInfo(info);
		mgr.GetGpSecInfoEx(info);
		mgr.GetGpSecInfoEx1(info);
}