#pragma once
// ������еİ�ȫ���ù�����
#include <wtypes.h>
#include <string>
#include "samsvr_extern.h"
#include "scecli.h"

static constexpr DWORD kSceSystemFlag = 300;
static constexpr DWORD kSceAreaAllFlag = 0xFFFFL;
#if 0
using GetSecProfileInfoFnPtr = DWORD(WINAPI*)(PVOID profileHandle,
	DWORD type,
	DWORD securityArea,
	PVOID profileInfo,
	PVOID errorInfo);
using SceFreeMemoryPtr = DWORD(WINAPI*)(PVOID data, DWORD securityArea);

struct SceProfileInfo { // gpeidt �Ĳ�������
	DWORD Unk0;
	DWORD MinPasswdAge;
	DWORD MaxPasswdAge;
	DWORD MinPasswdLen;
	DWORD PasswdComplexity;
	DWORD PasswdHistSize;
	DWORD LockoutBadCount;
	DWORD ResetLockoutCount;
	DWORD LockoutDuration;
	DWORD ReqLogonChangePasswd;
	DWORD ForceLogoffExpire;
	PWSTR AdministratorName;
	PWSTR GuestName;
	DWORD Unk1;
	DWORD ClearTextPasswd;
	DWORD LsaAllowAnonymousSidLookup;
	PVOID Unk2;
	PVOID Unk3;
	PVOID Unk4;
	PVOID Unk5;
	PVOID Unk6;
	PVOID Unk7;
	PVOID Unk8;
	PVOID Unk9;
	DWORD MaxLogSize[kSceInfoMaxArray];
	DWORD RetentionLog[kSceInfoMaxArray];
	DWORD RetentionLogDays[kSceInfoMaxArray];
	DWORD RestrictAccessGuest[kSceInfoMaxArray];
	DWORD AuditSystemEvents;
	DWORD AuditLogonEvents;
	DWORD AuditObjectsAccess;
	DWORD AuditPrivilegeUse;
	DWORD AuditPolicyChange;
	DWORD AuditAccountManage;
	DWORD AuditProcessTracking;
	DWORD AuditDSAccess;
	DWORD AuditAccountLogon;
	DWORD AuditFull;
	DWORD RegInfoCount;
	PVOID Unk10;
	DWORD EnableAdminAccount;
	DWORD EnableGuestAccount;
};
#endif

typedef struct __GpSecInfo__
{
	DWORD MinPasswdAge;
	DWORD MaxPasswdAge;
	DWORD MinPasswdLen;
	DWORD PasswdComplexity;
	DWORD PasswdHistSize;
	bool bChecked; // �Ƿ��Ѿ���ֵ

	__GpSecInfo__()
	{
		MinPasswdAge = 0;
		MinPasswdLen = 0;
		MinPasswdLen = 0;
		PasswdComplexity = 0;
		PasswdHistSize = 0;
		bChecked = false;
	}

	void init()
	{
		MinPasswdAge = 0;
		MinPasswdLen = 0;
		MinPasswdLen = 0;
		PasswdComplexity = 0;
		PasswdHistSize = 0;
		bChecked = false;
	}
}GpSecInfo, *PGpSecInfo;

class GpSecurityManager
{
public:
	GpSecurityManager();
	~GpSecurityManager();
	bool GetGpSecInfo(GpSecInfo& secInfo); // ͨ��api��ȡ��ȫ����
	bool GetGpSecInfoEx(GpSecInfo& secInfo); // ͨ����exe��ȡ��ȫ����
	bool GetGpSecInfoEx1(GpSecInfo& secInfo); // ͨ����sam�ӿڻ�ȡ��ȫ����
private:
	bool GenGpConfigFile(const std::wstring &wsPath = L""); // ����gpedit�������ļ�
	bool ParseGpConfigFileToGpSecInfo(const std::wstring &wsPath = L"");
	bool GetGpConfig();// ͨ��api��ȡ����Ȳ��� SceGetSecurityProfileInfo
	bool GetGpConfigEx(SAMPR_DOMAIN_INFO_BUFFER& gpInfo); // ͨ��api��ȡ����Ȳ���  SamQueryInformationDomain

	PSCE_PROFILE_INFO _data_;
	bool isneedSceFree;
};

