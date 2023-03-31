#pragma once
#include <string>
#include <wtypes.h>

static constexpr DWORD kSceInfoMaxArray = 3;

struct SceProfileInfo {
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
const std::string kTargetSCEDLL = "scecli.dll";

/**
 * @brief Name of the SceFreeMemory export function in scecli.dll
 */
const std::string kSceFreeMemoryFn = "SceFreeMemory";

/**
 * @brief Name of the SceGetSecurityProfileInfo export function in scecli.dll
 */
const std::string kSceGetSecProfileInfoFn = "SceGetSecurityProfileInfo";

using GetSecProfileInfoFnPtr = DWORD(WINAPI*)(PVOID profileHandle,
	DWORD type,
	DWORD securityArea,
	PVOID profileInfo,
	PVOID errorInfo);

using SceFreeMemoryPtr = DWORD(WINAPI*)(PVOID data, DWORD securityArea);
static constexpr DWORD kSceSystemFlag = 300;
static constexpr DWORD kSceAreaAllFlag = 0xFFFFL;
void gen_account_ini();