#pragma once
#include <wtypes.h>

// https://github.com/KernelPanic-OpenSource/Win2K3_NT_ds/blob/0d97393773ee5ecdc29aae15023492e383f7ee7f/published/inc/secedit.w

#ifdef _WIN64
#pragma comment(lib,"lib\\x64\\scecli.lib")
#else
#pragma comment(lib,"lib\\x86\\scecli.lib")
#endif // _WIN64

static constexpr DWORD kSceInfoMaxArray = 3;

typedef DWORD                   SCESTATUS;

typedef struct _SCE_ERROR_LOG_INFO {
	PWSTR  buffer;
	DWORD   rc;
	struct _SCE_ERROR_LOG_INFO *next;
} SCE_ERROR_LOG_INFO, *PSCE_ERROR_LOG_INFO;

typedef DWORD  AREA_INFORMATION;
typedef struct _SCE_NAME_LIST {
	PWSTR                  Name;
	struct _SCE_NAME_LIST   *Next;
}SCE_NAME_LIST, *PSCE_NAME_LIST;


typedef struct _SCE_PRIVILEGE_VALUE_LIST {
	PWSTR                  Name;
	DWORD                  PrivLowPart;
	DWORD                  PrivHighPart;
	struct _SCE_PRIVILEGE_VALUE_LIST   *Next;
}SCE_PRIVILEGE_VALUE_LIST, *PSCE_PRIVILEGE_VALUE_LIST;

typedef enum _SCE_TYPE {

	SCE_ENGINE_SYSTEM = 300,
	SCE_ENGINE_GPO,
	SCE_ENGINE_SCP,         // effective table
	SCE_ENGINE_SAP,         // analysis table
	SCE_ENGINE_SCP_INTERNAL,
	SCE_ENGINE_SMP_INTERNAL,
	SCE_ENGINE_SMP,         // local table
	SCE_STRUCT_INF,
	SCE_STRUCT_PROFILE,
	SCE_STRUCT_USER,
	SCE_STRUCT_NAME_LIST,
	SCE_STRUCT_NAME_STATUS_LIST,
	SCE_STRUCT_PRIVILEGE,
	SCE_STRUCT_GROUP,
	SCE_STRUCT_OBJECT_LIST,
	SCE_STRUCT_OBJECT_CHILDREN,
	SCE_STRUCT_OBJECT_SECURITY,
	SCE_STRUCT_OBJECT_ARRAY,
	SCE_STRUCT_ERROR_LOG_INFO,
	SCE_STRUCT_SERVICES,
	SCE_STRUCT_PRIVILEGE_VALUE_LIST,
	SCE_ENGINE_RBK

} SCETYPE;

typedef struct _SCE_PRIVILEGE_ASSIGNMENT {
	PWSTR                           Name;
	DWORD                           Value;
	// This value could be translated by SceLookupPrivByValue
	// The reason we define another set of privilege values is
	// we include both privilege and user rights into one set
	// (user rights do not have priv value on NT system).
	PSCE_NAME_LIST                   AssignedTo;
	// SCE_STATUS_GOOD
	// SCE_STATUS_MISMATCH
	// SCE_STATUS_NOT_CONFIGURED
	// SCE_DELETE_VALUE indicates that this priv is deleted from local table
	DWORD                           Status;
	struct _SCE_PRIVILEGE_ASSIGNMENT *Next;
} SCE_PRIVILEGE_ASSIGNMENT, *PSCE_PRIVILEGE_ASSIGNMENT;

typedef struct _SCE_NAME_STATUS_LIST {
	PWSTR                       Name;
	DWORD                       Status;
	struct _SCE_NAME_STATUS_LIST *Next;
}SCE_NAME_STATUS_LIST, *PSCE_NAME_STATUS_LIST;

typedef struct _SCE_GROUP_MEMBERSHIP {
	PWSTR                        GroupName;
	PSCE_NAME_LIST                pMembers;
	PSCE_NAME_LIST                pMemberOf;

	DWORD                         Status;
	//
	// pPrivilegesHeld is for analysis only.
	// The format of each entry in this list is:
	//    [PrivValue NULL] (directly assigned), or
	//    [PrivValue Name] (via group "Name")
	// To configure privileges, use AREA_PRIVILEGES area
	//
	// This PrivValue could be translated by SceLookupPrivByValue
	// The reason we define another set of privilege values is
	// we include both privilege and user rights into one set
	// (user rights do not have priv value on NT system).
	PSCE_NAME_STATUS_LIST         pPrivilegesHeld;
	struct _SCE_GROUP_MEMBERSHIP  *Next;
}SCE_GROUP_MEMBERSHIP, *PSCE_GROUP_MEMBERSHIP;

typedef struct _SCE_OBJECT_LIST {
	PWSTR                       Name;
	BYTE                        Status;
	// Status could be the status (mismatched/unknown) of the object
	// or, it could be a flag to ignore/check this ojbect
	//
	BOOL                        IsContainer;
	DWORD                       Count;
	//  Total count of mismatched/unknown objects under this object
	struct _SCE_OBJECT_LIST *Next;
}SCE_OBJECT_LIST, *PSCE_OBJECT_LIST;


typedef struct _SCE_OBJECT_SECURITY {
	PWSTR   Name;
	BYTE    Status;
	BOOL    IsContainer;
	PSECURITY_DESCRIPTOR  pSecurityDescriptor;
	SECURITY_INFORMATION  SeInfo;
	//    PWSTR   SDspec;
	//    DWORD   SDsize;
}SCE_OBJECT_SECURITY, *PSCE_OBJECT_SECURITY;

typedef struct _SCE_OBJECT_ARRAY_ {

	DWORD               Count;
	PSCE_OBJECT_SECURITY *pObjectArray;

} SCE_OBJECT_ARRAY, *PSCE_OBJECT_ARRAY;

typedef union _SCE_OBJECTS_ {
	// for Jet databases
	PSCE_OBJECT_LIST      pOneLevel;
	// for Inf files
	PSCE_OBJECT_ARRAY     pAllNodes;
} SCE_OBJECTS, *PSCE_OBJECTS;

typedef struct _SCE_SERVICES_ {
	PWSTR               ServiceName;
	PWSTR               DisplayName;

	BYTE                Status;
	BYTE                Startup;

	union {

		PSECURITY_DESCRIPTOR pSecurityDescriptor;
		PWSTR                ServiceEngineName;

	} General;

	SECURITY_INFORMATION SeInfo;

	struct _SCE_SERVICES_ *Next;

}SCE_SERVICES, *PSCE_SERVICES;


typedef struct _SCE_KERBEROS_TICKET_INFO_ {
	DWORD   MaxTicketAge;    // in hours (default 10), SCE_NO_VALUE, SCE_FOREVER_VALUE, no 0

	DWORD   MaxRenewAge;     // in days (default 7), SCE_NO_VALUE, SCE_FOREVER_VALUE, no 0

	DWORD   MaxServiceAge;   // in minutes (default 60), SCE_NO_VALUE, 10-MaxTicketAge
	DWORD   MaxClockSkew;    // in minutes (default 5), SCE_NO_VALUE

	// options
	DWORD   TicketValidateClient; // 0, 1, or SCE_NO_VALUE

	//
	// all other options are not configurable.
	//

} SCE_KERBEROS_TICKET_INFO, *PSCE_KERBEROS_TICKET_INFO;

typedef struct _SCE_REGISTRY_VALUE_INFO_ {
	LPTSTR  FullValueName;
	LPTSTR  Value;
	DWORD   ValueType;
	DWORD   Status;  // match, mismatch, not analyzed, error

} SCE_REGISTRY_VALUE_INFO, *PSCE_REGISTRY_VALUE_INFO;


typedef struct _SCE_PROFILE_INFO {

	// Type is used to free the structure by SceFreeMemory
	SCETYPE      Type;
	//
	// Area: System access
	//
	DWORD       MinimumPasswordAge;
	DWORD       MaximumPasswordAge;
	DWORD       MinimumPasswordLength;
	DWORD       PasswordComplexity;
	DWORD       PasswordHistorySize;
	DWORD       LockoutBadCount;
	DWORD       ResetLockoutCount;
	DWORD       LockoutDuration;
	DWORD       RequireLogonToChangePassword;
	DWORD       ForceLogoffWhenHourExpire;
	PWSTR       NewAdministratorName;
	PWSTR       NewGuestName;
	DWORD       SecureSystemPartition;
	DWORD       ClearTextPassword;
	DWORD       LSAAnonymousNameLookup;
	union {
		struct {
			// Area : user settings (scp)
			PSCE_NAME_LIST   pAccountProfiles;
			// Area: privileges
			// Name field is the user/group name, Status field is the privilege(s)
			//     assigned to the user/group
			union {
				//                PSCE_NAME_STATUS_LIST        pPrivilegeAssignedTo;
				PSCE_PRIVILEGE_VALUE_LIST   pPrivilegeAssignedTo;
				PSCE_PRIVILEGE_ASSIGNMENT    pInfPrivilegeAssignedTo;
			} u;
		} scp;
		struct {
			// Area: user settings (sap)
			PSCE_NAME_LIST        pUserList;
			// Area: privileges
			PSCE_PRIVILEGE_ASSIGNMENT    pPrivilegeAssignedTo;
		} sap;
		struct {
			// Area: user settings (smp)
			PSCE_NAME_LIST        pUserList;
			// Area: privileges
			// See sap structure for pPrivilegeAssignedTo
			PSCE_PRIVILEGE_ASSIGNMENT    pPrivilegeAssignedTo;
		} smp;
	} OtherInfo;

	// Area: group membership
	PSCE_GROUP_MEMBERSHIP        pGroupMembership;

	// Area: Registry
	SCE_OBJECTS            pRegistryKeys;

	// Area: System Services
	PSCE_SERVICES                pServices;

	// System storage
	SCE_OBJECTS            pFiles;
	//
	// ds object
	//
	SCE_OBJECTS            pDsObjects;
	//
	// kerberos policy settings
	//
	PSCE_KERBEROS_TICKET_INFO pKerberosInfo;
	//
	// System audit 0-system 1-security 2-application
	//
	DWORD                 MaximumLogSize[3];
	DWORD                 AuditLogRetentionPeriod[3];
	DWORD                 RetentionDays[3];
	DWORD                 RestrictGuestAccess[3];
	DWORD                 AuditSystemEvents;
	DWORD                 AuditLogonEvents;
	DWORD                 AuditObjectAccess;
	DWORD                 AuditPrivilegeUse;
	DWORD                 AuditPolicyChange;
	DWORD                 AuditAccountManage;
	DWORD                 AuditProcessTracking;
	DWORD                 AuditDSAccess;
	DWORD                 AuditAccountLogon;
	DWORD                 CrashOnAuditFull;

	//
	// registry values
	//
	DWORD                       RegValueCount;
	PSCE_REGISTRY_VALUE_INFO    aRegValues;
	DWORD                 EnableAdminAccount;
	DWORD                 EnableGuestAccount;

}SCE_PROFILE_INFO, *PSCE_PROFILE_INFO;

extern "C" {

	SCESTATUS
		WINAPI
		SceGetSecurityProfileInfo(
			IN  PVOID               hProfile OPTIONAL,
			IN  SCETYPE             ProfileType,
			IN  AREA_INFORMATION    Area,
			IN OUT PSCE_PROFILE_INFO   *ppInfoBuffer,
			OUT PSCE_ERROR_LOG_INFO *Errlog OPTIONAL
		);
	SCESTATUS
		WINAPI
		SceFreeMemory(
			IN PVOID smInfo,
			IN DWORD Category
		);
}