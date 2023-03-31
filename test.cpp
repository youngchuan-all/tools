// test.cpp : 定义应用程序的入口点。
//
#define no_init_all deprecated
#include "framework.h"
#include "test.h"
// #include "../../SupportDiagnosticToolApi.h"
//typedef  DeviceInfoInterface* (*pCreateDeviceObject)(ObjectType);
//typedef  SelfDiagnosisInterface* (*pCreateDiagnosisObject)(ObjectType);
//DeviceInfoInterface* ptrDeviceInfoManager;
//SelfDiagnosisInterface* ptrDiagnosisManager;
//int LoadSelfDiagnosisInterface()
//{
//	HMODULE  hModule = LoadLibrary(L"SupportDiagnosticTool.dll");
//	if (hModule == NULL)
//	{
//		ptrDeviceInfoManager = nullptr;
//		ptrDiagnosisManager = nullptr;
//		//std::cout << __FUNCTION__ << __LINE__ << "LoadLibrary failed" << std::endl;
//	}
//	else
//	{
//		auto ptrGetProcess = GetProcAddress(hModule, "CreateObject");
//		if (ptrGetProcess == nullptr)
//		{
//			ptrDeviceInfoManager = nullptr;
//			ptrDiagnosisManager = nullptr;
//			//std::cout << __FUNCTION__ << __LINE__ << "GetProcAddress failed" << std::endl;
//		}
//
//		ptrDiagnosisManager = ((pCreateDiagnosisObject)ptrGetProcess)(OBJ_SELF_DIAGNOSIS);
//		ptrDeviceInfoManager = ((pCreateDeviceObject)ptrGetProcess)(OBJ_SYSTEM_INFO);
//	}
//	system("pause");
//	return 0;
//}


#include <wuapi.h> 
#include <iostream> 
#include <ATLComTime.h> 
#include <wuerror.h> 
#include <atlbase.h>
#include <ShlObj.h>

using namespace std;
using namespace ATL;
// #pragma comment(lib, "comsupp.lib")


//检测操作系统安全补丁是否最新

BOOL DetectSecPatch()
{
	HRESULT ret;

	IUpdateSession *Session = NULL;//定义更新域

	ret = CoInitialize(NULL);//初始化COM接口
	if (FAILED(ret))
		return ERROR;

	ret = CoCreateInstance(CLSID_UpdateSession,
		NULL,
		CLSCTX_INPROC_SERVER,
		IID_IUpdateSession,
		(LPVOID*)&Session);//实例化COM接口
	if (FAILED(ret))
		return ERROR;

	IUpdateSearcher *Searcher = NULL;
	ret = Session->CreateUpdateSearcher(&Searcher);//创建搜索对象
	if (FAILED(ret))
		return ERROR;

	ret = Searcher->put_Online(VARIANT_FALSE);//查询模式
	if (FAILED(ret))
		return ERROR;

	ISearchResult *SearchResult = NULL;
	BSTR barBstr = ::SysAllocString(L"IsInstalled = 0 and Type = 'Software'");//IsInstalled = 0表示未安装，1表示安装。
	ret = Searcher->Search(barBstr, &SearchResult); //执行搜索，结果集放在SearchResult中
	::SysFreeString(barBstr);
	if (SearchResult == NULL)//获取补丁信息失败
		return ERROR;
	if (FAILED(ret))
		return ERROR;

	IUpdateCollection *Collection;
	ret = SearchResult->get_Updates(&Collection);
	if (FAILED(ret))
		return ERROR;

	long Colnum;
	ret = Collection->get_Count(&Colnum);//安全补丁个数
	if (FAILED(ret))
		return ERROR;

	for (int i = 0; i < Colnum; i++)
	{
		IUpdate *Update;
		ret = Collection->get_Item(i, &Update);

		BSTR SecLevel = NULL;
		ret = Update->get_MsrcSeverity(&SecLevel);//Critical Important Moderate Low

		if (SecLevel != NULL)//补丁不是最新.(有些补丁没有安全等级,无需安装的。只要安装了有安全等级的补丁,认为最新)
									//个人认为
		{
			::SysFreeString(SecLevel);
			return FALSE;
		}
		::SysFreeString(SecLevel);
	}
	return TRUE;//补丁为最新
}


int DetectSecPatchEx(){
	HRESULT hr;
	hr = CoInitialize(NULL);
	{
		CComPtr<IUpdateSession> iUpdate;
		CComPtr<IUpdateSearcher> searcher;
		CComPtr<ISearchResult> results;
		BSTR criteria = SysAllocString(L"IsInstalled=1 and Type='Software'");

		hr = CoCreateInstance(CLSID_UpdateSession, NULL, CLSCTX_INPROC_SERVER, IID_IUpdateSession, (LPVOID*)&iUpdate);
		hr = iUpdate->CreateUpdateSearcher(&searcher);

		wcout << L"Searching for updates ..." << endl;
		hr = searcher->put_CanAutomaticallyUpgradeService(VARIANT_TRUE);
		hr = searcher->put_IncludePotentiallySupersededUpdates(VARIANT_TRUE);
		searcher->put_Online(VARIANT_FALSE);
		hr = searcher->Search(criteria, &results);
		SysFreeString(criteria);
		criteria = nullptr;

		switch (hr)
		{
		case S_OK:
			wcout << L"List of applicable items on the machine:" << endl;
			break;
		case WU_E_LEGACYSERVER:
			wcout << L"No server selection enabled" << endl;
			return 0;
		case WU_E_INVALID_CRITERIA:
			wcout << L"Invalid search criteria" << endl;
			return 0;
		}

		CComPtr<IUpdateCollection> updateList;
		LONG updateSize;
		results->get_Updates(&updateList);
		updateList->get_Count(&updateSize);

		if (updateSize == 0)
		{
			wcout << L"No updates found" << endl;
		}

		for (LONG i = 0; i < updateSize; i++)
		{
			CComPtr<IUpdate> updateItem;
			CComPtr<IStringCollection> kbStrings;
			CComPtr<IUpdateCollection> bundledUpdates;
			LONG bundledUpdateSize;
			BSTR updateName;
			BSTR kbStr;

			updateList->get_Item(i, &updateItem);
			updateItem->get_Title(&updateName);
			updateItem->get_KBArticleIDs(&kbStrings);
			LONG kbCnt = 0;
			kbStrings->get_Count(&kbCnt);
			for (long j = 0; j < kbCnt; j++) // 获取所有的kb值
			{

				kbStrings->get_Item(j, &kbStr);
				wcout << i + 1 << L"-" << j + 1 << L" KB" << kbStr << endl;
				::SysFreeString(kbStr);
				kbStr = nullptr;
			}

			// wcout << i + 1 << L" - " << updateName << endl;
			::SysFreeString(updateName);
			updateName = nullptr;
			updateItem->get_BundledUpdates(&bundledUpdates);
			bundledUpdates->get_Count(&bundledUpdateSize);

			if (bundledUpdateSize != 0)
			{
				for (LONG ii = 0; ii < bundledUpdateSize; ii++)
				{
					CComPtr<IUpdate> bundledUpdateItem;
					CComPtr<IStringCollection> bundledkbStrings;
					bundledUpdates->get_Item(ii, &bundledUpdateItem);
					bundledUpdateItem->get_Title(&updateName);
					bundledUpdateItem->get_KBArticleIDs(&bundledkbStrings);
					LONG kbCnt = 0;
					bundledkbStrings->get_Count(&kbCnt);
					for (long k = 0; k < kbCnt; k++)
					{

						bundledkbStrings->get_Item(k, &kbStr);
						wcout << i + 1 << L"-" << ii + 1 << L"-" << k + 1 << L" KB" << kbStr << endl;
						::SysFreeString(kbStr);
						kbStr = nullptr;
					}
					wcout << i + 1 << L" - " << ii + 1 << updateName << endl;
					::SysFreeString(updateName);
					updateName = nullptr;
				}

			}

		}
	}
	::CoUninitialize();
	return 0;
}



int GetKbDir(){
	HRESULT hr = CoInitialize(NULL);
	int count = 0;

	if (SUCCEEDED(hr))
	{
		CComPtr<IShellItem> pUpdates;
		CComPtr<IEnumShellItems> pShellEnum;

		hr = SHGetKnownFolderItem(FOLDERID_AppUpdates, static_cast<KNOWN_FOLDER_FLAG>(0), nullptr, IID_PPV_ARGS(&pUpdates));
		hr = pUpdates->BindToHandler(nullptr, BHID_EnumItems, IID_PPV_ARGS(&pShellEnum));
		if (pShellEnum)
		{
			do {
				CComPtr<IShellItem> pItem;
				CComHeapPtr<WCHAR> szName;

				hr = pShellEnum->Next(1, &pItem, nullptr);
				if (pItem)
				{
					HRESULT hres = pItem->GetDisplayName(SIGDN_NORMALDISPLAY, &szName);
					wcout << static_cast<LPWSTR>(szName) << endl;
					count++;
				}
			} while (hr == S_OK);
		}
	}
	CoUninitialize();
	wcout << L"Found " << count << " updates" << endl;
	return 0;
}
#include <list>
#include <wbemcli.h>
#pragma comment(lib, "wbemuuid.lib")

void GetHotFix(OUT std::list<CString>& list)

{

	HRESULT hres;

	BSTR bstrNameSpace = SysAllocString(L"root\\cimv2");

	BSTR bstrWQL = SysAllocString(L"WQL");

	BSTR bstrQuery = SysAllocString(L"SELECT * FROM Win32_QuickFixEngineering");



	// Step 1: --------------------------------------------------

	// Initialize COM. ------------------------------------------



	hres = CoInitializeEx(0, COINIT_MULTITHREADED);

	if (FAILED(hres))

	{

		// MessageBox(_T("Failed to initialize COM library./n"), _T("MSG"), MB_ICONINFORMATION);

		return;                  // Program has failed.

	}



	// Step 2: --------------------------------------------------

	// Set general COM security levels --------------------------

	// Note: If you are using Windows 2000, you need to specify -

	// the default authentication credentials for a user by using

	// a SOLE_AUTHENTICATION_LIST structure in the pAuthList ----

	// parameter of CoInitializeSecurity ------------------------



	hres = CoInitializeSecurity(

		NULL,

		-1,                          // COM authentication

		NULL,                        // Authentication services

		NULL,                        // Reserved

		RPC_C_AUTHN_LEVEL_DEFAULT,   // Default authentication

		RPC_C_IMP_LEVEL_IMPERSONATE, // Default Impersonation 

		NULL,                        // Authentication info

		EOAC_NONE,                   // Additional capabilities

		NULL                         // Reserved

	);





	if (FAILED(hres))

	{

		cout << "Failed to initialize security. Error code = 0x"

			<< hex << hres << endl;

		CoUninitialize();

		return ;                    // Program has failed.

	}



	// Step 3: ---------------------------------------------------

		// Obtain the initial locator to WMI -------------------------



	IWbemLocator *pLoc1 = NULL;



	hres = CoCreateInstance(

		CLSID_WbemLocator,

		0,

		CLSCTX_INPROC_SERVER,

		IID_IWbemLocator, (LPVOID *)&pLoc1);

	if (FAILED(hres))

	{

		// MessageBox(_T("Failed to create IWbemLocator object./n"), _T("MSG"), MB_ICONINFORMATION);

		CoUninitialize();

		return;                 // Program has failed.

	}



	// Step 4: -----------------------------------------------------

	// Connect to WMI through the IWbemLocator::ConnectServer method



	IWbemServices *pSvc1 = NULL;



	// Connect to the root/cimv2 namespace with

	// the current user and obtain pointer pSvc

	// to make IWbemServices calls.

	hres = pLoc1->ConnectServer(

		bstrNameSpace, // Object path of WMI namespace

		NULL,                    // User name. NULL = current user

		NULL,                    // User password. NULL = current

		0,                       // Locale. NULL indicates current

		NULL,                    // Security flags.

		0,                       // Authority (e.g. Kerberos)

		0,                       // Context object

		&pSvc1                    // pointer to IWbemServices proxy

	);



	if (FAILED(hres))

	{

		//add by peterhu 2008-02-27

		//if failed to give user a message to reffer

		// MessageBox(_T("Could not connect. Error./n"), _T("MSG"), MB_ICONINFORMATION);

		pLoc1->Release();

		CoUninitialize();

		return;                // Program has failed.

	}





	// Step 5: --------------------------------------------------

	// Set security levels on the proxy -------------------------



	hres = CoSetProxyBlanket(

		pSvc1,                        // Indicates the proxy to set

		RPC_C_AUTHN_WINNT,           // RPC_C_AUTHN_xxx

		RPC_C_AUTHZ_NONE,            // RPC_C_AUTHZ_xxx

		NULL,                        // Server principal name

		RPC_C_AUTHN_LEVEL_CALL,      // RPC_C_AUTHN_LEVEL_xxx

		RPC_C_IMP_LEVEL_IMPERSONATE, // RPC_C_IMP_LEVEL_xxx

		NULL,                        // client identity

		EOAC_NONE                    // proxy capabilities

	);



	if (FAILED(hres))

	{



		//add by peterhu 2008-02-27

		//if failed to give user a message to reffer

		// MessageBox(_T("Could not set proxy blanket./n"), _T("MSG"), MB_ICONINFORMATION);

		pSvc1->Release();

		pLoc1->Release();

		CoUninitialize();

		return;               // Program has failed.

	}





	// Step 6: --------------------------------------------------

	// Use the IWbemServices pointer to make requests of WMI ----



	// For example, get the name of the operating system

	IEnumWbemClassObject* pEnumerator = NULL;

	hres = pSvc1->ExecQuery(

		bstrWQL,

		bstrQuery,

		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,

		NULL,

		&pEnumerator);



	if (FAILED(hres))

	{

		//add by peterhu 2008-02-27

		//if failed to give user a message to reffer

		// MessageBox(_T("Query for operating system name failed./n"), _T("MSG"), MB_ICONINFORMATION);

		pSvc1->Release();

		pLoc1->Release();

		CoUninitialize();

		return;               // Program has failed.

	}





	// Step 7: -------------------------------------------------

// Get the data from the query in step 6 -------------------



	IWbemClassObject *pclsObj = nullptr;

	ULONG uReturn = 0;

	CString csTemp;

	int iResult = 0;



	while (pEnumerator)

	{



		HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1,

			&pclsObj, &uReturn);



		if (0 == uReturn)

		{

			break;

		}



		VARIANT vtProp;

		CString strHotfixID;

		CString strFixComments;

		// Get the value of the HotFixID property

		hr = pclsObj->Get(L"HotFixID", 0, &vtProp, 0, 0);

		strHotfixID = vtProp.bstrVal;

		// Get the value of the FixComments property

		hr = pclsObj->Get(L"FixComments", 0, &vtProp, 0, 0);

		strFixComments = vtProp.bstrVal;

		VariantClear(&vtProp);



		strFixComments.ReleaseBuffer();

		if (!strFixComments.IsEmpty())

		{

			strHotfixID.Append(_T("-"));

			strHotfixID += strFixComments;



		}



		strHotfixID.ReleaseBuffer();

		if (!strHotfixID.IsEmpty())

		{

			strHotfixID.Append(_T("/r/n"));

			list.push_back(strHotfixID);

		}

	}



	// Cleanup

	// ========

	pSvc1->Release();

	pLoc1->Release();

	pEnumerator->Release();

	pclsObj->Release();

	CoUninitialize();

}
#include <vector>
#include <iphlpapi.h>

#pragma comment(lib,"iphlpapi.lib")


typedef struct __IP_PORT_INFO__
{

}IP_PORT_INFO, *PIP_PORT_INFO;

int GetPortList(std::vector<IP_PORT_INFO> vecIpTalbeInfo)
{
	int iErrno;
	PMIB_TCPTABLE_OWNER_PID pMibTcpTableOwnerPid;
	DWORD dwSize = 0;
	TCHAR szBuffer[1024];
	if ((iErrno = GetExtendedTcpTable(NULL, &dwSize, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)) != NO_ERROR)
	{
		if (iErrno != ERROR_INSUFFICIENT_BUFFER)
		{
			wsprintf(szBuffer, _T("GetExtendedTcpTable Error: %d\n"), iErrno);
			OutputDebugString(szBuffer);
			return FALSE;
		}
	}
	pMibTcpTableOwnerPid = (PMIB_TCPTABLE_OWNER_PID)malloc(dwSize);
	if (pMibTcpTableOwnerPid == NULL)
	{
		OutputDebugString(_T("malloc Error!\n"));
		return FALSE;
	}
	if ((iErrno = GetExtendedTcpTable(pMibTcpTableOwnerPid, &dwSize, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)) != NO_ERROR)
	{
		wsprintf(szBuffer, _T("GetExtendedTcpTable Error: %d\n"), iErrno);
		OutputDebugString(szBuffer);
		return FALSE;
	}
}
#ifndef UNICODE
#define UNICODE
#endif
#pragma comment(lib, "netapi32.lib")

#include <stdio.h>
#include <windows.h> 
#include <lm.h>
#include <ntsecapi.h>
int GetCurrentMacPassPolicy(wchar_t* wsServerName = nullptr)
{
	DWORD dwLevel = 0;
	USER_MODALS_INFO_0 *pBuf = NULL;
	NET_API_STATUS nStatus;
	LPTSTR pszServerName = NULL;
	pszServerName = wsServerName;
	
	nStatus = NetUserModalsGet((LPCWSTR)pszServerName,
		dwLevel,
		(LPBYTE *)&pBuf);
	//
	// If the call succeeds, print the global information.
	//
	if (nStatus == NERR_Success)
	{
		if (pBuf != NULL)
		{
			printf("\tMinimum password length:  %d\n", pBuf->usrmod0_min_passwd_len);
			printf("\tMaximum password age (d): %d\n", pBuf->usrmod0_max_passwd_age / 86400);
			printf("\tMinimum password age (d): %d\n", pBuf->usrmod0_min_passwd_age / 86400);
			printf("\tForced log off time (s):  %d\n", pBuf->usrmod0_force_logoff);
			printf("\tPassword history length:  %d\n", pBuf->usrmod0_password_hist_len);
		}
	}
	// Otherwise, print the system error.
	//
	else
		fprintf(stderr, "A system error has occurred: %d\n", nStatus);
	//
	// Free the allocated memory.
	//
	if (pBuf != NULL)
		NetApiBufferFree(pBuf);

	return 0;
}

#include <iostream>
#include <windows.h>
#include <ntsecapi.h>

using namespace std;
#include "port_scanner.h"

int main()
{
	/*std::list<CString> hotfixLst;
	GetHotFix(hotfixLst);*/
#if 1
	port_scanner scanner;
	scanner.scan_port_ip_info();
	std::set<UINT> vecPortList;
	scanner.get_all_port(vecPortList);
	std::string strWinVersion;
	scanner.get_windows_ver(strWinVersion);
#endif
}
#include "password_manger.h"
#include "future"
void test_async()
{
	int a = 10;
	std::future<void>  m_future = std::async(std::launch::async, [=]() {
		OutputDebugString(L"\neeee\n");
		this_thread::sleep_for(chrono::seconds(a));
		OutputDebugString(L"\ndddd\n");
	});
	future_status m_status;
	do
	{
		this_thread::sleep_for(chrono::seconds(2));
		m_status = m_future.wait_for(chrono::seconds(1));
		switch (m_status)
		{
		case future_status::timeout:
			OutputDebugString(L"\naaaaa\n");
			break;
		case future_status::ready:
			OutputDebugString(L"\nbbbb\n");
			break;
		case future_status::deferred:
			OutputDebugString(L"\nccc\n");
			break;
		default:
			break;
		}
	} while (false);
}

void test_func_thread()
{
	std::thread([]() {
		test_async();
	}).detach();
}

//int main()
//{
//	// gen_account_ini();
//	test_func_thread();
//	Sleep(20000);
//	return 0;
//}
//int main()
//{
//	DWORD dwResult = 0;
//	PUSER_MODALS_INFO_0 pDPInfo = NULL;
//
//	dwResult = NetUserModalsGet(NULL, 0, (LPBYTE *)&pDPInfo);
//	if (dwResult == NERR_Success)
//	{
//		/*if (!(pDPInfo->PasswordProperties & DOMAIN_PASSWORD_COMPLEX))
//		{
//			cout << "Password complexity is disabled" << endl;
//		}
//		else
//		{
//			cout << "Password complexity is enabled" << endl;
//		}*/
//	}
//	else
//	{
//		cout << "Error: " << dwResult << endl;
//	}
//
//	NetApiBufferFree(pDPInfo);
//
//	return 0;
//}


//#if 1
//int _tmain(int argc, _TCHAR* argv[])
//{
//	// wcout << L" bundled update severity: " << endl;
//	// MessageBox(0, 0, 0, 0);
//	setlocale(LC_ALL, "");
//	//std::list<CString> hotfixLst;
//	//GetHotFix(hotfixLst);
//	//int i = 0;
//	//for (auto av : hotfixLst)
//	//{
//	//	i++;
//	//	wcout << i << L" - " << av.GetString() << endl;
//	//}
//	GetCurrentMacPassPolicy();
//
//	// DetectSecPatchEx();
//	// GetKbDir();
//	// DetectSecPatch();
//}
//#else
//
//int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
//	_In_opt_ HINSTANCE hPrevInstance,
//	_In_ LPWSTR    lpCmdLine,
//	_In_ int       nCmdShow)
//{
//	
//	// LoadSelfDiagnosisInterface();
//	setlocale(LC_ALL, "");
//	DetectSecPatchEx();
//}
//#endif 

// #include "stdafx.h" 


#if 0
int _tmain(int argc, _TCHAR* argv[])
{


	HRESULT hr;
	hr = CoInitialize(NULL);

	IUpdateSession* iUpdate;
	IUpdateSearcher* searcher;
	ISearchResult* results;
	BSTR criteria = SysAllocString(L"IsInstalled=0");

	hr = CoCreateInstance(CLSID_UpdateSession, NULL, CLSCTX_INPROC_SERVER, IID_IUpdateSession, (LPVOID*)&iUpdate);
	hr = iUpdate->CreateUpdateSearcher(&searcher);

	wcout << L"Searching for updates ..." << endl;
	hr = searcher->Search(criteria, &results);
	SysFreeString(criteria);

	switch (hr)
	{
	case S_OK:
		wcout << L"List of applicable items on the machine:" << endl;
		break;
	case WU_E_LEGACYSERVER:
		wcout << L"No server selection enabled" << endl;
		return 0;
	case WU_E_INVALID_CRITERIA:
		wcout << L"Invalid search criteria" << endl;
		return 0;
	}

	IUpdateCollection *updateList;
	IUpdateCollection *bundledUpdates;
	IUpdate *updateItem;
	IUpdate *bundledUpdateItem;
	LONG updateSize;
	LONG bundledUpdateSize;
	BSTR updateName;
	BSTR severity;

	results->get_Updates(&updateList);
	updateList->get_Count(&updateSize);

	if (updateSize == 0)
	{
		wcout << L"No updates found" << endl;
	}

	for (LONG i = 0; i < updateSize; i++)
	{
		updateList->get_Item(i, &updateItem);
		updateItem->get_Title(&updateName);

		severity = NULL;
		updateItem->get_MsrcSeverity(&severity);
		if (severity != NULL)
		{
			wcout << L"update severity: " << severity << endl;
		}

		wcout << i + 1 << " - " << updateName << endl;

		// bundled updates 
		updateItem->get_BundledUpdates(&bundledUpdates);
		bundledUpdates->get_Count(&bundledUpdateSize);

		if (bundledUpdateSize != 0)
		{
			// iterate through bundled updates 
			for (LONG ii = 0; ii < bundledUpdateSize; ii++)
			{
				bundledUpdates->get_Item(ii, &bundledUpdateItem);
				severity = NULL;
				bundledUpdateItem->get_MsrcSeverity(&severity);
				if (severity != NULL)
				{
					wcout << L" bundled update severity: " << severity << endl;
				}
			}

		}

	}

	::CoUninitialize();
	wcin.get();


	return 0;
}
#endif