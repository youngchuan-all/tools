#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <Psapi.h>
#include <ip2string.h>
#include <tchar.h>
#include "port_scanner.h"
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "ws2_32.lib")

std::wstring StringToWString(const std::string& str,
	unsigned int code_page /* CP_UTF8 */) {
	return StringToWString(str.c_str(), code_page);
}

std::string WStringToString(const std::wstring& wstr,
	unsigned int code_page /* CP_UTF8 */) {
	return WStringToString(wstr.c_str(), code_page);
}

std::wstring StringToWString(const char* source,
	unsigned int code_page) {
	const auto len = static_cast<int>(std::strlen(source));
	std::wstring ret;
	ret.resize(len);
	const auto result = MultiByteToWideChar(code_page                     /*CodePage*/,
		0                             /*dwFlags*/,
		source                        /*lpMultiByteStr*/,
		len                           /*cbMultiByte*/,
		&ret[0]                       /*lpWideCharStr*/,
		static_cast<int>(ret.length())/*cchWideChar*/);
	if (!result) {
		return L"";
	}
	ret.resize(result);
	return ret;
}

std::string WStringToString(const wchar_t* source,
	unsigned int code_page) {
	const auto len = static_cast<int>(std::wcslen(source));
	std::string ret;
	if (int requiredSizeInBytes = WideCharToMultiByte(code_page /*CodePage*/,
		0         /*dwFlags*/,
		source    /*lpWideCharStr*/,
		len       /*cchWideChar*/,
		nullptr   /*lpMultiByteStr*/,
		0         /*cbMultiByte*/,
		nullptr   /*lpDefaultChar*/,
		nullptr   /*lpUsedDefaultChar*/)) {
		ret.resize(requiredSizeInBytes);
	}
	const auto result = WideCharToMultiByte(code_page                         /*CodePage*/,
		0                                 /*dwFlags*/,
		source                            /*lpWideCharStr*/,
		len                               /*cchWideChar*/,
		&ret[0]                           /*lpMultiByteStr*/,
		static_cast<int>(ret.length())    /*cbMultiByte*/,
		nullptr                           /*lpDefaultChar*/,
		nullptr                           /*lpUsedDefaultChar*/);
	if (!result) {
		return "";
	}
	ret.resize(result);
	return ret;
}

typedef DWORD(WINAPI * PFN_GET_EXTENDED_TCP_TABLE)
(
	PVOID pTcpTable,
	PDWORD pdwSize,
	BOOL bOrder,
	ULONG ulAf,
	TCP_TABLE_CLASS TableClass,
	ULONG Reserved
);

typedef DWORD(WINAPI * PFN_GET_EXTENDED_UDP_TABLE)
(
	PVOID pUdpTable,
	PDWORD pdwSize,
	BOOL bOrder,
	ULONG ulAf,
	UDP_TABLE_CLASS TableClass,
	ULONG Reserved
);

void port_scanner::scan_port_ip_info()
{
	scan_tcp();
	scan_tcp6();
	scan_udp();
	scan_udp6();
}

void port_scanner::get_all_port(std::set<UINT> &vecPortList)
{
	for (auto port_info : port_info_vec)
	{
		if (port_info.type == "tcp")
		{
			vecPortList.insert(port_info.local_port);
			vecPortList.insert(port_info.remote_port);
		}
		else if(port_info.type == "udp")
		{
			vecPortList.insert(port_info.local_port);
		}
		else
		{
			OutputDebugString(L"unknown type");
		}
	}
}

BOOL port_scanner::scan_tcp()
{
	int iErrno;
	PMIB_TCPTABLE  pMibTcpTableAll;
	// PMIB_TCP6TABLE pMibTcp6TableAll;
	DWORD dwSize = 0;
	TCHAR szBuffer[1024];
	int i;
	HMODULE hModule;
	// PFN_GET_EXTENDED_TCP_TABLE GetExtendedTcpTable;

	// hModule = LoadLibrary(L"iphlpapi.dll");
	// GetExtendedTcpTable = (PFN_GET_EXTENDED_TCP_TABLE)GetProcAddress(hModule, "GetExtendedTcpTable");
	if ((iErrno = GetExtendedTcpTable(NULL, &dwSize, TRUE, AF_INET, TCP_TABLE_BASIC_ALL, 0)) != NO_ERROR)
	{
		if (iErrno != ERROR_INSUFFICIENT_BUFFER)
		{
			wsprintf(szBuffer, L"GetExtendedTcpTable Error: %d\n", iErrno);
			OutputDebugString(szBuffer);
			return FALSE;
		}
	}
	pMibTcpTableAll = (PMIB_TCPTABLE)malloc(dwSize);
	if (pMibTcpTableAll == NULL)
	{
		OutputDebugString(L"malloc Error!\n");
		return FALSE;
	}
	// auto ret = GetExtendedTcpTable(pMibTcpTableAll, &dwSize, TRUE, AF_INET, TCP_TABLE_BASIC_ALL, 0);

	if ((iErrno = GetExtendedTcpTable(pMibTcpTableAll, &dwSize, TRUE, AF_INET, TCP_TABLE_BASIC_ALL, 0)) != NO_ERROR)
	{
		wsprintf(szBuffer, L"GetExtendedTcpTable Error: %d\n", iErrno);
		OutputDebugString(szBuffer);
		return FALSE;
	}

	for (i = 0; i < (int)pMibTcpTableAll->dwNumEntries; i++)
	{
		IN_ADDR localAddr;
		IN_ADDR remoteAddr;
		TCHAR szLocalAddr[1024];
		TCHAR szRemoteAddr[1024];
		USHORT usLocalPort;
		USHORT usRemotePort;
		TCHAR szState[1024];
		DWORD dwWriteNum;
		TCHAR szLocal[1024];
		TCHAR szRemote[1024];

		localAddr.S_un.S_addr = pMibTcpTableAll->table[i].dwLocalAddr;
		remoteAddr.S_un.S_addr = pMibTcpTableAll->table[i].dwRemoteAddr;
		MultiByteToWideChar(CP_ACP, 0, inet_ntoa(localAddr), -1, (LPWSTR)szLocalAddr, 1024);
		MultiByteToWideChar(CP_ACP, 0, inet_ntoa(remoteAddr), -1, (LPWSTR)szRemoteAddr, 1024);
		std::string status;
		switch (pMibTcpTableAll->table[i].dwState)
		{
		case MIB_TCP_STATE_CLOSED:
			wsprintf(szState, _T("%s"), _T("CLOSED"));
			status = "CLOSED";
			break;
		case MIB_TCP_STATE_LISTEN:
			wsprintf(szState, _T("%s"), _T("LISTENING"));
			status = "LISTENING";
			break;
		case MIB_TCP_STATE_SYN_SENT:
			wsprintf(szState, _T("%s"), _T("SYN_SENT"));
			status = "SYN_SENT";
			break;
		case MIB_TCP_STATE_SYN_RCVD:
			wsprintf(szState, _T("%s"), _T("SYN_RCVD"));
			status = "SYN_RCVD";
			break;
		case MIB_TCP_STATE_ESTAB:
			wsprintf(szState, _T("%s"), _T("ESTABLISHED"));
			status = "ESTABLISHED";
			break;
		case MIB_TCP_STATE_FIN_WAIT1:
			wsprintf(szState, _T("%s"), _T("FIN_WAIT_1"));
			status = "FIN_WAIT_1";
			break;
		case MIB_TCP_STATE_FIN_WAIT2:
			wsprintf(szState, _T("%s"), _T("FIN_WAIT_2"));
			status = "FIN_WAIT_2";
			break;
		case MIB_TCP_STATE_CLOSE_WAIT:
			wsprintf(szState, _T("%s"), _T("CLOSE_WAIT"));
			status = "CLOSED";
			break;
		case MIB_TCP_STATE_CLOSING:
			wsprintf(szState, _T("%s"), _T("CLOSING"));
			status = "CLOSING";
			break;
		case MIB_TCP_STATE_LAST_ACK:
			wsprintf(szState, _T("%s"), _T("LAST_ACK"));
			status = "LAST_ACK";
			break;
		case MIB_TCP_STATE_TIME_WAIT:
			wsprintf(szState, _T("%s"), _T("TIME_WAIT"));
			status = "TIME_WAIT";
			break;
		case MIB_TCP_STATE_DELETE_TCB:
			wsprintf(szState, _T("%s"), _T("DELETE_TCB"));
			status = "DELETE_TCB";
			break;
		}
		usLocalPort = ntohs((USHORT)pMibTcpTableAll->table[i].dwLocalPort);
		usRemotePort = _tcscmp(szState, _T("LISTENING")) == 0 ? 0 : ntohs((USHORT)pMibTcpTableAll->table[i].dwRemotePort);
		wsprintf(szLocal, _T("%s:%d"), szLocalAddr, usLocalPort);
		wsprintf(szRemote, _T("%s:%d"), szRemoteAddr, usRemotePort);
		wsprintf(szBuffer, _T("  %-7s%-23s%-23s%-16s\n"), _T("TCP"), szLocal, szRemote, szState);// , pMibTcpTableOwnerPid->table[i].dwOwningPid);
		WriteConsole(GetStdHandle(STD_OUTPUT_HANDLE), szBuffer, (DWORD)_tcslen(szBuffer), &dwWriteNum, NULL);
		PORT_INFO info;
		info.type = "tcp";
		info.local_addr = inet_ntoa(localAddr);
		info.remote_addr = inet_ntoa(remoteAddr);
		info.local_port = usLocalPort;
		info.remote_port = usRemotePort;
		info.status = status;
		port_info_vec.push_back(info);
		// add_scan_port_2_map(usLocalPort, pMibTcpTableOwnerPid->table[i].dwOwningPid, inet_ntoa(localAddr));
	}
#if 0
	for (i = 0; i < (int)pMibTcp6TableAll->dwNumEntries; i++)
	{
		IN6_ADDR localAddr;
		IN6_ADDR remoteAddr;
		TCHAR szLocalAddr[1024];
		TCHAR szRemoteAddr[1024];
		USHORT usLocalPort;
		USHORT usRemotePort;
		TCHAR szState[1024];
		DWORD dwWriteNum;
		TCHAR szLocal[1024];
		TCHAR szRemote[1024];

		std::string strlocalAddr;
		std::string strRemoteAddr;
		localAddr = pMibTcp6TableAll->table[i].LocalAddr;
		remoteAddr = pMibTcp6TableAll->table[i].RemoteAddr;
		RtlIpv6AddressToStringW(&localAddr, szLocalAddr);
		RtlIpv6AddressToStringW(&remoteAddr, szRemoteAddr);

		std::string status;
		switch (pMibTcpTableAll->table[i].dwState)
		{
		case MIB_TCP_STATE_CLOSED:
			wsprintf(szState, _T("%s"), _T("CLOSED"));
			status = "CLOSED";
			break;
		case MIB_TCP_STATE_LISTEN:
			wsprintf(szState, _T("%s"), _T("LISTENING"));
			status = "LISTENING";
			break;
		case MIB_TCP_STATE_SYN_SENT:
			wsprintf(szState, _T("%s"), _T("SYN_SENT"));
			status = "SYN_SENT";
			break;
		case MIB_TCP_STATE_SYN_RCVD:
			wsprintf(szState, _T("%s"), _T("SYN_RCVD"));
			status = "SYN_RCVD";
			break;
		case MIB_TCP_STATE_ESTAB:
			wsprintf(szState, _T("%s"), _T("ESTABLISHED"));
			status = "ESTABLISHED";
			break;
		case MIB_TCP_STATE_FIN_WAIT1:
			wsprintf(szState, _T("%s"), _T("FIN_WAIT_1"));
			status = "FIN_WAIT_1";
			break;
		case MIB_TCP_STATE_FIN_WAIT2:
			wsprintf(szState, _T("%s"), _T("FIN_WAIT_2"));
			status = "FIN_WAIT_2";
			break;
		case MIB_TCP_STATE_CLOSE_WAIT:
			wsprintf(szState, _T("%s"), _T("CLOSE_WAIT"));
			status = "CLOSED";
			break;
		case MIB_TCP_STATE_CLOSING:
			wsprintf(szState, _T("%s"), _T("CLOSING"));
			status = "CLOSING";
			break;
		case MIB_TCP_STATE_LAST_ACK:
			wsprintf(szState, _T("%s"), _T("LAST_ACK"));
			status = "LAST_ACK";
			break;
		case MIB_TCP_STATE_TIME_WAIT:
			wsprintf(szState, _T("%s"), _T("TIME_WAIT"));
			status = "TIME_WAIT";
			break;
		case MIB_TCP_STATE_DELETE_TCB:
			wsprintf(szState, _T("%s"), _T("DELETE_TCB"));
			status = "DELETE_TCB";
			break;
		}
		usLocalPort = ntohs((USHORT)pMibTcp6TableAll->table[i].dwLocalPort);
		usRemotePort = _tcscmp(szState, _T("LISTENING")) == 0 ? 0 : ntohs((USHORT)pMibTcp6TableAll->table[i].dwRemotePort);
		wsprintf(szLocal, _T("%s:%d"), szLocalAddr, usLocalPort);
		wsprintf(szRemote, _T("%s:%d"), szRemoteAddr, usRemotePort);
		wsprintf(szBuffer, _T("  %-7s%-23s%-23s%-16s\n"), _T("TCP"), szLocal, szRemote, szState);// , pMibTcpTableOwnerPid->table[i].dwOwningPid);
		WriteConsole(GetStdHandle(STD_OUTPUT_HANDLE), szBuffer, (DWORD)_tcslen(szBuffer), &dwWriteNum, NULL);
		PORT_INFO info;
		info.type = "tcp";
		info.local_addr = WStringToString(szLocalAddr,CP_UTF8);
		info.remote_addr = WStringToString(szRemoteAddr, CP_UTF8);
		info.local_port = usLocalPort;
		info.remote_port = usRemotePort;
		info.status = status;
		port_info_vec.push_back(info);
		// add_scan_port_2_map(usLocalPort, pMibTcpTableOwnerPid->table[i].dwOwningPid, inet_ntoa(localAddr));
	}
	free(pMibTcp6TableAll);
#endif

	free(pMibTcpTableAll);
	
	// FreeLibrary(hModule);
	return TRUE;
}

BOOL port_scanner::scan_udp()
{
	int iErrno;
	PMIB_UDPTABLE pMibUdpTableAll;
	DWORD dwSize = 0;
	TCHAR szBuffer[1024];
	int i;
	HMODULE hModule;
	// PFN_GET_EXTENDED_UDP_TABLE GetExtendedUdpTable;

	// hModule = LoadLibrary(_T("iphlpapi.dll"));
	// GetExtendedUdpTable = (PFN_GET_EXTENDED_UDP_TABLE)GetProcAddress(hModule, "GetExtendedUdpTable");

	if ((iErrno = GetExtendedUdpTable(NULL, &dwSize, TRUE, AF_INET, UDP_TABLE_BASIC, 0)) != NO_ERROR)
	{
		if (iErrno != ERROR_INSUFFICIENT_BUFFER)
		{
			wsprintf(szBuffer, _T("GetExtendedUdpTable Error: %d\n"), iErrno);
			OutputDebugString(szBuffer);
			return FALSE;
		}
	}
	pMibUdpTableAll = (PMIB_UDPTABLE)malloc(dwSize);
	if (pMibUdpTableAll == NULL)
	{
		OutputDebugString(_T("malloc Error!"));
		return FALSE;
	}
	if ((iErrno = GetExtendedUdpTable(pMibUdpTableAll, &dwSize, TRUE, AF_INET, UDP_TABLE_BASIC, 0)) != NO_ERROR)
	{
		wsprintf(szBuffer, _T("GetExtendedUdpTable Error: %d\n"), iErrno);
		OutputDebugString(szBuffer);
		return FALSE;
	}

	for (i = 0; i < (int)pMibUdpTableAll->dwNumEntries; i++)
	{
		IN_ADDR localAddr;
		TCHAR szLocalAddr[1024];
		USHORT usLocalPort;
		TCHAR szLocal[1024];
		TCHAR szRemote[1024];
		TCHAR szState[1024];
		DWORD dwWriteNum;

		localAddr.S_un.S_addr = pMibUdpTableAll->table[i].dwLocalAddr;
		usLocalPort = ntohs((USHORT)pMibUdpTableAll->table[i].dwLocalPort);
		MultiByteToWideChar(CP_ACP, 0, inet_ntoa(localAddr), -1, (LPWSTR)szLocalAddr, 1024);
		wsprintf(szLocal, _T("%s:%d"), szLocalAddr, usLocalPort);
		wsprintf(szRemote, _T("*:*"));
		wsprintf(szState, _T(""));
		wsprintf(szBuffer, _T("  %-7s%-23s%-23s%-16s\n"), _T("UDP"), szLocal, szRemote, szState);//  , pMibUdpTableOwnerPid->table[i].dwOwningPid);
		WriteConsole(GetStdHandle(STD_OUTPUT_HANDLE), szBuffer, (DWORD)_tcslen(szBuffer), &dwWriteNum, NULL);
		PORT_INFO info;
		info.type = "udp";
		info.local_addr = inet_ntoa(localAddr);
		info.remote_addr = "";
		info.local_port = usLocalPort;
		info.remote_port = 0;
		info.status = "";
		port_info_vec.push_back(info);
		// add_scan_port_2_map(usLocalPort, pMibUdpTableOwnerPid->table[i].dwOwningPid, inet_ntoa(localAddr));
	}

	free(pMibUdpTableAll);
	// FreeLibrary(hModule);
	return TRUE;
}
#if 1
BOOL port_scanner::scan_udp6()
{
	PMIB_UDP6TABLE pUdpTable;
	// PMIB_TCP6TABLE pTcpTable;
	DWORD dwSize = 0;
	DWORD dwRetVal = 0;

	wchar_t ipstringbuffer[46];

	int i;

	pUdpTable = (PMIB_UDP6TABLE)malloc(sizeof(PMIB_UDP6TABLE));
	if (pUdpTable == NULL) {
		wprintf(L"Error allocating memory\n");
		return 1;
	}

	dwSize = sizeof(MIB_UDP6TABLE);
	// Make an initial call to GetTcp6Table to
	// get the necessary size into the dwSize variable
	if ((dwRetVal = GetUdp6Table(pUdpTable, &dwSize, TRUE)) ==
		ERROR_INSUFFICIENT_BUFFER) {
		free(pUdpTable);
		pUdpTable = (PMIB_UDP6TABLE)malloc(dwSize);
		if (pUdpTable == NULL) {
			wprintf(L"Error allocating memory\n");
			return 1;
		}
	}
	// Make a second call to GetTcp6Table to get
	// the actual data we require
	if ((dwRetVal = GetUdp6Table(pUdpTable, &dwSize, TRUE)) == NO_ERROR) {
		wprintf(L"\tNumber of entries: %d\n", (int)pUdpTable->dwNumEntries);
		for (i = 0; i < (int)pUdpTable->dwNumEntries; i++) {
			PORT_INFO info;
			info.local_port = pUdpTable->table[i].dwLocalPort;
			
			wprintf(L"\tUDP[%d] Local Port: %d\n", i,
				ntohs((u_short)pUdpTable->table[i].dwLocalPort));
		}
	}
	else {
		wprintf(L"\tGetUdp6Table failed with %d\n", dwRetVal);
		free(pUdpTable);
		return 1;
	}

	if (pUdpTable != NULL) {
		free(pUdpTable);
		pUdpTable = NULL;
	}

	return 0;
}

BOOL port_scanner::scan_tcp6()
{
	PMIB_TCP6TABLE pTcpTable;
	DWORD dwSize = 0;
	DWORD dwRetVal = 0;

	wchar_t ipstringbuffer[46];

	int i;

	pTcpTable = (MIB_TCP6TABLE *)malloc(sizeof(MIB_TCP6TABLE));
	if (pTcpTable == NULL) {
		wprintf(L"Error allocating memory\n");
		return 1;
	}

	dwSize = sizeof(MIB_TCP6TABLE);
	// Make an initial call to GetTcp6Table to
	// get the necessary size into the dwSize variable
	if ((dwRetVal = GetTcp6Table(pTcpTable, &dwSize, TRUE)) ==
		ERROR_INSUFFICIENT_BUFFER) {
		free(pTcpTable);
		pTcpTable = (MIB_TCP6TABLE *)malloc(dwSize);
		if (pTcpTable == NULL) {
			wprintf(L"Error allocating memory\n");
			return 1;
		}
	}
	// Make a second call to GetTcp6Table to get
	// the actual data we require
	if ((dwRetVal = GetTcp6Table(pTcpTable, &dwSize, TRUE)) == NO_ERROR) {
		wprintf(L"\tNumber of entries: %d\n", (int)pTcpTable->dwNumEntries);
		for (i = 0; i < (int)pTcpTable->dwNumEntries; i++) {
			wprintf(L"\n\tTCP[%d] State: %ld - ", i,
				pTcpTable->table[i].State);
			switch (pTcpTable->table[i].State) {
			case MIB_TCP_STATE_CLOSED:
				wprintf(L"CLOSED\n");
				break;
			case MIB_TCP_STATE_LISTEN:
				wprintf(L"LISTEN\n");
				break;
			case MIB_TCP_STATE_SYN_SENT:
				wprintf(L"SYN-SENT\n");
				break;
			case MIB_TCP_STATE_SYN_RCVD:
				wprintf(L"SYN-RECEIVED\n");
				break;
			case MIB_TCP_STATE_ESTAB:
				wprintf(L"ESTABLISHED\n");
				break;
			case MIB_TCP_STATE_FIN_WAIT1:
				wprintf(L"FIN-WAIT-1\n");
				break;
			case MIB_TCP_STATE_FIN_WAIT2:
				wprintf(L"FIN-WAIT-2 \n");
				break;
			case MIB_TCP_STATE_CLOSE_WAIT:
				wprintf(L"CLOSE-WAIT\n");
				break;
			case MIB_TCP_STATE_CLOSING:
				wprintf(L"CLOSING\n");
				break;
			case MIB_TCP_STATE_LAST_ACK:
				wprintf(L"LAST-ACK\n");
				break;
			case MIB_TCP_STATE_TIME_WAIT:
				wprintf(L"TIME-WAIT\n");
				break;
			case MIB_TCP_STATE_DELETE_TCB:
				wprintf(L"DELETE-TCB\n");
				break;
			default:
				wprintf(L"UNKNOWN dwState value\n");
				break;
			}

			if (InetNtop(AF_INET6, &pTcpTable->table[i].LocalAddr, ipstringbuffer, 46) == NULL)
				wprintf(L"  InetNtop function failed for local IPv6 address\n");
			else
				wprintf(L"\tTCP[%d] Local Addr: %s\n", i, ipstringbuffer);
			wprintf(L"\tTCP[%d] Local Scope ID: %d \n", i,
				ntohl(pTcpTable->table[i].dwLocalScopeId));
			wprintf(L"\tTCP[%d] Local Port: %d \n", i,
				ntohs((u_short)pTcpTable->table[i].dwLocalPort));

			if (InetNtop(AF_INET6, &pTcpTable->table[i].RemoteAddr, ipstringbuffer, 46) == NULL)
				wprintf(L"  InetNtop function failed for remote IPv6 address\n");
			else
				wprintf(L"\tTCP[%d] Remote Addr: %s\n", i, ipstringbuffer);
			wprintf(L"\tTCP[%d] Remote Scope ID: %d \n", i,
				ntohl(pTcpTable->table[i].dwRemoteScopeId));
			wprintf(L"\tTCP[%d] Remote Port: %d\n", i,
				ntohs((u_short)pTcpTable->table[i].dwRemotePort));
		}
	}
	else {
		wprintf(L"\tGetTcp6Table failed with %d\n", dwRetVal);
		free(pTcpTable);
		return 1;
	}

	if (pTcpTable != NULL) {
		free(pTcpTable);
		pTcpTable = NULL;
	}

	return 0;
}
#endif

port_scanner::port_scanner()
{
	port_info_vec.clear();
}


BOOL port_scanner::getOsVersion(OSVERSIONINFOEXW& OSVersionInfo) {
	ZeroMemory(&OSVersionInfo, sizeof(OSVERSIONINFOEXW));

#pragma warning( disable : 4996 )
	OSVersionInfo.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEXW);
	if (!GetVersionExW((LPOSVERSIONINFOW)&OSVersionInfo)) {
		return FALSE;
	}
#pragma warning( default : 4996 )

	if (OSVersionInfo.dwMajorVersion == 6 && OSVersionInfo.dwMinorVersion == 2) {
		// 从Windows8开始，用GetVersionEx()获取版本号都返回6.2，要调用内部API来获取准确的版本
		HMODULE hModNtdll = NULL;
		DWORD dwMajorVer = 0;
		DWORD dwMinorVer = 0;
		DWORD dwBuildNumber = 0;
		if (hModNtdll = ::LoadLibraryA("ntdll.dll")) {
			typedef void (WINAPI* pfRTLGETNTVERSIONNUMBERS)(DWORD*, DWORD*, DWORD*);
			pfRTLGETNTVERSIONNUMBERS pfRtlGetNtVersionNumbers;
			pfRtlGetNtVersionNumbers = (pfRTLGETNTVERSIONNUMBERS)::GetProcAddress(hModNtdll, "RtlGetNtVersionNumbers");
			if (pfRtlGetNtVersionNumbers) {
				pfRtlGetNtVersionNumbers(&dwMajorVer, &dwMinorVer, &dwBuildNumber);
				dwBuildNumber &= 0x0ffff;
			}
		}
		else {
			return FALSE;
		}
		::FreeLibrary(hModNtdll);
		OSVersionInfo.dwMajorVersion = dwMajorVer;
		OSVersionInfo.dwMinorVersion = dwMinorVer;
		OSVersionInfo.dwBuildNumber = dwBuildNumber;
	}

	return TRUE;
}

void port_scanner::get_windows_ver(std::string &verstr) {
	OSVERSIONINFOEXW OSVersionInfo = { 0 };
	BOOL bIsWin7Below = FALSE;
	if (getOsVersion(OSVersionInfo)) {
		verstr = std::to_string(OSVersionInfo.dwMajorVersion) +"." + std::to_string(OSVersionInfo.dwMinorVersion) + "." + std::to_string(OSVersionInfo.dwBuildNumber);
	}
}