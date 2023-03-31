#pragma once
#include <string>
#include <vector>
#include <wtypes.h>
#include <set>

typedef struct __PORT_INFO__
{
	std::string type;
	std::string remote_addr;
	std::string local_addr;
	UINT32 remote_port;
	UINT32 local_port;
	std::string status;

	__PORT_INFO__()
	{
		type = "";
		remote_addr = "";
		local_addr = "";
		remote_port = 0;
		local_port = 0;
		status = "";
	}

}PORT_INFO, *PPORTINFO;

class port_scanner
{
public:
	port_scanner();
	void scan_port_ip_info();
	void get_all_port(std::set<UINT32> &vecPortList);
	void get_windows_ver(std::string &verstr);
private:
	BOOL scan_tcp();
	BOOL scan_udp();
	BOOL scan_tcp6();
	BOOL scan_udp6();

	std::vector<PORT_INFO> port_info_vec;
	BOOL getOsVersion(OSVERSIONINFOEXW& OSVersionInfo);
};


