// rawsocket.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include <iostream>
#include "windows.h"
#pragma comment(lib,"wsock32.lib")

using namespace std;


USHORT checksum(USHORT *buffer, int size) {
	unsigned long cksum = 0; //
	while (size > 1)
	{
		cksum += *buffer++;
		size -= sizeof(USHORT);
	}
	if (size) {
		cksum += *(UCHAR*)buffer;
	}
	cksum = (cksum >> 16) + (cksum & 0xffff); 
	cksum += (cksum >> 16);
	return (USHORT)(~cksum);
}

int _tmain(int argc, _TCHAR* argv[])
{
	WSAData wsaData;
	auto Result = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (Result == SOCKET_ERROR)
	{
		printf("WSAStartup failed with error %d\n", Result);
		return -1;
	}

	cout << "MaxSocket:" << wsaData.iMaxSockets << endl;
	cout << "MaxUdpDg:" << wsaData.iMaxUdpDg << endl;
	cout << "VersionInfo:" << wsaData.lpVendorInfo << endl;
	cout << "Description:" << wsaData.lpVendorInfo << endl;
	cout << "SystemStatus:" << wsaData.szSystemStatus << endl;
	cout << "HighVersion:" << wsaData.wHighVersion << endl;
	cout << "Version:" << wsaData.wVersion << endl;
	WSACleanup();
	return 0;
}

