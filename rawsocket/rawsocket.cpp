// rawsocket.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include <iostream>
#include <winsock2.h>
#pragma comment(lib,"ws2_32.lib")

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
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0){
		printf("WSAStartup() error!");
		return -1;
	}
	printf("MaxSocket:%d\n",wsaData.iMaxSockets);
	printf("MaxUdpDg:%d\n" ,wsaData.iMaxUdpDg);
	printf("VersionInfo:%p\n",wsaData.lpVendorInfo);
	printf("Description:%p\n",wsaData.lpVendorInfo);
	printf("SystemStatus:%s\n",wsaData.szSystemStatus);
	printf("HighVersion:%d\n",wsaData.wHighVersion);
	printf("Version:%d\n",wsaData.wVersion);
	WSACleanup();
	getchar();
	return 0;
}

