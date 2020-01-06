// rawsocket.cpp : �������̨Ӧ�ó������ڵ㡣
//

#include "stdafx.h"
#include <iostream>
//#include <Windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include "ip.h"
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
	WSADATA wsaData = { 0 };
	char szSendBuf[1024] = { 0 };
	SOCKADDR_IN addr_in;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0){
		printf("WSAStartup() error!");
		return -1;
	}
	
	auto hSock = WSASocket(AF_INET, SOCK_RAW, IPPROTO_RAW, NULL, 0, WSA_FLAG_OVERLAPPED);
	if (hSock == INVALID_SOCKET)
	{
		printf("create socket failed with error %d\n", WSAGetLastError()); 
		closesocket(hSock);
		return -1;
	}
	//���÷��͵�ַ
	addr_in.sin_family = AF_INET;
	addr_in.sin_port = htons(5555);
	addr_in.sin_addr.S_un.S_addr = inet_addr("127.0.0.1");
	//----�ֶ�����IP
	BOOL flag=true;
	if (setsockopt(hSock, IPPROTO_IP, 2, (char*)&flag, sizeof(flag)) ==SOCKET_ERROR) {
		printf("setsockopt IP failed with error %d\n\n", WSAGetLastError());
		return false;
	}
	//���ó�ʱ
	int nTimeOver = 1000;
	if (setsockopt(hSock, SOL_SOCKET, SO_SNDTIMEO, (char*)&nTimeOver,sizeof(nTimeOver)) == SOCKET_ERROR) {
		printf("setsockopt Timeover failed with error %d\n\n", WSAGetLastError());
		return false;
	}
	//���ӱ���IP��ַ
	/*struct sockaddr_in ServerAddr = { 0 };
	ServerAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
	ServerAddr.sin_port = htons(5555);
	ServerAddr.sin_family = AF_INET;
	auto errNo = connect(hSock, (sockaddr*)&ServerAddr, sizeof(ServerAddr));
	if (errNo == SOCKET_ERROR)
	{
		printf("connect failed with error %d\n", WSAGetLastError());
		closesocket(hSock);
		return 0;
	}*/
	IPTCP	pacp = { 0 };
	pacp.ip.TTL = 128;
	pacp.ip.Checksum = 0;
	pacp.ip.DestinationAddr = inet_addr("127.0.0.1");
	pacp.ip.SourceAddr = inet_addr("127.0.0.1");
	pacp.ip.Version_HLen = (4 << 4 | sizeof(pacp.ip) / sizeof(unsigned long));
	pacp.ip.TOS = 0;
	pacp.ip.Protocol = IPPROTO_TCP;
	pacp.ip.Ident = 1;
	pacp.ip.Length = htons(sizeof(pacp.ip) + sizeof(pacp.tcp));
	pacp.ip.Flags_Offset = 0;
	//-----����IP�����-------------
	pacp.tcp.DstPort = htons(5555);//Ŀ�Ķ˿ں�
	pacp.tcp.SrcPort = htons(1234); //Դ�˿ں�
	pacp.tcp.SequenceNum = htonl(0x123);
	pacp.tcp.Acknowledgment = 0;
	pacp.tcp.HdrLen = (sizeof(pacp.tcp) / 4 << 4 | 0);
	pacp.tcp.Flags = 2; //�޸�������ʵ�ֲ�ͬ�ı�־λ̽�⣬2��SYN��1��FIN��16��ACK̽�� �ȵ�
	pacp.tcp.AdvertisedWindow = htons(512);
	pacp.tcp.UrgPtr = 0;
	pacp.tcp.Checksum = 0;
	//-----����tcp�����------------
	pacp.psd_header.SourceAddr = pacp.ip.SourceAddr;
	pacp.psd_header.DestinationAddr = pacp.ip.DestinationAddr;
	pacp.psd_header.Zero = 0;
	pacp.psd_header.Protcol = IPPROTO_TCP;
	pacp.psd_header.TcpLen = htons(sizeof(pacp.tcp));
	//------psd tcp�������-----------
	
	memcpy(szSendBuf, &pacp.psd_header, sizeof(pacp.psd_header));
	memcpy(szSendBuf + sizeof(pacp.psd_header), &pacp.tcp, sizeof(pacp.tcp));
	pacp.tcp.Checksum = checksum((USHORT *)szSendBuf, sizeof(pacp.psd_header) + sizeof(pacp.tcp));
	//����tcpУ���
	memset(szSendBuf, 0, 1024);
	//------����IPУ���
	memcpy(szSendBuf, &pacp.ip, sizeof(pacp.ip));
	memcpy(szSendBuf + sizeof(pacp.ip), &pacp.tcp, sizeof(pacp.tcp));
	memset(szSendBuf + sizeof(pacp.ip) + sizeof(pacp.tcp), 0, 4);
	pacp.ip.Checksum = checksum((USHORT *)szSendBuf, sizeof(pacp.ip) + sizeof(pacp.tcp));
	memcpy(szSendBuf, &pacp.ip, sizeof(pacp.ip));
	//send data
	auto ret = sendto(hSock, szSendBuf, sizeof(pacp.ip) + sizeof(pacp.tcp),0, (struct sockaddr*)&addr_in, sizeof(addr_in));
	if (ret == SOCKET_ERROR)
	{
		printf("send error!:%d/n", WSAGetLastError());
		return false;
	}
	else{
		printf("send ok!/n");
	}
	
	WSACleanup();
	getchar();
	return 0;
}

