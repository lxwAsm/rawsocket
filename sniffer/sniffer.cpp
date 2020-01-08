// sniffer.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
# include "winsock2.h"
# include "ws2tcpip.h"
# include<stdio.h>
#include <mstcpip.h>

#pragma comment(lib,"ws2_32.lib")       // sokect 2

typedef struct _TCP
{
	WORD SrcPort; // 源端口 
	WORD DstPort; // 目的端口
	DWORD SeqNum; // 顺序号
	DWORD AckNum; // 确认号
	BYTE DataOff; // TCP头长
	BYTE Flags; // 标志（URG、ACK等）
	WORD Window; // 窗口大小
	WORD Chksum; // 校验和
	WORD UrgPtr; // 紧急指针
} TCP;
typedef TCP *LPTCP;
typedef TCP UNALIGNED * ULPTCP;

typedef struct _UDP
{
	unsigned short SrcPort; //WORD SrcPort; // 源端口
	unsigned short DstPort; //WORD DstPort; // 目的端口
	short Length;           //WORD Length; // UDP 长度
	unsigned short Chksum;   //WORD Chksum; // 校验和
} UDP;
typedef UDP *LPUDP;
typedef UDP UNALIGNED * ULPUDP;


typedef struct _IP
{
	union{
		BYTE Version; // 版本       //    |前4位 是 版本号| 后4位 是头的长度|
		BYTE HdrLen; // IHL                //其中，头的第一个字段指定的是IP版本，目前通常是版本4。头长度是指在整个头中， 3 2
		// 位字一共有多少个（一头的长度必须是3 2位的整数倍）
	};
	BYTE ServiceType; // 服务类型
	WORD TotalLen; // 总长
	WORD ID; // 标识
	union{
		WORD Flags; // 标志
		WORD FragOff; // 分段偏移
	};
	BYTE TimeToLive; // 生命期
	BYTE Protocol; // 协议
	WORD HdrChksum; // 头校验和
	DWORD SrcAddr; // 源地址
	DWORD DstAddr; // 目的地址
	BYTE Options[0]; // 选项
	// 根据Network Programming for Microsoft Windows 1st 的描述
	//IP选项字段是一个长度不定的字段，包含了某些可选的信息，通常与I P安全或路由选择有关
	//但书中，没有说如何确定这个长度，有的书上定一个结构也是没有这个结构的，所以这里也注释掉了，才能获得
	//正确的端口号。

} IP;
typedef IP * LPIP;
typedef IP UNALIGNED * ULPIP;


char * GetProtocolTxt(int Protocol)
{
	switch (Protocol){
	case IPPROTO_ICMP: //1
		return "ICMP";
	case IPPROTO_TCP: //6 
		return "TCP";
	case IPPROTO_UDP: //17  
		return "UDP";
	default:
		return "unknown";
	}

}


int main()
{

	sockaddr_in addr_in;
	const int  BUFFER_SIZE = 65535;
	int  flag = 1;
	char LocalName[256];
	hostent  * pHost;
	char RecvBuf[BUFFER_SIZE];
	SOCKET sock;
	IP ip;
	TCP tcp;
	WSADATA WSAData;

	if (0 != WSAStartup(MAKEWORD(2, 2), &WSAData))
	{
		printf("WSAStartup fail to initialize !\n");
	}
	// 创建原始套接字 ////////这里最后一个选项必须时IPPROTO_IP才能收到网络包
	//原来为sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);，结果收不到网络包。
	sock = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
	if (sock == INVALID_SOCKET)
	{
		printf("socket create fail !\n");
	}
	// 设置IP头操作选项，其中flag 设置为true，亲自对IP头进行处理
	// 设置IP头操作选项，其中flag 设置为true，亲自对IP头进行处理
	//原来声明 bool flag＝true，运行不成功，改为 int  flag =1;
	if (0 != setsockopt(sock, IPPROTO_IP, IP_HDRINCL, (char*)&flag, sizeof(flag)))
	{
		printf("setsockopt fail  ! \n");
	}

	// 获取本机名
	if (0 != gethostname((char*)LocalName, sizeof(LocalName) - 1))
	{
		printf("gethostname fail  ! \n");
	}
	else
	{
		printf("hostname=%s \n", LocalName);
	}

	// 获取本地 IP 地址
	pHost = gethostbyname((char*)LocalName);
	if (pHost == NULL)
	{
		printf("gethostbyname fail  ! \n");
	}

	// 填充SOCKADDR_IN结构
	addr_in.sin_addr = *(in_addr *)pHost->h_addr_list[0]; //IP
	addr_in.sin_family = AF_INET;
	addr_in.sin_port = htons(45882);

	// 把原始套接字sock 绑定到本地网卡地址上
	if (0 != bind(sock, (PSOCKADDR)&addr_in, sizeof(addr_in)))
	{
		printf("bind failed ! \n");
	}
	// dwValue为输入输出参数，为1时执行，0时取消
	DWORD dwValue = 1;
	// 设置 SOCK_RAW 为SIO_RCVALL，以便接收所有的IP包。其中SIO_RCVALL
	// 的定义为： #define SIO_RCVALL _WSAIOW(IOC_VENDOR,1)
	if (0 != ioctlsocket(sock, SIO_RCVALL, &dwValue))
	{
		printf("ioctlsocket failed !\n");
	}

	while (true)
	{
		//If no incoming data is available at the socket, the recv call blocks and waits for data to arrive according to the blocking rules defined for WSARecv with the MSG_PARTIAL flag not set unless the socket is nonblocking. In this case, a value of SOCKET_ERROR is returned with the error code set to WSAEWOULDBLOCK. The select, WSAAsyncSelect, or WSAEventSelect functions can be used to determine when more data arrives
		// 接收原始数据包信息
		int ret = recv(sock, RecvBuf, BUFFER_SIZE, 0);

		if (ret > 0)
		{
			printf("%s", RecvBuf);
			// 对数据包进行分析，并输出分析结果
			ip = *(IP*)RecvBuf;
			tcp = *(TCP*)(RecvBuf + 4 * (ip.HdrLen & 0xF)); //ip.HdrLen  & 0xF 得到IP头长度，这个长度是32位字的个数
			printf("协议： %s\r\n", GetProtocolTxt(ip.Protocol));
			printf("IP源地址： %s\r\n", inet_ntoa(*(in_addr*)&ip.SrcAddr));
			printf("IP目标地址: %s\r\n", inet_ntoa(*(in_addr*)&ip.DstAddr));
			printf("TCP源端口号： %d\r\n", ntohs(tcp.SrcPort)); //需要ntohs()转换才能得到正常所要的端口号
			//The ntohs function converts a u_short from TCP/IP network byte order to host byte order (which is little-endian on Intel processors).
			printf("TCP目标端口号：%d\r\n", ntohs(tcp.DstPort));
			printf("数据包长度： %d\r\n\r\n\r\n", ntohs(ip.TotalLen));

		}
		else if (ret == 0)
		{
			printf("the connection has been gracefully closed\r\n");
		}
	}





}

