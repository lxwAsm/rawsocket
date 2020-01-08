// sniffer.cpp : �������̨Ӧ�ó������ڵ㡣
//

#include "stdafx.h"
# include "winsock2.h"
# include "ws2tcpip.h"
# include<stdio.h>
#include <mstcpip.h>

#pragma comment(lib,"ws2_32.lib")       // sokect 2

typedef struct _TCP
{
	WORD SrcPort; // Դ�˿� 
	WORD DstPort; // Ŀ�Ķ˿�
	DWORD SeqNum; // ˳���
	DWORD AckNum; // ȷ�Ϻ�
	BYTE DataOff; // TCPͷ��
	BYTE Flags; // ��־��URG��ACK�ȣ�
	WORD Window; // ���ڴ�С
	WORD Chksum; // У���
	WORD UrgPtr; // ����ָ��
} TCP;
typedef TCP *LPTCP;
typedef TCP UNALIGNED * ULPTCP;

typedef struct _UDP
{
	unsigned short SrcPort; //WORD SrcPort; // Դ�˿�
	unsigned short DstPort; //WORD DstPort; // Ŀ�Ķ˿�
	short Length;           //WORD Length; // UDP ����
	unsigned short Chksum;   //WORD Chksum; // У���
} UDP;
typedef UDP *LPUDP;
typedef UDP UNALIGNED * ULPUDP;


typedef struct _IP
{
	union{
		BYTE Version; // �汾       //    |ǰ4λ �� �汾��| ��4λ ��ͷ�ĳ���|
		BYTE HdrLen; // IHL                //���У�ͷ�ĵ�һ���ֶ�ָ������IP�汾��Ŀǰͨ���ǰ汾4��ͷ������ָ������ͷ�У� 3 2
		// λ��һ���ж��ٸ���һͷ�ĳ��ȱ�����3 2λ����������
	};
	BYTE ServiceType; // ��������
	WORD TotalLen; // �ܳ�
	WORD ID; // ��ʶ
	union{
		WORD Flags; // ��־
		WORD FragOff; // �ֶ�ƫ��
	};
	BYTE TimeToLive; // ������
	BYTE Protocol; // Э��
	WORD HdrChksum; // ͷУ���
	DWORD SrcAddr; // Դ��ַ
	DWORD DstAddr; // Ŀ�ĵ�ַ
	BYTE Options[0]; // ѡ��
	// ����Network Programming for Microsoft Windows 1st ������
	//IPѡ���ֶ���һ�����Ȳ������ֶΣ�������ĳЩ��ѡ����Ϣ��ͨ����I P��ȫ��·��ѡ���й�
	//�����У�û��˵���ȷ��������ȣ��е����϶�һ���ṹҲ��û������ṹ�ģ���������Ҳע�͵��ˣ����ܻ��
	//��ȷ�Ķ˿ںš�

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
	// ����ԭʼ�׽��� ////////�������һ��ѡ�����ʱIPPROTO_IP�����յ������
	//ԭ��Ϊsock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);������ղ����������
	sock = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
	if (sock == INVALID_SOCKET)
	{
		printf("socket create fail !\n");
	}
	// ����IPͷ����ѡ�����flag ����Ϊtrue�����Զ�IPͷ���д���
	// ����IPͷ����ѡ�����flag ����Ϊtrue�����Զ�IPͷ���д���
	//ԭ������ bool flag��true�����в��ɹ�����Ϊ int  flag =1;
	if (0 != setsockopt(sock, IPPROTO_IP, IP_HDRINCL, (char*)&flag, sizeof(flag)))
	{
		printf("setsockopt fail  ! \n");
	}

	// ��ȡ������
	if (0 != gethostname((char*)LocalName, sizeof(LocalName) - 1))
	{
		printf("gethostname fail  ! \n");
	}
	else
	{
		printf("hostname=%s \n", LocalName);
	}

	// ��ȡ���� IP ��ַ
	pHost = gethostbyname((char*)LocalName);
	if (pHost == NULL)
	{
		printf("gethostbyname fail  ! \n");
	}

	// ���SOCKADDR_IN�ṹ
	addr_in.sin_addr = *(in_addr *)pHost->h_addr_list[0]; //IP
	addr_in.sin_family = AF_INET;
	addr_in.sin_port = htons(45882);

	// ��ԭʼ�׽���sock �󶨵�����������ַ��
	if (0 != bind(sock, (PSOCKADDR)&addr_in, sizeof(addr_in)))
	{
		printf("bind failed ! \n");
	}
	// dwValueΪ�������������Ϊ1ʱִ�У�0ʱȡ��
	DWORD dwValue = 1;
	// ���� SOCK_RAW ΪSIO_RCVALL���Ա�������е�IP��������SIO_RCVALL
	// �Ķ���Ϊ�� #define SIO_RCVALL _WSAIOW(IOC_VENDOR,1)
	if (0 != ioctlsocket(sock, SIO_RCVALL, &dwValue))
	{
		printf("ioctlsocket failed !\n");
	}

	while (true)
	{
		//If no incoming data is available at the socket, the recv call blocks and waits for data to arrive according to the blocking rules defined for WSARecv with the MSG_PARTIAL flag not set unless the socket is nonblocking. In this case, a value of SOCKET_ERROR is returned with the error code set to WSAEWOULDBLOCK. The select, WSAAsyncSelect, or WSAEventSelect functions can be used to determine when more data arrives
		// ����ԭʼ���ݰ���Ϣ
		int ret = recv(sock, RecvBuf, BUFFER_SIZE, 0);

		if (ret > 0)
		{
			printf("%s", RecvBuf);
			// �����ݰ����з�����������������
			ip = *(IP*)RecvBuf;
			tcp = *(TCP*)(RecvBuf + 4 * (ip.HdrLen & 0xF)); //ip.HdrLen  & 0xF �õ�IPͷ���ȣ����������32λ�ֵĸ���
			printf("Э�飺 %s\r\n", GetProtocolTxt(ip.Protocol));
			printf("IPԴ��ַ�� %s\r\n", inet_ntoa(*(in_addr*)&ip.SrcAddr));
			printf("IPĿ���ַ: %s\r\n", inet_ntoa(*(in_addr*)&ip.DstAddr));
			printf("TCPԴ�˿ںţ� %d\r\n", ntohs(tcp.SrcPort)); //��Ҫntohs()ת�����ܵõ�������Ҫ�Ķ˿ں�
			//The ntohs function converts a u_short from TCP/IP network byte order to host byte order (which is little-endian on Intel processors).
			printf("TCPĿ��˿ںţ�%d\r\n", ntohs(tcp.DstPort));
			printf("���ݰ����ȣ� %d\r\n\r\n\r\n", ntohs(ip.TotalLen));

		}
		else if (ret == 0)
		{
			printf("the connection has been gracefully closed\r\n");
		}
	}





}

