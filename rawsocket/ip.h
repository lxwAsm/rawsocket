
#include <Windows.h>
typedef struct IpHeader {
	unsigned char Version_HLen;//版本号 首部长度
	unsigned char TOS;//服务类型
	unsigned short Length;//总长度
	unsigned short Ident; //标识
	unsigned short Flags_Offset; //标志 片偏移 
	unsigned char TTL; //生存时间
	unsigned char Protocol; //协议
	unsigned short Checksum; //首部校验和 
	unsigned int SourceAddr; //源地址
	unsigned int DestinationAddr; //目的地址
} Ip_Header;


//TCP 的标志
#define URG 0x20 
#define ACK 0x10 
#define PSH 0x08
#define RST 0x04
#define SYN 0x02
#define FIN 0x01

//定义 TCP 首部 
typedef struct TcpHeader {
	USHORT SrcPort;//16 位源端口
	USHORT DstPort; //16 位目的端口
	unsigned int SequenceNum; //32 位序号
	unsigned int Acknowledgment; //32 为确认序号 
	unsigned char HdrLen; //首部长度
	unsigned char Flags; //6 位标志位
	USHORT AdvertisedWindow; //16 位窗口大小 
	USHORT Checksum; //16 位校验和
	USHORT UrgPtr; //16 位紧急指针
} Tcp_Header;

typedef struct PsdTcpHeader {
	unsigned long SourceAddr;
	unsigned long DestinationAddr;
	char Zero;
	char Protcol;
	unsigned short TcpLen;
} PSD_Tcp_Header;

typedef struct IPTCP {
	IpHeader ip;
	TcpHeader tcp;
	PsdTcpHeader psd_header;
} IPTCP;

