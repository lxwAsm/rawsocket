
#include <Windows.h>
typedef struct IpHeader {
	unsigned char Version_HLen;//�汾�� �ײ�����
	unsigned char TOS;//��������
	unsigned short Length;//�ܳ���
	unsigned short Ident; //��ʶ
	unsigned short Flags_Offset; //��־ Ƭƫ�� 
	unsigned char TTL; //����ʱ��
	unsigned char Protocol; //Э��
	unsigned short Checksum; //�ײ�У��� 
	unsigned int SourceAddr; //Դ��ַ
	unsigned int DestinationAddr; //Ŀ�ĵ�ַ
} Ip_Header;


//TCP �ı�־
#define URG 0x20 
#define ACK 0x10 
#define PSH 0x08
#define RST 0x04
#define SYN 0x02
#define FIN 0x01

//���� TCP �ײ� 
typedef struct TcpHeader {
	USHORT SrcPort;//16 λԴ�˿�
	USHORT DstPort; //16 λĿ�Ķ˿�
	unsigned int SequenceNum; //32 λ���
	unsigned int Acknowledgment; //32 Ϊȷ����� 
	unsigned char HdrLen; //�ײ�����
	unsigned char Flags; //6 λ��־λ
	USHORT AdvertisedWindow; //16 λ���ڴ�С 
	USHORT Checksum; //16 λУ���
	USHORT UrgPtr; //16 λ����ָ��
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

