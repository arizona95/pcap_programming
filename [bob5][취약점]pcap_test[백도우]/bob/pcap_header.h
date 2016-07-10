#pragma once
#include <pcap.h>
typedef struct _eth_header {
	UCHAR                dest_addr[6];                  // ������ �ּ�
	UCHAR                src_addr[6];                    // ����� �ּ�
	USHORT             d_type;                            // �̴��� ���� �Ǵ� ieee ����
} ETH_HEADER, *PETH_HEADER;

typedef struct _ip_header {
	//little endian begin
	USHORT             len : 4;         //����
	USHORT             version : 4;         //��� ����
											// little endian end
	USHORT             tos : 8;         // ���� ����
	USHORT             length;                              // ��ü ����
	USHORT             id;                                    // 16 ��Ʈ ���̵�
															  //little endian begin
	USHORT             fragment_offset1 : 5;         // ����ȭ �ɼ�
	USHORT             flags : 3;         // flag
	USHORT             fragment_offset2 : 8;         // ����ȭ �ɼ�
													 //little endian end
	USHORT             ttl : 8;         // ttl
	USHORT             protocol : 8;         // protocol tcp==06
	USHORT             checksum;                                    // ��� ý��
	ULONG               src_ip;                                          // ����� IP
	ULONG               dest_ip;                                        // ������ IP
} IP_HEADER, *PIP_HEADER;

typedef struct _tcp_header {
	USHORT             src_port;                          // ����� port
	USHORT             dest_port;                        // ������ port
	ULONG               sqc_number;                    // ������ �ѹ�
	ULONG               ack_number;                    // ack �ѹ�
													   //little endian begin
	USHORT             reserved1 : 4;                      // reserved
	USHORT             length : 4;                      // ��� ����
	USHORT             fin : 1;                      // FIN
	USHORT             syn : 1;                      // SYN
	USHORT             rst : 1;                      // RST
	USHORT             psh : 1;                      // PSH
	USHORT             ack : 1;                      // ACK
	USHORT             urg : 1;                      // URG
	USHORT             reserved2 : 2;                      // reserved
														   //little endian end
	USHORT             window_size;                                // ������ ũ��
	USHORT             tcp_checksum;                             // TCP checksum
	USHORT             urg_point;                                      //��� ������
} TCP_HEADER, *PTCP_HEADER;
