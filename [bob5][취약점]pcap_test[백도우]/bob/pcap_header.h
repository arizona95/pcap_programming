#pragma once
#include <pcap.h>
typedef struct _eth_header {
	UCHAR                dest_addr[6];                  // 목적지 주소
	UCHAR                src_addr[6];                    // 출발지 주소
	USHORT             d_type;                            // 이더넷 유형 또는 ieee 길이
} ETH_HEADER, *PETH_HEADER;

typedef struct _ip_header {
	//little endian begin
	USHORT             len : 4;         //버전
	USHORT             version : 4;         //헤더 길이
											// little endian end
	USHORT             tos : 8;         // 서비스 유형
	USHORT             length;                              // 전체 길이
	USHORT             id;                                    // 16 비트 아이디
															  //little endian begin
	USHORT             fragment_offset1 : 5;         // 단편화 옵셋
	USHORT             flags : 3;         // flag
	USHORT             fragment_offset2 : 8;         // 단편화 옵셋
													 //little endian end
	USHORT             ttl : 8;         // ttl
	USHORT             protocol : 8;         // protocol tcp==06
	USHORT             checksum;                                    // 헤더 첵섬
	ULONG               src_ip;                                          // 출발지 IP
	ULONG               dest_ip;                                        // 목적지 IP
} IP_HEADER, *PIP_HEADER;

typedef struct _tcp_header {
	USHORT             src_port;                          // 출발지 port
	USHORT             dest_port;                        // 목적지 port
	ULONG               sqc_number;                    // 시컨스 넘버
	ULONG               ack_number;                    // ack 넘버
													   //little endian begin
	USHORT             reserved1 : 4;                      // reserved
	USHORT             length : 4;                      // 헤더 길이
	USHORT             fin : 1;                      // FIN
	USHORT             syn : 1;                      // SYN
	USHORT             rst : 1;                      // RST
	USHORT             psh : 1;                      // PSH
	USHORT             ack : 1;                      // ACK
	USHORT             urg : 1;                      // URG
	USHORT             reserved2 : 2;                      // reserved
														   //little endian end
	USHORT             window_size;                                // 윈도우 크기
	USHORT             tcp_checksum;                             // TCP checksum
	USHORT             urg_point;                                      //긴급 포인터
} TCP_HEADER, *PTCP_HEADER;
