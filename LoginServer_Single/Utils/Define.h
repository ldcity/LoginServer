#ifndef __SERVER_DEFINE__
#define __SERVER_DEFINE__

#include "../PCH.h"

// 1회 송수신 시, WSABUF 최대 제한
#define MAXWSABUF 200

// ioRefCount에서 ReleaseFlag 확인용 비트마스크
#define RELEASEMASKING 0x80000000

#define IDMAXLEN			20
#define NICKNAMEMAXLEN		20
#define MSGMAXLEN			64

#define GAMESERVERIP		16
#define CHATSERVERIIP		16

#define MAXPACKETLEN		348

#pragma pack(1)
// LAN Header
struct LanHeader
{
	// Payload Len
	short len;
};

// WAN Header
struct WanHeader
{
	unsigned char code;
	short len;
	unsigned char randKey;
	unsigned char checkSum;
};
#pragma pack()

#endif // !__SERVER_DEFINE__
