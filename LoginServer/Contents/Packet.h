#ifndef __CHATTING_PACKET__
#define __CHATTING_PACKET__

#include "PCH.h"

// 채팅서버 로그인 응답 패킷
void mpResLogin(CPacket* packet, INT64 accountNo, BYTE status, WCHAR* id, WCHAR* nickname, WCHAR* gameServerIP, USHORT gameServerPort, WCHAR* chatServerIP, USHORT chatServerPort);

#endif
