#ifndef __CHATTING_PACKET__
#define __CHATTING_PACKET__

#include <winsock2.h>
#include <Windows.h>

#include "../Library/SerializingBuffer.h"

// ä�ü��� �α��� ���� ��Ŷ
void MPResLogin(CPacket* packet, INT64 accountNo, BYTE status, WCHAR* id, WCHAR* nickname, WCHAR* gameServerIP, USHORT gameServerPort, WCHAR* chatServerIP, USHORT chatServerPort);

#endif
