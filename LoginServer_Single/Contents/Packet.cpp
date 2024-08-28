#include "../PCH.h"
#include "Packet.h"

// 로그인 응답 패킷 
void mpResLogin(CPacket* packet, INT64 accountNo, BYTE status, WCHAR* id, WCHAR* nickname, WCHAR* gameServerIP, USHORT gameServerPort, WCHAR* chatServerIP, USHORT chatServerPort)
{
	WORD type = en_PACKET_CS_LOGIN_RES_LOGIN;

	*packet << type << accountNo << status;

	packet->PutData((char*)id, IDMAXLEN * sizeof(wchar_t));
	packet->PutData((char*)nickname, NICKNAMEMAXLEN * sizeof(wchar_t));

	packet->PutData((char*)gameServerIP, GAMESERVERIP * sizeof(wchar_t));
	*packet << gameServerPort;

	packet->PutData((char*)chatServerIP, CHATSERVERIIP * sizeof(wchar_t));
	*packet << chatServerPort;
}
