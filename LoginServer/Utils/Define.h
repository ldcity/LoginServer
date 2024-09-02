#ifndef __SERVER_DEFINE__
#define __SERVER_DEFINE__

#include "../PCH.h"

#define ID_MAX_LEN			20
#define NICKNAME_MAX_LEN	20
#define MSG_MAX_LEN			64

#define GAMESERVERIP		16
#define CHATSERVERIIP		16

#define MAX_PACKET_LEN		348

#define PACKET_CODE			0x56
#define KEY					0xa9

#pragma pack(1)
// LAN Header
struct LANHeader
{
	// Payload Len
	short len;
};

// Net Header
struct NetHeader
{
	unsigned char code;
	short len;
	unsigned char randKey;
	unsigned char checkSum;
};

#pragma pack()

struct Player
{
	ULONG64 sessionID;								// ���� ID
	INT64 accountNo;								// ȸ�� ��ȣ
	char sessionKey[64];							// ������ū
	wchar_t ID[ID_MAX_LEN];							// ID
	wchar_t nickname[NICKNAME_MAX_LEN];				// �г���

	short sectorX;
	short sectorY;
	
	bool disconnect;
	bool login;
	
	DWORD recvLastTime;						// ��Ʈ��Ʈ �ð�

	Player() : sessionID(-1), accountNo(-1), sessionKey{ 0 }, ID{ 0 }, nickname{ 0 }, 
		sectorX(-1), sectorY(-1), recvLastTime(0), disconnect(false), login(false) {}
	Player(ULONG64 _sessionID, INT64 _accountNo, const wchar_t* _ID, const wchar_t* _nickname,
		short _sectorX, short _sectorY) :
		sessionID(_sessionID), accountNo(_accountNo), sectorX(_sectorX), sectorY(_sectorY), sessionKey{ 0 }, recvLastTime(0), disconnect(false), login(false)
	{
		wmemcpy_s(ID, ID_MAX_LEN, _ID, ID_MAX_LEN);
		wmemcpy_s(nickname, NICKNAME_MAX_LEN, _nickname, NICKNAME_MAX_LEN);
	}

};

enum DBLENSIZE
{
	QUERY_MAX_LEN = 1024,
	QUERY_MAX_TIME = 1000,
	DBCONNECT_TRY = 5,
	SHORT_LEN = 16,
	MIDDLE_LEN = 64,
	LONG_LEN = 128
};




#endif // !__SERVER_DEFINE__
