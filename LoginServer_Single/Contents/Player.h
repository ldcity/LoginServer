#ifndef __PLAYER_CLASS__
#define __PLAYER_CLASS__

#include "../PCH.h"

// ��� ����
constexpr ULONG64 INVALID_SESSION_ID = static_cast<ULONG64>(-1);
constexpr INT64 INVALID_ACCOUNT_NO = static_cast<INT64>(-1);
constexpr short INVALID_SECTOR = static_cast<short>(-1);

struct Player
{
	ULONG64 sessionID;								// ���� ID
	INT64 accountNo;								// ȸ�� ��ȣ
	char sessionKey[64];							// ������ū
	wchar_t ID[IDMAXLEN];							// ID
	wchar_t nickname[NICKNAMEMAXLEN];				// �г���

	short sectorX;
	short sectorY;

	bool disconnect;

	DWORD recvLastTime;								// ��Ʈ��Ʈ �ð�

	Player(ULONG64 _sessionID = INVALID_SESSION_ID,
		INT64 _accountNo = INVALID_ACCOUNT_NO,
		const wchar_t* _ID = L"",
		const wchar_t* _nickname = L"",
		short _sectorX = INVALID_SECTOR,
		short _sectorY = INVALID_SECTOR) : 
		sessionID(_sessionID), accountNo(_accountNo), sectorX(_sectorX), sectorY(_sectorY), recvLastTime(0), disconnect(false) {}
	Player(ULONG64 _sessionID, INT64 _accountNo, const wchar_t* _ID, const wchar_t* _nickname,
		short _sectorX, short _sectorY) :
		sessionID(_sessionID), accountNo(_accountNo), sectorX(_sectorX), sectorY(_sectorY), sessionKey{ 0 }, recvLastTime(0), disconnect(false)
	{
		wmemcpy_s(ID, IDMAXLEN, _ID, IDMAXLEN);
		wmemcpy_s(nickname, NICKNAMEMAXLEN, _nickname, NICKNAMEMAXLEN);
	}

};

#endif // !__PLAYER_CLASS__
