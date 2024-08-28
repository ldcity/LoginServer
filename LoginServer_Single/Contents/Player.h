#ifndef __PLAYER_CLASS__
#define __PLAYER_CLASS__

#include "../PCH.h"

// 상수 정의
constexpr ULONG64 INVALID_SESSION_ID = static_cast<ULONG64>(-1);
constexpr INT64 INVALID_ACCOUNT_NO = static_cast<INT64>(-1);
constexpr short INVALID_SECTOR = static_cast<short>(-1);

struct Player
{
	ULONG64 sessionID;								// 세션 ID
	INT64 accountNo;								// 회원 번호
	char sessionKey[64];							// 인증토큰
	wchar_t ID[IDMAXLEN];							// ID
	wchar_t nickname[NICKNAMEMAXLEN];				// 닉네임

	short sectorX;
	short sectorY;

	bool disconnect;

	DWORD recvLastTime;								// 하트비트 시간

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
