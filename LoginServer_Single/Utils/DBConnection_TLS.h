#ifndef __DBCONNECTION_TLS_CLASS__
#define __DBCONNECTION_TLS_CLASS__

#include "PCH.h"

class DBConnector_TLS
{
public:
	DBConnector_TLS(const wchar_t* host, const wchar_t* user, const wchar_t* password, const wchar_t* db, unsigned short port, bool sslOff);
	~DBConnector_TLS();

	enum myDB
	{
		QUERY_MAX_LEN = 1024,
		QUERY_MAX_TIME = 1000,
		DBCONNECT_TRY = 5,
		SHORT_LEN = 16,
		MIDDLE_LEN = 64,
		LONG_LEN = 128
	};

	// DB 연결
	bool Open();

	// DB 연결 끊기
	void Close();

	// Make Query - 쿼리 날리고 결과 임시 보관
	// [return]
	// -1 : 일반적인 실패
	// 0 : 쿼리 성공 후 반환된 row 값이 0 (table 내에 없는 값 select
	// 1 이상 : 쿼리 성공 후 반환된 row 값
	int Query(const wchar_t* strFormat, ...);

	// Make Query - 쿼리 날리고 결과 저장 X
	bool QuerySave(const wchar_t* strFormat, ...);

	// 쿼리 날린 것에 대한 결과 뽑아오기
	MYSQL_ROW FetchRow();

	// 한 쿼리에 대한 결과 모두 사용 후 정리
	void FreeResult();

	void* GetConnectionStatus();

	void onError();

private:
	DBConnector* GetDBConnector();

private:
	wchar_t mHost[SHORT_LEN];
	wchar_t mUser[MIDDLE_LEN];
	wchar_t mPassword[MIDDLE_LEN];
	wchar_t mDB[MIDDLE_LEN];

	unsigned short mPort;
	bool mFlag;

	// TLS
	DWORD tlsIndex;

	// 리소스 정리 작업 : DB 세션은 프로세스 종료 시 해제되지 않기 때문에 사용된 Session들을 추적해 해제해줘야 함
	LockFreeStack<DBConnector*> DBStack;
};

#endif