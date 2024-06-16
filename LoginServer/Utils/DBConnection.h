#ifndef __DBCONNECTION_CLASS__
#define __DBCONNECTION_CLASS__

#include "PCH.h"

class DBConnector
{
public:
	DBConnector(const wchar_t* host, const wchar_t* user, const wchar_t* password, const wchar_t* db, unsigned short port, bool sslOff);
	~DBConnector();

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

	// Transaction Start
	bool StartTransaction();

	// Commit
	bool Commit();

	// Make Query - 쿼리 날리고 결과 임시 보관
	// [return]
	// -1 : 일반적인 실패
	// 0 : 쿼리 성공 후 반환된 row 값이 0 (table 내에 없는 값 select
	// 1 이상 : 쿼리 성공 후 반환된 row 값
	int Query(const wchar_t* strFormat, ...);
	
	// Make Query - 쿼리 날리고 결과 저장 X
	bool QuerySave(const wchar_t* strFormat, ...);

	// Transaction ~ Query ~ Commit
	bool AllQuery(std::string query);

	// 쿼리 날린 것에 대한 결과 뽑아오기
	inline MYSQL_ROW FetchRow()
	{
		return mysql_fetch_row(myResult);
	}

	// 한 쿼리에 대한 결과 모두 사용 후 정리
	inline void FreeResult()
	{
		mysql_free_result(myResult);
	}

	inline void* GetConnectionStatus()
	{
		return connection;
	}

	void onError();

private:
	MYSQL conn;
	MYSQL* connection;

	MYSQL_RES* myResult;

	wchar_t mHost[SHORT_LEN];
	wchar_t mUser[MIDDLE_LEN];
	wchar_t mPassword[MIDDLE_LEN];
	wchar_t mDB[MIDDLE_LEN];

	char mHostUTF8[SHORT_LEN];
	char mUserUTF8[MIDDLE_LEN];
	char mPasswordUTF8[MIDDLE_LEN];
	char mDBUTF8[MIDDLE_LEN];

	unsigned short mPort;
	bool mFlag;

	wchar_t mQuery[QUERY_MAX_LEN];
	char mQueryUTF8[QUERY_MAX_LEN];

	wchar_t errorMsg[LONG_LEN];
	char errorMsgUTF8[LONG_LEN];

	ULONGLONG mQueryTime;

	uint64_t connectCnt;
	uint64_t connectFailCnt;
	uint64_t disconnectCnt;
};

#endif