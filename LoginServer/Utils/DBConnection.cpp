#include "../PCH.h"


DBConnector::DBConnector(const wchar_t* host, const wchar_t* user, const wchar_t* password, const wchar_t* db, unsigned short port, bool sslOff) : connection(NULL), mFlag(0)
{
	// 초기화
	mysql_init(&conn);

	wmemcpy_s(mHost, SHORT_LEN, host, wcslen(host));
	wmemcpy_s(mUser, MIDDLE_LEN, user, wcslen(user));
	wmemcpy_s(mPassword, MIDDLE_LEN, password, wcslen(password));
	wmemcpy_s(mDB, MIDDLE_LEN, db, wcslen(db));
	mPort = port;

	if (sslOff)
		mFlag = SSL_MODE_DISABLED;

	dbLog = new Log(L"DBLog.txt");
}


DBConnector::~DBConnector()
{
	delete dbLog;
}

bool DBConnector::Open()
{
	// SSL 모드를 비활성화
	// 성능 개선의 이유로 해당 옵션 설정
	// SSL은 데이터를 암호화하고 복호화하는 과정이 추가되므로 약간의 성능 오버헤드가 발생
	// -> 이 기능을 비활성화하여 성능 개선
	// => 내부 네트워크에 있는 서버 간 통신이나 개발 및 테스트 환경에서 SSL을 비활성화 (네트워크 환경이 안전하다고 확정) 
	if (mFlag)
	{
		mysql_options(&conn, MYSQL_OPT_SSL_MODE, &mFlag);
	}

	WideCharToMultiByte(CP_UTF8, 0, mHost, -1, mHostUTF8, SHORT_LEN, NULL, NULL);
	WideCharToMultiByte(CP_UTF8, 0, mUser, -1, mUserUTF8, MIDDLE_LEN, NULL, NULL);
	WideCharToMultiByte(CP_UTF8, 0, mPassword, -1, mPasswordUTF8, MIDDLE_LEN, NULL, NULL);
	WideCharToMultiByte(CP_UTF8, 0, mDB, -1, mDBUTF8, MIDDLE_LEN, NULL, NULL);

	// DB 연결
	connection = mysql_real_connect(&conn, mHostUTF8, mUserUTF8, mPasswordUTF8, mDBUTF8, mPort, (char*)NULL, 0);
	if (connection == NULL)
	{
		// 연결 실패 시, 일정 횟수 재연결 시도
		int tryCnt = 0;

		while (NULL == connection)
		{
			if (tryCnt > DBCONNECT_TRY)
			{
				// 최종 연결 실패!

				return false;
			}

			// 재연결 시도
			connection = mysql_real_connect(&conn, mHostUTF8, mUserUTF8, mPasswordUTF8, mDBUTF8, mPort, (char*)NULL, 0);

			tryCnt++;
			Sleep(500);
		}

		return false;
	}

	mysql_set_character_set(connection, "utf8mb4");


	return true;
}

void DBConnector::Close()
{
	// DB 연결 끊기
	mysql_close(connection);
}

// 매개변수화된 쿼리 실행 - 벡터 버전
bool DBConnector::ExecuteQuery(const std::wstring& query, std::vector<MYSQL_BIND>& bindParams, std::function<bool(MYSQL_STMT*, Log* dbLog)> resultHandler)
{
	mStmt = mysql_stmt_init(connection);

	if (!mStmt)
	{
		dbLog->logger(dfLOG_LEVEL_ERROR, __LINE__, L"[DB] Coult not initialize statement");
		return false;
	}

	std::string utf8Query(query.begin(), query.end());
	if (mysql_stmt_prepare(mStmt, utf8Query.c_str(), utf8Query.size()))
	{
		dbLog->logger(dfLOG_LEVEL_ERROR, __LINE__, L"[DB] Statement preparation failed : %s", mysql_stmt_error(mStmt));
		mysql_stmt_close(mStmt);
		return false;
	}

	if (!bindParams.empty() && mysql_stmt_bind_param(mStmt, bindParams.data()))
	{
		dbLog->logger(dfLOG_LEVEL_ERROR, __LINE__, L"[DB] Parameter binding failed : %s", mysql_stmt_error(mStmt));
		mysql_stmt_close(mStmt);
		return false;
	}

	if (mysql_stmt_execute(mStmt))
	{
		dbLog->logger(dfLOG_LEVEL_ERROR, __LINE__, L"[DB] Query execution failed : %s", mysql_stmt_error(mStmt));
		mysql_stmt_close(mStmt);
		return false;
	}

	bool isSuccessful = true;

	// 쿼리 성공 후, 매개변수로 받았떤 핸들러 함수 수행
	if (resultHandler)
		isSuccessful = resultHandler(mStmt, dbLog);

	if (isSuccessful)
		mysql_stmt_close(mStmt);


	return isSuccessful;
}

// 매개변수화된 쿼리 실행 - 벡터 버전
MYSQL_STMT* DBConnector::ExecuteQuery(const std::wstring& query, std::vector<MYSQL_BIND>& bindParams)
{
	mStmt = mysql_stmt_init(connection);

	if (!mStmt)
	{
		dbLog->logger(dfLOG_LEVEL_ERROR, __LINE__, L"[DB] Coult not initialize statement");
		//stmtPool.Free(stmt);
		return nullptr;
	}

	std::string utf8Query(query.begin(), query.end());
	if (mysql_stmt_prepare(mStmt, utf8Query.c_str(), utf8Query.size()))
	{
		dbLog->logger(dfLOG_LEVEL_ERROR, __LINE__, L"[DB] Statement preparation failed : %s", mysql_stmt_error(mStmt));
		mysql_stmt_close(mStmt);
		//stmtPool.Free(stmt);
		return nullptr;
	}

	if (!bindParams.empty() && mysql_stmt_bind_param(mStmt, bindParams.data()))
	{
		dbLog->logger(dfLOG_LEVEL_ERROR, __LINE__, L"[DB] Parameter binding failed : %s", mysql_stmt_error(mStmt));
		mysql_stmt_close(mStmt);
		//stmtPool.Free(stmt);
		return nullptr;
	}

	if (mysql_stmt_execute(mStmt))
	{
		dbLog->logger(dfLOG_LEVEL_ERROR, __LINE__, L"[DB] Query execution failed : %s", mysql_stmt_error(mStmt));
		mysql_stmt_close(mStmt);
		//stmtPool.Free(stmt);
		return nullptr;
	}

	return mStmt;
}