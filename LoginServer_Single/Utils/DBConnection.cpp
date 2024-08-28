#include "../PCH.h"

DBConnector::DBConnector(const wchar_t* host, const wchar_t* user, const wchar_t* password, const wchar_t* db, unsigned short port, bool sslOff) : connection(NULL), mFlag(0), mQueryTime(0)
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
	//wprintf(L"DB Closed...\n");
}

bool DBConnector::StartTransaction()
{
	if (mysql_query(connection, "start transaction;"))
	{
		printf("Query Error : %s\n", mysql_error(connection));
		return false;
	}

	return true;
}

bool DBConnector::Commit()
{
	if (mysql_query(connection, "commit;"))
	{
		printf("Query Error : %s\n", mysql_error(connection));
		return false;
	}

	return true;
}

// 매개변수화된 쿼리 실행 - 벡터 버전
bool DBConnector::ExecuteQuery(const std::wstring& query, std::vector<MYSQL_BIND>& bindParams, std::function<bool(MYSQL_STMT*, Log* dbLog)> resultHandler)
{
	MYSQL_STMT* stmt = mysql_stmt_init(connection);
	if (!stmt)
	{
		dbLog->logger(dfLOG_LEVEL_ERROR, __LINE__, L"[DB] Coult not initialize statement");
		return false;
	}

	std::string utf8Query(query.begin(), query.end());
	if (mysql_stmt_prepare(stmt, utf8Query.c_str(), utf8Query.size()))
	{
		std::cout << mysql_stmt_error(stmt) << std::endl;
		dbLog->logger(dfLOG_LEVEL_ERROR, __LINE__, L"[DB] Statement preparation failed : %s", mysql_stmt_error(stmt));
		mysql_stmt_close(stmt);
		return false;
	}

	if (!bindParams.empty() && mysql_stmt_bind_param(stmt, bindParams.data()))
	{
		dbLog->logger(dfLOG_LEVEL_ERROR, __LINE__, L"[DB] Parameter binding failed : %s", mysql_stmt_error(stmt));
		mysql_stmt_close(stmt);
		return false;
	}

	if (mysql_stmt_execute(stmt))
	{
		std::cout << mysql_stmt_error(stmt) << std::endl;
		dbLog->logger(dfLOG_LEVEL_ERROR, __LINE__, L"[DB] Query execution failed : %s", mysql_stmt_error(stmt));
		mysql_stmt_close(stmt);
		return false;
	}

	bool isSuccessful = true;

	if (resultHandler)
		isSuccessful = resultHandler(stmt, dbLog);

	mysql_stmt_close(stmt);

	return isSuccessful;
}

int DBConnector::Query(const wchar_t* strFormat, ...)
{
	if (QUERY_MAX_LEN < wcslen(strFormat))
	{
		//DBLog->logger(dfLOG_LEVEL_ERROR, __LINE__, L"Query Length is Too Long!");
		wprintf(L"Query Length is Too Long!");
		return -1;
	}
	
	memset(mQuery, 0, sizeof(wchar_t) * QUERY_MAX_LEN);
	memset(mQueryUTF8, 0, sizeof(char) * QUERY_MAX_LEN);

	HRESULT hResult;
	va_list vList;
	int queryError;

	va_start(vList, strFormat);
	hResult = StringCchPrintf(mQuery, QUERY_MAX_LEN, strFormat, vList);
	va_end(vList);

	if (FAILED(hResult))
		return -1;

	// wchar_t -> char
	//WideCharToMultiByte(CP_UTF8, 0, mQuery, lstrlenW(mQuery), mQueryUTF8, sizeof(mQuery), NULL, NULL);
	WideCharToMultiByte(CP_UTF8, 0, mQuery, -1, mQueryUTF8, QUERY_MAX_LEN, NULL, NULL);

	// 쿼리 날린 시간
	mQueryTime = GetTickCount64();

	int queryResult = mysql_query(connection, mQueryUTF8);

	// 쿼리 실패
	if (queryResult != 0)
	{
		onError();

		// 재연결
		Close();
		Open();

		return -1;
	}

	ULONGLONG time = GetTickCount64();

	if (time - mQueryTime > QUERY_MAX_TIME)
	{
		//DBLog->logger(dfLOG_LEVEL_ERROR, __LINE__, L"Too much Time has passed [%IId]", time);
		wprintf(L"Too much Time has passed [%IId]", time);
	}
	mQueryTime = time;

	// 결과 셋 저장
	myResult = mysql_store_result(connection);

	// 쿼리 성공 시, 결과 row 갯수 반환
	return mysql_num_rows(myResult);
}

bool DBConnector::QuerySave(const wchar_t* strFormat, ...)
{
	if (QUERY_MAX_LEN < wcslen(strFormat))
	{
		//DBLog->logger(dfLOG_LEVEL_ERROR, __LINE__, L"Query Length is Too Long!");
		wprintf(L"Query Length is Too Long!");
		return false;
	}

	memset(mQuery, 0, sizeof(wchar_t) * QUERY_MAX_LEN);
	memset(mQueryUTF8, 0, sizeof(char) * QUERY_MAX_LEN);

	HRESULT hResult;
	va_list vList;
	int queryError;

	va_start(vList, strFormat);
	hResult = StringCchPrintf(mQuery, QUERY_MAX_LEN, strFormat, vList);
	va_end(vList);

	if (FAILED(hResult))
		return false;

	// wchar_t -> char
	//WideCharToMultiByte(CP_UTF8, 0, mQuery, lstrlenW(mQuery), mQueryUTF8, sizeof(mQuery), NULL, NULL);
	WideCharToMultiByte(CP_UTF8, 0, mQuery, -1, mQueryUTF8, QUERY_MAX_LEN, NULL, NULL);

	// 쿼리 날린 시간
	mQueryTime = GetTickCount64();

	int queryResult = mysql_query(connection, mQueryUTF8);

	if (queryResult != 0)
	{
		onError();

		Close();
		Open();

		return false;
	}

	ULONGLONG time = GetTickCount64();

	if (time - mQueryTime > QUERY_MAX_TIME)
	{
		//DBLog->logger(dfLOG_LEVEL_ERROR, __LINE__, L"Too much Time has passed [%IId]", time);
		wprintf(L"Too much Time has passed [%IId]", time);
	}
	mQueryTime = time;

	FreeResult();

	return true;
}



bool DBConnector::AllQuery(std::string query)
{
	std::string requestSQL = "start transaction;";
	requestSQL += query;
	requestSQL += " commit;";
	
	if (mysql_real_query(connection, requestSQL.c_str(), requestSQL.length()) != 0)
	{
		printf("Query Error : %s\n", mysql_error(connection));
		return false;
	}


	do
	{
		MYSQL_RES* result = mysql_store_result(connection);
		if (result != NULL)
			FreeResult();
	} while (!mysql_next_result(connection));

	return true;
}





void DBConnector::onError()
{	
	strcpy_s(errorMsgUTF8, mysql_error(connection));

	// char -> wchar_t
	int result = MultiByteToWideChar(CP_UTF8, 0, errorMsgUTF8, strlen(errorMsgUTF8), errorMsg, sizeof(errorMsg));
	if (result < sizeof(errorMsg))
		errorMsg[result] = L'\0';

	//DBLog->logger(dfLOG_LEVEL_ERROR, __LINE__, errorMsg);
}