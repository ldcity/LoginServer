#include "../PCH.h"


DBConnector::DBConnector(const wchar_t* host, const wchar_t* user, const wchar_t* password, const wchar_t* db, unsigned short port, bool sslOff) : connection(NULL), mFlag(0)
{
	// �ʱ�ȭ
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
	// SSL ��带 ��Ȱ��ȭ
	// ���� ������ ������ �ش� �ɼ� ����
	// SSL�� �����͸� ��ȣȭ�ϰ� ��ȣȭ�ϴ� ������ �߰��ǹǷ� �ణ�� ���� ������尡 �߻�
	// -> �� ����� ��Ȱ��ȭ�Ͽ� ���� ����
	// => ���� ��Ʈ��ũ�� �ִ� ���� �� ����̳� ���� �� �׽�Ʈ ȯ�濡�� SSL�� ��Ȱ��ȭ (��Ʈ��ũ ȯ���� �����ϴٰ� Ȯ��) 
	if (mFlag)
	{
		mysql_options(&conn, MYSQL_OPT_SSL_MODE, &mFlag);
	}

	WideCharToMultiByte(CP_UTF8, 0, mHost, -1, mHostUTF8, SHORT_LEN, NULL, NULL);
	WideCharToMultiByte(CP_UTF8, 0, mUser, -1, mUserUTF8, MIDDLE_LEN, NULL, NULL);
	WideCharToMultiByte(CP_UTF8, 0, mPassword, -1, mPasswordUTF8, MIDDLE_LEN, NULL, NULL);
	WideCharToMultiByte(CP_UTF8, 0, mDB, -1, mDBUTF8, MIDDLE_LEN, NULL, NULL);

	// DB ����
	connection = mysql_real_connect(&conn, mHostUTF8, mUserUTF8, mPasswordUTF8, mDBUTF8, mPort, (char*)NULL, 0);
	if (connection == NULL)
	{
		// ���� ���� ��, ���� Ƚ�� �翬�� �õ�
		int tryCnt = 0;

		while (NULL == connection)
		{
			if (tryCnt > DBCONNECT_TRY)
			{
				// ���� ���� ����!

				return false;
			}

			// �翬�� �õ�
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
	// DB ���� ����
	mysql_close(connection);
}

// �Ű�����ȭ�� ���� ���� - ���� ����
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

	// ���� ���� ��, �Ű������� �޾Ҷ� �ڵ鷯 �Լ� ����
	if (resultHandler)
		isSuccessful = resultHandler(mStmt, dbLog);

	if (isSuccessful)
		mysql_stmt_close(mStmt);


	return isSuccessful;
}

// �Ű�����ȭ�� ���� ���� - ���� ����
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