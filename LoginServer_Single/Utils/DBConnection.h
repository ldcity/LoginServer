#ifndef __DBCONNECTION_CLASS__
#define __DBCONNECTION_CLASS__

#pragma comment(lib, "libmysql.lib")

#include <winsock2.h>
#include <Windows.h>

#include <functional>
#include <string>

#include "LOG.h"
#include "Define.h"
#include "../Library/TLSFreeList.h"

#include "../mysql/include/mysql.h"

class DBConnector
{
public:
	DBConnector(const wchar_t* host, const wchar_t* user, const wchar_t* password, const wchar_t* db, unsigned short port, bool sslOff);
	~DBConnector();

public:
	// MySQL ������ Ÿ�� �߷�
	template<typename T>
	enum enum_field_types GetMysqlType();


	// MySQL ������ Ÿ�� �߷� Ư��ȭ
	template<>
	enum enum_field_types GetMysqlType<int>()
	{
		return MYSQL_TYPE_LONG;
	}

	template<>
	enum enum_field_types GetMysqlType<int&>()
	{
		return MYSQL_TYPE_LONG;
	}

	template<>
	enum enum_field_types GetMysqlType<int64_t*>()
	{
		return MYSQL_TYPE_LONGLONG;
	}

	template<>
	enum enum_field_types GetMysqlType<int64_t>()
	{
		return MYSQL_TYPE_LONGLONG;
	}

	template<>
	enum enum_field_types GetMysqlType<std::string>()
	{
		return MYSQL_TYPE_STRING;
	}

	template<>
	enum enum_field_types GetMysqlType<std::wstring>()
	{
		return MYSQL_TYPE_STRING;
	}

	template<>
	enum enum_field_types GetMysqlType<const char*>()
	{
		return MYSQL_TYPE_STRING;
	}

	template<>
	enum enum_field_types GetMysqlType<char*>()
	{
		return MYSQL_TYPE_STRING;
	}

	template<>
	enum enum_field_types GetMysqlType<char(&)[IDMAXLEN]>()
	{
		return MYSQL_TYPE_STRING;
	}

	template<>
	enum enum_field_types GetMysqlType<char[]>()
	{
		return MYSQL_TYPE_STRING;
	}

	// �ʿ��, ��Ÿ Ư��ȭ �߰�...

private:
	void BindParam(std::vector<MYSQL_BIND>& bindParams, std::wstring& value)
	{
		MYSQL_BIND bind;
		memset(&bind, 0, sizeof(MYSQL_BIND));

		// std::wstring�� UTF-8�� ��ȯ�ϱ� ���� ����� ���� ũ�� ���
		int utf8Length = WideCharToMultiByte(CP_UTF8, 0, value.c_str(), -1, NULL, 0, NULL, NULL);
		std::string utf8Value(utf8Length, 0);

		// ��ȯ ����
		WideCharToMultiByte(CP_UTF8, 0, value.c_str(), -1, &utf8Value[0], utf8Length, NULL, NULL);

		bind.buffer_type = MYSQL_TYPE_STRING;
		bind.buffer = (char*)utf8Value.c_str();
		bind.buffer_length = utf8Value.length();

		bindParams.push_back(bind);
	}

	// std::string�� ���� ����� �����ε�
	void BindParam(std::vector<MYSQL_BIND>& bindParams, std::string& value)
	{
		MYSQL_BIND bind;
		memset(&bind, 0, sizeof(MYSQL_BIND));

		bind.buffer_type = MYSQL_TYPE_STRING;
		bind.buffer = (char*)value.c_str();
		bind.buffer_length = value.length();

		bindParams.push_back(bind);
	}

	// `char*`�� �迭 ��θ� ó���� �� �ִ� ���ε� �Լ�
	void BindParam(std::vector<MYSQL_BIND>& bindParams, const char* value)
	{
		MYSQL_BIND bind;
		memset(&bind, 0, sizeof(MYSQL_BIND));

		bind.buffer_type = MYSQL_TYPE_STRING;
		bind.buffer = (char*)value;
		bind.buffer_length = strlen(value);  // ���ڿ� ���� ���

		bindParams.push_back(bind);
	}

	// `char*`�Ӹ� �ƴ϶� `char[]`�� ó���� �� �ִ� Ư��ȭ
	template<size_t N>
	void BindParam(std::vector<MYSQL_BIND>& bindParams, char(&value)[N])
	{
		BindParam(bindParams, static_cast<const char*>(value));
	}

	// �Ű����� ���ε��� ó���ϴ� �Լ�
	template<typename T>
	void BindParams(std::vector<MYSQL_BIND>& bindParams, T& value) {
		BindParam(bindParams, value);
	}

	// ���ø� �Լ��� �Ű����� ���ε�
	template<typename T, typename... Args>
	void BindParams(std::vector<MYSQL_BIND>& bindParams, T& first, Args... rest)
	{
		BindParam(bindParams, first);
		BindParams(bindParams, rest...);
	}

	void BindParams(std::vector<MYSQL_BIND>& bindParams) {} // ���ȣ�� ���� ����

	// �Ű����� �ϳ��� ���ε��ϴ� �Լ� (Ư��ȭ �ʿ�)
	template<typename T>
	void BindParam(std::vector<MYSQL_BIND>& bindParams, T& value) 
	{
		MYSQL_BIND bind;
		memset(&bind, 0, sizeof(MYSQL_BIND));

		bind.buffer_type = GetMysqlType<T>();
		bind.buffer = (char*)&value;

		bindParams.push_back(bind);
	}

	// ��� ��ġ �Լ�
	template<typename T, typename... Args>
	int FetchResultImpl(MYSQL_STMT* stmt, T& firstArg, Args&... restArgs)
	{
		MYSQL_BIND resultBind[sizeof...(Args) + 1];
		memset(resultBind, 0, sizeof(resultBind));

		// �⺻�� ����
		size_t i = 0;
		auto setupBind = [&](auto& arg, MYSQL_BIND& bind)
		{
			bind.buffer_type = GetMysqlType<decltype(arg)>();
			bind.buffer = reinterpret_cast<char*>(&arg);
			bind.is_null = nullptr;
			bind.length = nullptr;

			if (bind.buffer_type == MYSQL_TYPE_STRING)
			{
				// ���ڿ� ������ ũ�� ����
				bind.buffer_length = sizeof(arg); 

				// ���� ������ ����
				bind.length = &bind.buffer_length; 
			}
		};

		setupBind(firstArg, resultBind[i++]);
		(..., setupBind(restArgs, resultBind[i++]));

		if (mysql_stmt_bind_result(stmt, resultBind))
		{
			return -1;
		}

		int stmtResult = mysql_stmt_fetch(stmt);

		//mysql_stmt_close(stmt);
		//stmtPool.Free(stmt);

		return stmtResult;
	}

public:
	// DB ����
	bool Open();

	// DB ���� ����
	void Close();

	// �Ű�����ȭ�� ���� ���� - ���� ����
	bool ExecuteQuery(const std::wstring& query, std::vector<MYSQL_BIND>& bindParams, std::function<bool(MYSQL_STMT*, Log* dbLog)> resultHandler);

	MYSQL_STMT* ExecuteQuery(const std::wstring& query, std::vector<MYSQL_BIND>& bindParams);

	// ���ø� �Լ��� �Ű������� ���ε� - ���� ���� ����
	template<typename... Args>
	bool ExecuteQuery(const std::wstring& query, std::function<bool(MYSQL_STMT*, Log* dbLog)> resultHandler, Args... args) 
	{
		std::vector<MYSQL_BIND> bindParams;
		BindParams(bindParams, args...);
		return ExecuteQuery(query, bindParams, resultHandler);
	}

	// ���ø� �Լ��� �Ű������� ���ε� - ���� ���� ����, ��� ��ó�� �ڵ鷯 ���� ����
	template<typename... Args>
	MYSQL_STMT* ExecuteSelectQuery(const std::wstring& query, Args... args)
	{
		std::vector<MYSQL_BIND> bindParams;
		BindParams(bindParams, args...);
		return ExecuteQuery(query, bindParams);
	}

	// ��� ��ġ �Լ�
	template<typename... T>
	bool FetchResult(MYSQL_STMT* stmt, T&... args)
	{
		return FetchResultImpl(stmt, args...);
	}

private:
	MYSQL conn;
	MYSQL* connection;
	
	MYSQL_STMT* mStmt;

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

private:
	Log* dbLog;
};

#endif