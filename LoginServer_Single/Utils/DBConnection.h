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
	// MySQL 데이터 타입 추론
	template<typename T>
	enum enum_field_types GetMysqlType();


	// MySQL 데이터 타입 추론 특수화
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

	// 필요시, 기타 특수화 추가...

private:
	void BindParam(std::vector<MYSQL_BIND>& bindParams, std::wstring& value)
	{
		MYSQL_BIND bind;
		memset(&bind, 0, sizeof(MYSQL_BIND));

		// std::wstring을 UTF-8로 변환하기 위한 충분한 버퍼 크기 계산
		int utf8Length = WideCharToMultiByte(CP_UTF8, 0, value.c_str(), -1, NULL, 0, NULL, NULL);
		std::string utf8Value(utf8Length, 0);

		// 변환 수행
		WideCharToMultiByte(CP_UTF8, 0, value.c_str(), -1, &utf8Value[0], utf8Length, NULL, NULL);

		bind.buffer_type = MYSQL_TYPE_STRING;
		bind.buffer = (char*)utf8Value.c_str();
		bind.buffer_length = utf8Value.length();

		bindParams.push_back(bind);
	}

	// std::string에 대한 명시적 오버로딩
	void BindParam(std::vector<MYSQL_BIND>& bindParams, std::string& value)
	{
		MYSQL_BIND bind;
		memset(&bind, 0, sizeof(MYSQL_BIND));

		bind.buffer_type = MYSQL_TYPE_STRING;
		bind.buffer = (char*)value.c_str();
		bind.buffer_length = value.length();

		bindParams.push_back(bind);
	}

	// `char*`와 배열 모두를 처리할 수 있는 바인딩 함수
	void BindParam(std::vector<MYSQL_BIND>& bindParams, const char* value)
	{
		MYSQL_BIND bind;
		memset(&bind, 0, sizeof(MYSQL_BIND));

		bind.buffer_type = MYSQL_TYPE_STRING;
		bind.buffer = (char*)value;
		bind.buffer_length = strlen(value);  // 문자열 길이 계산

		bindParams.push_back(bind);
	}

	// `char*`뿐만 아니라 `char[]`도 처리할 수 있는 특수화
	template<size_t N>
	void BindParam(std::vector<MYSQL_BIND>& bindParams, char(&value)[N])
	{
		BindParam(bindParams, static_cast<const char*>(value));
	}

	// 매개변수 바인딩을 처리하는 함수
	template<typename T>
	void BindParams(std::vector<MYSQL_BIND>& bindParams, T& value) {
		BindParam(bindParams, value);
	}

	// 템플릿 함수로 매개변수 바인딩
	template<typename T, typename... Args>
	void BindParams(std::vector<MYSQL_BIND>& bindParams, T& first, Args... rest)
	{
		BindParam(bindParams, first);
		BindParams(bindParams, rest...);
	}

	void BindParams(std::vector<MYSQL_BIND>& bindParams) {} // 재귀호출 종료 조건

	// 매개변수 하나를 바인딩하는 함수 (특수화 필요)
	template<typename T>
	void BindParam(std::vector<MYSQL_BIND>& bindParams, T& value) 
	{
		MYSQL_BIND bind;
		memset(&bind, 0, sizeof(MYSQL_BIND));

		bind.buffer_type = GetMysqlType<T>();
		bind.buffer = (char*)&value;

		bindParams.push_back(bind);
	}

	// 결과 패치 함수
	template<typename T, typename... Args>
	int FetchResultImpl(MYSQL_STMT* stmt, T& firstArg, Args&... restArgs)
	{
		MYSQL_BIND resultBind[sizeof...(Args) + 1];
		memset(resultBind, 0, sizeof(resultBind));

		// 기본값 설정
		size_t i = 0;
		auto setupBind = [&](auto& arg, MYSQL_BIND& bind)
		{
			bind.buffer_type = GetMysqlType<decltype(arg)>();
			bind.buffer = reinterpret_cast<char*>(&arg);
			bind.is_null = nullptr;
			bind.length = nullptr;

			if (bind.buffer_type == MYSQL_TYPE_STRING)
			{
				// 문자열 버퍼의 크기 설정
				bind.buffer_length = sizeof(arg); 

				// 길이 포인터 설정
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
	// DB 연결
	bool Open();

	// DB 연결 끊기
	void Close();

	// 매개변수화된 쿼리 실행 - 벡터 버전
	bool ExecuteQuery(const std::wstring& query, std::vector<MYSQL_BIND>& bindParams, std::function<bool(MYSQL_STMT*, Log* dbLog)> resultHandler);

	MYSQL_STMT* ExecuteQuery(const std::wstring& query, std::vector<MYSQL_BIND>& bindParams);

	// 템플릿 함수로 매개변수를 바인딩 - 가변 인자 받음
	template<typename... Args>
	bool ExecuteQuery(const std::wstring& query, std::function<bool(MYSQL_STMT*, Log* dbLog)> resultHandler, Args... args) 
	{
		std::vector<MYSQL_BIND> bindParams;
		BindParams(bindParams, args...);
		return ExecuteQuery(query, bindParams, resultHandler);
	}

	// 템플릿 함수로 매개변수를 바인딩 - 가변 인자 받음, 결과 후처리 핸들러 없는 버전
	template<typename... Args>
	MYSQL_STMT* ExecuteSelectQuery(const std::wstring& query, Args... args)
	{
		std::vector<MYSQL_BIND> bindParams;
		BindParams(bindParams, args...);
		return ExecuteQuery(query, bindParams);
	}

	// 결과 패치 함수
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