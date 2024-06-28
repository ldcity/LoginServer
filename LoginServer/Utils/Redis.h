#pragma once

#include "../PCH.h"

class CRedis
{
public:
	CRedis();
	~CRedis();

	void Connect(std::wstring IP, unsigned short port);

	// 동기
	bool syncSet(const std::string& key, const std::string& value, int timeout = 0);
	cpp_redis::reply syncGet(const std::string& key);

	// 비동기
	void asyncSet(const std::string& key, const std::string& value, int timeout, std::function<void(const cpp_redis::reply&)> callback);

private:
	cpp_redis::client client;
};


class CRedis_TLS : public CRedis
{
public:
	CRedis_TLS(std::wstring IP, unsigned short port);
	~CRedis_TLS();

	bool syncSet(const std::string& key, const std::string& value, int timeout = 0);
	cpp_redis::reply syncGet(const std::string& key);

	CRedis* GetCRedisObj();

private:
	DWORD tlsIndex;

	LockFreeStack<CRedis*> redisStack;

	std::wstring mIP;
	unsigned short mPort;
};
