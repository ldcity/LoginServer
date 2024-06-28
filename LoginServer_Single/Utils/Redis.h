#pragma once

#include "../PCH.h"

class CRedis
{
public:
	CRedis();
	~CRedis();

	void Connect(std::wstring IP, unsigned short port);

	// ����
	bool syncSet(const std::string& key, const std::string& value, int timeout = 0);
	cpp_redis::reply syncGet(const std::string& key);

	// �񵿱�
	void asyncSet(const std::string& key, const std::string& value, int timeout, std::function<void(const cpp_redis::reply&)> callback);

private:
	cpp_redis::client client;
};
