#include "../PCH.h"
#include "Redis.h"


CRedis::CRedis()
{

}

CRedis::~CRedis()
{

}

// redis 연결
void CRedis::Connect(std::wstring IP, unsigned short port)
{
	std::string IPStr(IP.begin(), IP.end());
	client.connect(IPStr, port);
}

// 동기
bool CRedis::syncSet(const std::string& key, const std::string& value, int timeout)
{
	if (timeout > 0)
	{
		client.setex(key, timeout, value);
		client.sync_commit();
	}
	else
	{
		client.set(key, value);
		client.sync_commit();
	}
	return true;
}

cpp_redis::reply CRedis::syncGet(const std::string& key)
{
	std::future<cpp_redis::reply> get_reply = client.get(key);

	client.sync_commit();

	return get_reply.get();
}

// 비동기 set 호출
void CRedis::asyncSet(const std::string& key, const std::string& value, int timeout, std::function<void(const cpp_redis::reply&)> callback)
{
	if (timeout > 0)
	{
		client.setex(key, timeout, value, [callback](const cpp_redis::reply& reply)
			{
				callback(reply);
			}).commit();
	}
	else
	{
		client.set(key, value, [callback](const cpp_redis::reply& reply) mutable
			{
				callback(reply);
			}).commit();
	}

}

CRedis_TLS::CRedis_TLS(std::wstring IP, unsigned short port)
{
	mIP = IP;
	mPort = port;

	tlsIndex = TlsAlloc();
	if (tlsIndex == TLS_OUT_OF_INDEXES)
	{
		wprintf(L"CRedis_TLS : TLS_OUT_OF_INDEXES\n");
		CRASH();
	}
}

CRedis_TLS::~CRedis_TLS()
{
	CRedis* redisObj;

	while (redisStack.Pop(&redisObj))
	{
		delete redisObj;
	}

	TlsFree(tlsIndex);
}

bool CRedis_TLS::syncSet(const std::string& key, const std::string& value, int timeout)
{
	CRedis* redisObj = GetCRedisObj();

	return redisObj->syncSet(key, value, timeout);
}

cpp_redis::reply CRedis_TLS::syncGet(const std::string& key)
{
	CRedis* redisObj = GetCRedisObj();

	return redisObj->syncGet(key);
}

CRedis* CRedis_TLS::GetCRedisObj()
{
	CRedis* redis = (CRedis*)TlsGetValue(tlsIndex);
	if (redis == nullptr)
	{
		redis = new CRedis;

		redisStack.Push(redis);
		TlsSetValue(tlsIndex, redis);

		redis->Connect(mIP, mPort);
	}


	return redis;
}







