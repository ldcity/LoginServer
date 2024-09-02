#ifndef __LOGINSERVER__CLASS__
#define __LOGINSERVER__CLASS__

#include "../PCH.h"

class LoginServer : public NetServer
{
public:
	LoginServer();
	~LoginServer();

	bool LoginServerStart();
	bool LoginServerStop();

	bool OnConnectionRequest(const wchar_t* IP, unsigned short PORT);
	void OnClientJoin(uint64_t sessionID);
	void OnClientLeave(uint64_t sessionID);
	void OnRecv(uint64_t sessionID, CPacket* packet);
	void OnJob(uint64_t sessionID, CPacket* packet);
	void OnError(int errorCode, const wchar_t* msg);
	void OnTimeout(uint64_t sessionID);

	//--------------------------------------------------------------------------------------
	// Packet Proc
	//--------------------------------------------------------------------------------------
	void PacketProc(uint64_t sessionID, CPacket* packet, WORD type);
	void NetPacketProc_ReqLogin(uint64_t sessionID, CPacket* packet);

	friend unsigned __stdcall MoniteringThread(void* param);
	
	bool MoniterThread_serv();

private:
	Log* loginLog;

	int mUserMAXCnt;									// 최대 player 수
	int mTimeout;

	HANDLE mMoniteringThread;							// Monitering Thread
	HANDLE mControlThread;

	HANDLE mMoniterEvent;								// Monitering Event
	HANDLE mRunEvent;									// Thread Start Event

private:
	wchar_t chatIP[16];
	unsigned short chatPort;

	// 모니터링 관련 변수들
private:
	__int64 m_loginCount;
	__int64 m_loginTPS;

	__int64 m_loginSuccessCount;
	__int64 m_loginSuccessTPS;

	__int64 m_loginFailCount;
	__int64 m_loginFailTPS;

	__int64 m_timeoutTotalCnt;
	__int64 m_timeoutCntTPS;

	__int64 m_dbQueryTotal;
	__int64 m_dbQueryTPS;

	__int64 m_updateTPS;

	__int64 m_loginResJobUpdateTPS;

	__int64 m_redisJobThreadUpdateTPS;
	
	bool startFlag;

private:
	PerformanceMonitor performMoniter;
	MonitoringLanClient lanClient;

	std::wstring m_tempIp;
	std::string m_ip;

	static DWORD _DBTlsIdx;
	LockFreeStack<DBConnector*> tlsDBObjects = LockFreeStack<DBConnector*>(5);		// tls db 객체를 정리하기 위해 필요 

	static DWORD _RedisTlsIdx;
	LockFreeStack<CRedis*> tlsRedisObjects = LockFreeStack<CRedis*>(5);		// tls db 객체를 정리하기 위해 필요 

	// DB 관련 변수
	int dbPort;
	wchar_t host[16];
	wchar_t user[64];
	wchar_t password[64];
	wchar_t dbName[64];

	wchar_t redisIP[20];
	int redisPort;
};

#endif // !__LOGINSERVER__CLASS__
