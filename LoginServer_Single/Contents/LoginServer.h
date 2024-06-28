#ifndef __LOGINSERVER__CLASS__
#define __LOGINSERVER__CLASS__

#include "../PCH.h"
#include <variant>

class LoginServer : public NetServer
{
private:
	//--------------------------------------------------------------------------------------
	// Job Info
	//--------------------------------------------------------------------------------------
	enum JobType
	{
		MSG_PACKET,				// 패킷
		REDIS_RES,				// 레디스 결과 이후 로그인 처리
		TIMEOUT					// 타임아웃
	};

	// Job 구조체
	struct LoginJob
	{
		// Session 고유 ID
		uint64_t sessionID;

		// Job Type (새 접속, 패킷 메시지, 접속 해제 등)
		WORD type;

		// 패킷 포인터
		CPacket* packet;
	};

	//// Redis Job 구조체
	//struct RedisJob
	//{
	//	// Session 고유 ID
	//	uint64_t sessionID;

	//	CPacket* packet;

	//	// 비동기 redis 요청 결과를 담은 future 객체
	//	std::future<cpp_redis::reply> redisFuture;
	//};

	// Redis Job 구조체
	struct RedisJob
	{
		uint64_t sessionID;				// Session 고유 ID
		std::string accountNo;
		std::string sessionKey; // 세션 키 포인터

		CPacket* packet;
	};

public:
	LoginServer();
	~LoginServer();

	bool LoginServerStart();
	bool LoginServerStop();

	bool OnConnectionRequest(const wchar_t* IP, unsigned short PORT);
	void OnClientJoin(uint64_t sessionID);
	void OnClientLeave(uint64_t sessionID);
	void OnRecv(uint64_t sessionID, CPacket* packet);
	void OnError(int errorCode, const wchar_t* msg);
	void OnTimeout(uint64_t sessionID);

	//bool AsyncLogin(RedisJob* redisJob);

	//--------------------------------------------------------------------------------------
	// Packet Proc
	//--------------------------------------------------------------------------------------
	void PacketProc(uint64_t sessionID, CPacket* packet);
	void netPacketProc_ReqLogin(uint64_t sessionID, CPacket* packet);
	void netPacketProc_ResLoginRedis(uint64_t sessionID, CPacket* packet);

	friend unsigned __stdcall JobWorkerThread(PVOID param);					// Job 일 처리 스레드
	friend unsigned __stdcall MoniteringThread(void* param);
	friend unsigned __stdcall RedisJobWorkerThread(PVOID param);			// Redis Job 일 처리 스레드

	bool JobWorkerThread_serv();
	bool MoniterThread_serv();
	bool RedisJobWorkerThread_serv();

private:
	Log* loginLog;

	int m_userMAXCnt;									// 최대 player 수
	int m_timeout;

	HANDLE m_moniteringThread;							// Monitering Thread
	HANDLE m_controlThread;

	HANDLE m_moniterEvent;								// Monitering Event
	HANDLE m_runEvent;									// Thread Start Event

	HANDLE m_jobHandle;
	HANDLE m_jobEvent;
	
	HANDLE m_redisJobHandle;
	HANDLE m_redisJobEvent;

	TLSObjectPool<LoginJob> jobPool = TLSObjectPool<LoginJob>(300);

	LockFreeQueue<LoginJob*> loginJobQ = LockFreeQueue<LoginJob*>(1000);

	TLSObjectPool<RedisJob> redisJobPool = TLSObjectPool<RedisJob>(100);

	LockFreeQueue<RedisJob*> redisJobQ = LockFreeQueue<RedisJob*>(1000);

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

	__int64 m_updateTotal;
	__int64 m_updateTPS;

	__int64 m_jobUpdatecnt;													// job 개수
	__int64 m_jobThreadUpdateCnt;											// job thread update 횟수

	__int64 m_redisSetCnt;
	__int64 m_redisSetTPS;

	__int64 m_redisJobEnqueueTPS;
	__int64 m_redisJobThreadUpdateTPS;

	bool startFlag;

private:
	PerformanceMonitor performMoniter;
	MonitoringLanClient lanClient;

	std::wstring m_tempIp;
	std::string m_ip;

	//CRedis_TLS* mRedis_TLS;				// TLS용 Redis Connector
	//DBConnector_TLS* dbConn_TLS;			// TLS용 DBConnector

	CRedis* mRedis;				// Redis Connector
	DBConnector* dbConn;		// DBConnector

	wchar_t mDBName[64];

};




#endif // !__LOGINSERVER__CLASS__
