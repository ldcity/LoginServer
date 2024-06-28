#ifndef __LOGINSERVER__CLASS__
#define __LOGINSERVER__CLASS__

#include "../PCH.h"

class LoginServer : public NetServer
{
private:
	//// Redis Job ����ü
	//struct RedisJob
	//{
	//	// Session ���� ID
	//	uint64_t sessionID;

	//	CPacket* packet;

	//	// �񵿱� redis ��û ����� ���� future ��ü
	//	std::future<cpp_redis::reply> redisFuture;
	//};

	// Redis Job ����ü
	struct RedisJob
	{
		uint64_t sessionID;				// Session ���� ID
		std::string accountNo;
		std::string sessionKey; // ���� Ű ������

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
	void OnJob(uint64_t sessionID, CPacket* packet);
	void OnError(int errorCode, const wchar_t* msg);
	void OnTimeout(uint64_t sessionID);

	//bool AsyncLogin(RedisJob* redisJob);

	//--------------------------------------------------------------------------------------
	// Packet Proc
	//--------------------------------------------------------------------------------------
	void PacketProc(uint64_t sessionID, CPacket* packet, WORD type);
	void netPacketProc_ReqLogin(uint64_t sessionID, CPacket* packet);
	void netPacketProc_ResLoginRedis(uint64_t sessionID, CPacket* packet);

	friend unsigned __stdcall MoniteringThread(void* param);
	friend unsigned __stdcall RedisJobWorkerThread(PVOID param);			// Redis Job �� ó�� ������

	bool MoniterThread_serv();
	bool RedisJobWorkerThread_serv();

private:
	Log* loginLog;

	int m_userMAXCnt;									// �ִ� player ��
	int m_timeout;

	HANDLE m_moniteringThread;							// Monitering Thread
	HANDLE m_controlThread;

	HANDLE m_moniterEvent;								// Monitering Event
	HANDLE m_runEvent;									// Thread Start Event

	HANDLE m_redisJobHandle;
	HANDLE m_redisJobEvent;

	TLSObjectPool<RedisJob> redisJobPool = TLSObjectPool<RedisJob>(50);

	LockFreeQueue<RedisJob*> redisJobQ = LockFreeQueue<RedisJob*>(10000);

private:
	wchar_t chatIP[16];
	unsigned short chatPort;

	// ����͸� ���� ������
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

	__int64 m_redisSetCnt;
	__int64 m_redisSetTPS;

	__int64 m_redisJobThreadUpdateTPS;
	__int64 m_redisJobEnqueueTPS;

	bool startFlag;

private:
	PerformanceMonitor performMoniter;
	MonitoringLanClient lanClient;

	std::wstring m_tempIp;
	std::string m_ip;

	static DWORD					_DBTlsIdx;

	LockFreeStack<DBConnector*> tlsDBObjects = LockFreeStack<DBConnector*>(5);		// tls db ��ü�� �����ϱ� ���� �ʿ� 

	// DB ���� ����
	int dbPort;
	wchar_t host[16];
	wchar_t user[64];
	wchar_t password[64];
	wchar_t dbName[64];

	CRedis* mRedis;
};

#endif // !__LOGINSERVER__CLASS__
