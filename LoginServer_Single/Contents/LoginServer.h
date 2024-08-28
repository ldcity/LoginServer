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
		MSG_PACKET,		// ���ŵ� ��Ŷ ó��
		JOB_PACKET,		// ���������� ��û�� �۾�
		DB_FAIL,		// DB ���� ����
		//DB_SELECT,		// Select ���� ��û
		//DB_UPDATE,		// Update ���� ��û
		TIMEOUT			// Ÿ�Ӿƿ�
	};

	enum ErrorCode
	{
		REDISSETERROR
	};

	// Job ����ü
	struct LoginJob
	{
		// Session ID
		uint64_t sessionID;

		// Job Type
		WORD type;

		// ��Ŷ ������
		CPacket* packet;
	};

	//// DB Job ����ü
	//struct DBJob
	//{
	//	WORD type;
	//	uint64_t sessionID;
	//	__int64 accountNo;
	//	char sessionKey[65];
	//};

	// Redis Job ����ü
	struct RedisJob
	{
		uint64_t sessionID;			// Session ���� ID
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
	void OnError(int errorCode, const wchar_t* msg);
	void OnTimeout(uint64_t sessionID);

	//bool AsyncLogin(RedisJob* redisJob);

	//--------------------------------------------------------------------------------------
	// Packet Proc
	//--------------------------------------------------------------------------------------
	void PacketProc(uint64_t sessionID, CPacket* packet);
	void netPacketProc_ReqLogin(uint64_t sessionID, CPacket* packet);
	void netPacketProc_ResLogin(uint64_t sessionID, CPacket* packet);

	void RedisProc(RedisJob* redisJob);

	friend unsigned __stdcall MoniteringThread(void* param);
	friend unsigned __stdcall JobWorkerThread(PVOID param);					// Job �� ó�� ������
	//friend unsigned __stdcall DBJobWorkerThread(PVOID param);			// Redis Job �� ó�� ������
	friend unsigned __stdcall RedisJobWorkerThread(PVOID param);			// Redis Job �� ó�� ������

	bool MoniterThread_serv();
	bool JobWorkerThread_serv();
	//bool DBJobWorkerThread_serv();
	bool RedisJobWorkerThread_serv();

private:
	Log* loginLog;

	int m_userMAXCnt;									// �ִ� player ��
	int m_timeout;

	HANDLE m_moniteringThread;							// Monitering Thread
	HANDLE m_controlThread;

	HANDLE m_moniterEvent;								// Monitering Event
	HANDLE m_runEvent;									// Thread Start Event

	HANDLE m_jobHandle;
	HANDLE m_jobEvent;

	//HANDLE m_dbJobHandle;
	//HANDLE m_dbJobEvent;

	HANDLE m_redisJobHandle;
	HANDLE m_redisJobEvent;

	TLSObjectPool<LoginJob> jobPool = TLSObjectPool<LoginJob>(300);
	LockFreeQueue<LoginJob*> jobQ = LockFreeQueue<LoginJob*>(500);

	//TLSObjectPool<DBJob> dbJobPool = TLSObjectPool<DBJob>(300);
	//LockFreeQueue<DBJob*> dbJobQ = LockFreeQueue<DBJob*>(500);

	TLSObjectPool<RedisJob> redisJobPool = TLSObjectPool<RedisJob>(100);
	LockFreeQueue<RedisJob*> redisJobQ = LockFreeQueue<RedisJob*>(200);

	//TLSObjectPool<RedisJob> redisJobPool = TLSObjectPool<RedisJob>(0);
	//LockFreeQueue<RedisJob*> redisJobQ = LockFreeQueue<RedisJob*>(0);

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

	__int64 m_jobUpdatecnt;													// job ����
	__int64 m_jobThreadUpdateCnt;											// job thread update Ƚ��

	__int64 m_loginResJobUpdateTPS;
	__int64 m_redisJobThreadUpdateTPS;

	bool startFlag;

private:
	PerformanceMonitor performMoniter;
	MonitoringLanClient lanClient;

	std::wstring m_tempIp;
	std::string m_ip;

	//CRedis_TLS* mRedis_TLS;				// TLS�� Redis Connector
	//DBConnector_TLS* dbConn_TLS;			// TLS�� DBConnector

	CRedis* mRedis;				// Redis Connector
	DBConnector* dbConn;		// DBConnector

	wchar_t mDBName[64];

};




#endif // !__LOGINSERVER__CLASS__
