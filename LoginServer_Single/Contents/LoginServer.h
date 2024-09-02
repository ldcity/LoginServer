#ifndef __LOGINSERVER__CLASS__
#define __LOGINSERVER__CLASS__

#include "../Library/NetServer.h"
#include "../Utils/PerformanceMonitor.h"
#include "../Contents/MonitoringLanClient.h"
#include "../Library/LockFreeQueue.h"
#include "../Utils/DBConnection.h"
#include "../Utils/Redis.h"

class RedisWorkerThread;
class DBWorkerThread;;

class LoginServer : public NetServer
{
public:
	//--------------------------------------------------------------------------------------
	// Job Info
	//--------------------------------------------------------------------------------------
	enum JobType
	{
		MSG_PACKET,	// ���ŵ� ��Ŷ ó��
		LOGIN_RES,	// �α��� ���� ��Ŷ ó��
		DB_RES,		// DB ��� ó��
		TIMEOUT		// Ÿ�Ӿƿ�
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

public:
	void SendJob(uint64_t sessionID, WORD type, CPacket* packet);

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

	//--------------------------------------------------------------------------------------
	// Packet Proc
	//--------------------------------------------------------------------------------------
	void PacketProc(uint64_t sessionID, CPacket* packet);
	void DBProc(uint64_t sessionID, CPacket* packet);

	void NetPacketProc_ReqLogin(uint64_t sessionID, CPacket* packet);
	void NetPacketProc_ResLogin(uint64_t sessionID, CPacket* packet);
	void NetDBProc_ResAccountSelect(uint64_t sessionID, CPacket* packet);

	void MPReqSelectAccount(INT64 accountNo, const char* SessionKey, CPacket* packet);

	friend unsigned __stdcall MoniteringThread(void* param);				// ����͸� ������
	friend unsigned __stdcall JobWorkerThread(PVOID param);					// ���� Job ó�� ������

	bool MoniterThread_serv();
	bool JobWorkerThread_serv();

private:
	RedisWorkerThread* mRedisWorkerThread;
	DBWorkerThread* mDBWorkerThread;

private:
	Log* mLog;

	int mUserMAXCnt;									// �ִ� player ��
	int mTimeout;

	HANDLE mMoniteringThread;							// Monitering Thread
	HANDLE mControlThread;

	HANDLE mMoniterEvent;								// Monitering Event
	HANDLE mRunEvent;									// Thread Start Event

	HANDLE mJobHandle;
	HANDLE mJobEvent;

	TLSObjectPool<LoginJob> mJobPool = TLSObjectPool<LoginJob>(300);
	LockFreeQueue<LoginJob*> mJobQ = LockFreeQueue<LoginJob*>(500);

private:
	wchar_t mChatIP[16];
	unsigned short mChatPort;

	wchar_t mGameServerIp[16];
	USHORT mGameServerPort;


// ����͸� ���� ������
private:
	__int64 mLoginCount;
	__int64 mLoginTPS;

	__int64 mJobUpdatecnt;													// job ����
	__int64 mJobUpdateTPS;											// job thread update Ƚ��

	__int64 mLoginResJobUpdateTPS;

	bool mStartFlag;

private:
	PerformanceMonitor mPerformMoniter;
	MonitoringLanClient mLanClient;

	std::wstring mTempIp;
	std::string mIp;
};




#endif // !__LOGINSERVER__CLASS__
