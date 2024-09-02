#include <conio.h>

#include "LoginServer.h"
#include "../Utils/TextParser.h"
#include "../Utils/Profiling.h"
#include "../Utils/Protocol.h"
#include "../Utils/MonitorProtocol.h"
#include "../Utils/MonitoringDefine.h"
#include "Packet.h"

#include "RedisJobThread.h"
#include "DBJobThread.h"


// Job Worker Thread
unsigned __stdcall JobWorkerThread(PVOID param)
{
	LoginServer* loginServ = (LoginServer*)param;

	loginServ->JobWorkerThread_serv();

	return 0;
}

// Worker Thread Call
unsigned __stdcall MoniteringThread(void* param)
{
	LoginServer* logServ = (LoginServer*)param;

	logServ->MoniterThread_serv();

	return 0;
}

LoginServer::LoginServer()
{

}

LoginServer::~LoginServer()
{
	LoginServerStop();
}

bool LoginServer::LoginServerStart()
{
	mLog = new Log(L"mLog.txt");

	// login server ���������� Parsing�Ͽ� �о��
	TextParser loginServerInfoTxt;

	const wchar_t* txtName = L"LoginServer.txt";
	loginServerInfoTxt.LoadFile(txtName);

	// DB ���� ����
	wchar_t host[16];
	wchar_t user[64];
	wchar_t password[64];
	wchar_t dbName[64];
	int port;

	loginServerInfoTxt.GetValue(L"DB.HOST", host);
	loginServerInfoTxt.GetValue(L"DB.USER", user);
	loginServerInfoTxt.GetValue(L"DB.PASSWORD", password);
	loginServerInfoTxt.GetValue(L"DB.DBNAME", dbName);
	loginServerInfoTxt.GetValue(L"DB.PORT", &port);

	wchar_t redisIP[20];
	int redisPort;

	loginServerInfoTxt.GetValue(L"REDIS.IP", redisIP);
	loginServerInfoTxt.GetValue(L"REDIS.PORT", &redisPort);

	// DB Worker Thread ���� �� ���� - DBConnector ��ü ���� �� DB ����
	mDBWorkerThread = new DBWorkerThread(this, host, user, password, dbName, port, true);

	if (mDBWorkerThread == nullptr || 
		!mDBWorkerThread->StartThread(DBWorkerThread::ThreadFunction, mDBWorkerThread))
	{
		mLog->logger(dfLOG_LEVEL_ERROR, __LINE__, L"DB Connect Failed...");
		return false;
	}

	// Redis Worker Thread ���� �� ���� - RedisConnector ��ü ���� �� Redis ����
	mRedisWorkerThread = new RedisWorkerThread(this, redisIP, redisPort);

	if (mRedisWorkerThread == nullptr ||
		!mRedisWorkerThread->StartThread(RedisWorkerThread::ThreadFunction, mRedisWorkerThread))
	{
		mLog->logger(dfLOG_LEVEL_ERROR, __LINE__, L"Redis Connect Failed...");
		return false;
	}

	loginServerInfoTxt.GetValue(L"CHATSERVER.BIND_IP", mChatIP);
	loginServerInfoTxt.GetValue(L"CHATSERVER.BIND_PORT", &mChatPort);

	wchar_t ip[20];
	loginServerInfoTxt.GetValue(L"LOGINSERVER.BIND_IP", ip);

	mTempIp = ip;
	int len = WideCharToMultiByte(CP_UTF8, 0, mTempIp.c_str(), -1, NULL, 0, NULL, NULL);
	std::string result(len - 1, '\0');
	WideCharToMultiByte(CP_UTF8, 0, mTempIp.c_str(), -1, &result[0], len, NULL, NULL);
	mIp = result;

	mPerformMoniter.AddInterface(mIp);

	port;
	loginServerInfoTxt.GetValue(L"LOGINSERVER.BIND_PORT", &port);

	int workerThread;
	loginServerInfoTxt.GetValue(L"LOGINSERVER.IOCP_WORKER_THREAD", &workerThread);

	int runningThread;
	loginServerInfoTxt.GetValue(L"LOGINSERVER.IOCP_ACTIVE_THREAD", &runningThread);

	int nagleOff;
	loginServerInfoTxt.GetValue(L"LOGINSERVER.NAGLE_OFF", &nagleOff);

	int zeroCopyOff;
	loginServerInfoTxt.GetValue(L"LOGINSERVER.ZEROCOPY_OFF", &zeroCopyOff);

	int sessionMAXCnt;
	loginServerInfoTxt.GetValue(L"LOGINSERVER.SESSION_MAX", &sessionMAXCnt);

	loginServerInfoTxt.GetValue(L"LOGINSERVER.USER_MAX", &mUserMAXCnt);

	int packetCode;
	loginServerInfoTxt.GetValue(L"LOGINSERVER.PACKET_CODE", &packetCode);

	int packetKey;
	loginServerInfoTxt.GetValue(L"LOGINSERVER.PACKET_KEY", &packetKey);

	loginServerInfoTxt.GetValue(L"SERVICE.TIMEOUT_DISCONNECT", &mTimeout);

	// Login Lan Client Start
	bool clientRet = mLanClient.MonitoringLanClientStart();

	if (!clientRet)
	{
		mLog->logger(dfLOG_LEVEL_ERROR, __LINE__, L"LanClient Start Error");
		return false;
	}

	// Network Logic Start
	bool ret = this->Start(ip, port, workerThread, runningThread, nagleOff, zeroCopyOff, sessionMAXCnt, packetCode, packetKey, mTimeout);
	if (!ret)
	{
		mLog->logger(dfLOG_LEVEL_ERROR, __LINE__, L"NetServer Start Error");
		return false;
	}

	// Create Manual Event
	mRunEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	if (mRunEvent == NULL)
	{
		int eventError = WSAGetLastError();
		mLog->logger(dfLOG_LEVEL_ERROR, __LINE__, L"CreateEvent() Error : %d", eventError);

		return false;
	}

	// Create Auto Event
	mMoniterEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	if (mMoniterEvent == NULL)
	{
		int eventError = WSAGetLastError();
		mLog->logger(dfLOG_LEVEL_ERROR, __LINE__, L"CreateEvent() Error : %d", eventError);

		return false;
	}
	// Create Auto Event
	mJobEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
	if (mJobEvent == NULL)
	{
		int eventError = WSAGetLastError();
		mLog->logger(dfLOG_LEVEL_ERROR, __LINE__, L"CreateEvent() Error : %d", eventError);

		return false;
	}

	// Monitering Thread
	mMoniteringThread = (HANDLE)_beginthreadex(NULL, 0, MoniteringThread, this, CREATE_SUSPENDED, NULL);
	if (mMoniteringThread == NULL)
	{
		int threadError = GetLastError();
		mLog->logger(dfLOG_LEVEL_ERROR, __LINE__, L"_beginthreadex() Error : %d", threadError);

		return false;
	}

	// Job Worker Thread
	mJobHandle = (HANDLE)_beginthreadex(NULL, 0, JobWorkerThread, this, 0, NULL);
	if (mJobHandle == NULL)
	{
		int threadError = GetLastError();
		mLog->logger(dfLOG_LEVEL_ERROR, __LINE__, L"_beginthreadex() Error : %d", threadError);
		return false;
	}

	mLog->logger(dfLOG_LEVEL_DEBUG, __LINE__, L"Create Job Worker Thread");

	WaitForSingleObject(mMoniteringThread, INFINITE);
	WaitForSingleObject(mJobHandle, INFINITE);

	return true;
}

bool LoginServer::LoginServerStop()
{
	CloseHandle(mJobHandle);
	CloseHandle(mJobEvent);

	CloseHandle(mMoniteringThread);
	CloseHandle(mMoniterEvent);
	CloseHandle(mRunEvent);

	if(mRedisWorkerThread)
		delete mRedisWorkerThread;

	if(mDBWorkerThread)
		delete mDBWorkerThread;

	this->Stop();

	return true;
}

void LoginServer::MPReqSelectAccount(INT64 accountNo, const char* SessionKey, CPacket* packet)
{
	WORD type = en_PACKET_SS_REQ_SELECT_ACCOUNT;
	*packet << type << accountNo;

	packet->PutData((char*)SessionKey, MSGMAXLEN);
}

void LoginServer::SendJob(uint64_t sessionID, WORD type, CPacket* packet)
{
	// ���� ���� ��, �α��� ���� ó���� ���� �۾��� Job Worker Thread�� �ѱ�
	LoginJob* job = mJobPool.Alloc();
	job->sessionID = sessionID;
	job->type = type;
	job->packet = packet;

	mJobQ.Enqueue(job);
	SetEvent(mJobEvent);
}

// Monitering Thread
bool LoginServer::MoniterThread_serv()
{
	DWORD threadID = GetCurrentThreadId();

	while (true)
	{
		// 1�ʸ��� ����͸� -> Ÿ�Ӿƿ� �ǵ� ó��
		DWORD ret = WaitForSingleObject(mMoniterEvent, 1000);

		if (ret == WAIT_TIMEOUT)
		{
			// ����͸� ���� ���ۿ� ������
			__int64 iSessionCnt = sessionCnt;
			__int64 iAuthCnt = InterlockedExchange64(&mLoginTPS, 0);

			__int64 iJobThreadUpdateCnt = InterlockedExchange64(&mJobUpdateTPS, 0);

			__int64 jobPoolCapacity = mJobPool.GetCapacity();
			__int64 jobPoolUseCnt = mJobPool.GetObjectUseCount();
			__int64 jobPoolAllocCnt = mJobPool.GetObjectAllocCount();
			__int64 jobPoolFreeCnt = mJobPool.GetObjectFreeCount();

			__int64 packetPoolCapacity = CPacket::GetPoolCapacity();
			__int64 packetPoolUseCnt = CPacket::GetPoolUseCnt();
			__int64 packetPoolAllocCnt = CPacket::GetPoolTotalAllocCnt();
			__int64 packetPoolFreeCnt = CPacket::GetPoolTotalFreeCnt();

			wprintf(L"------------------------[Moniter]----------------------------\n");
			mPerformMoniter.PrintMonitorData();

			wprintf(L"------------------------[Network]----------------------------\n");
			wprintf(L"[Session              ] Total    : %10I64d\n", iSessionCnt);
			wprintf(L"[Accept               ] Total    : %10I64d      TPS        : %10I64d\n", acceptCount, InterlockedExchange64(&acceptTPS, 0));
			wprintf(L"[Release              ] Total    : %10I64d      TPS        : %10I64d\n", releaseCount, InterlockedExchange64(&releaseTPS, 0));
			wprintf(L"[Recv Call            ] Total    : %10I64d      TPS        : %10I64d\n", recvCallCount, InterlockedExchange64(&recvCallTPS, 0));
			wprintf(L"[Send Call            ] Total    : %10I64d      TPS        : %10I64d\n", sendCallCount, InterlockedExchange64(&sendCallTPS, 0));
			wprintf(L"[Recv Bytes           ] Total    : %10I64d      TPS        : %10I64d\n", recvBytes, InterlockedExchange64(&recvBytesTPS, 0));
			wprintf(L"[Send Bytes           ] Total    : %10I64d      TPS        : %10I64d\n", sendBytes, InterlockedExchange64(&sendBytesTPS, 0));
			wprintf(L"[Recv  Packet         ] Total    : %10I64d      TPS        : %10I64d\n", recvMsgCount, InterlockedExchange64(&recvMsgTPS, 0));
			wprintf(L"[Send  Packet         ] Total    : %10I64d      TPS        : %10I64d\n", sendMsgCount, InterlockedExchange64(&sendMsgTPS, 0));
			wprintf(L"[Pending TPS          ] Recv     : %10I64d      Send       : %10I64d\n", InterlockedExchange64(&recvPendingTPS, 0), InterlockedExchange64(&sendPendingTPS, 0));
			wprintf(L"---------------------[Login Contents]-------------------------\n");
			wprintf(L"[JobQ                 ] Main     : %10I64d      DB        : %10I64d     Redis     : %10I64d\n", mJobQ.GetSize(), mDBWorkerThread->mJobQ.GetSize(), mRedisWorkerThread->mJobQ.GetSize());
			wprintf(L"[JobQ                 ] Main     : %10I64d\n", mJobQ.GetSize());
			wprintf(L"[Main Job             ] TPS      : %10I64d      Total     : %10I64d\n", iJobThreadUpdateCnt, mJobUpdatecnt);
			wprintf(L"[DB Job               ] TPS      : %10I64d      Total     : %10I64d\n", InterlockedExchange64(&mDBWorkerThread->mJobThreadUpdateTPS, 0), mDBWorkerThread->mJobThreadUpdateCnt);
			wprintf(L"[Redis Job            ] TPS      : %10I64d      Total     : %10I64d\n", InterlockedExchange64(&mRedisWorkerThread->mJobThreadUpdateTPS, 0), mRedisWorkerThread->mJobThreadUpdateCnt);
			wprintf(L"[Login Req Job        ] TPS      : %10I64d      Total     : %10I64d \n",
				InterlockedExchange64(&mLoginTPS, 0), mLoginCount);
			wprintf(L"[Login Res Job        ] TPS      : %10I64d\n", InterlockedExchange64(&mLoginResJobUpdateTPS, 0));
			wprintf(L"[Job Pool Use         ] Main     : %10llu       DB       : %10llu    Redis : %10llu\n",
				jobPoolUseCnt, mDBWorkerThread->mJobPool.GetObjectUseCount(), mRedisWorkerThread->mJobPool.GetObjectUseCount());
			wprintf(L"[Packet Pool          ] Capacity : %10llu      Use       : %10llu    Alloc : %10llu    Free : %10llu\n",
				packetPoolCapacity, packetPoolUseCnt, packetPoolAllocCnt, packetPoolFreeCnt);
			wprintf(L"==============================================================\n\n");
			
			// ����͸� ������ ������ ����
			int iTime = (int)time(NULL);
			BYTE serverNo = SERVERTYPE::LOGIN_SERVER_TYPE;

			// LoginServer ���� ���� ON / OFF
			CPacket* onPacket = CPacket::Alloc();
			mLanClient.mpUpdateDataToMonitorServer(serverNo, MONITOR_DATA_TYPE_LOGIN_SERVER_RUN, true, iTime, onPacket);
			mLanClient.SendPacket(onPacket);
			CPacket::Free(onPacket);

			// LoginServer CPU ����
			CPacket* cpuPacket = CPacket::Alloc();
			mLanClient.mpUpdateDataToMonitorServer(serverNo, MONITOR_DATA_TYPE_LOGIN_SERVER_CPU, (int)mPerformMoniter.GetProcessCpuTotal(), iTime, cpuPacket);
			mLanClient.SendPacket(cpuPacket);
			CPacket::Free(cpuPacket);

			// LoginServer �޸� ��� MByte
			CPacket* memoryPacket = CPacket::Alloc();
			mLanClient.mpUpdateDataToMonitorServer(serverNo, MONITOR_DATA_TYPE_LOGIN_SERVER_MEM, (int)mPerformMoniter.GetProcessUserMemoryByMB(), iTime, memoryPacket);
			mLanClient.SendPacket(memoryPacket);
			CPacket::Free(memoryPacket);

			// LoginServer ���� �� (���ؼ� ��)
			CPacket* sessionPacket = CPacket::Alloc();
			mLanClient.mpUpdateDataToMonitorServer(serverNo, MONITOR_DATA_TYPE_LOGIN_SESSION, (int)iSessionCnt, iTime, sessionPacket);
			mLanClient.SendPacket(sessionPacket);
			CPacket::Free(sessionPacket);

			// LoginServer ���� ó�� �ʴ� Ƚ��
			CPacket* authPacket = CPacket::Alloc();
			mLanClient.mpUpdateDataToMonitorServer(serverNo, MONITOR_DATA_TYPE_LOGIN_AUTH_TPS, (int)iAuthCnt, iTime, authPacket);
			mLanClient.SendPacket(authPacket);
			CPacket::Free(authPacket);

			// LoginServer ��ŶǮ ��뷮
			CPacket* poolPacket = CPacket::Alloc();
			mLanClient.mpUpdateDataToMonitorServer(serverNo, MONITOR_DATA_TYPE_LOGIN_PACKET_POOL, (int)packetPoolUseCnt, iTime, poolPacket);
			mLanClient.SendPacket(poolPacket);
			CPacket::Free(poolPacket);
		}
	}

	return true;
}


bool LoginServer::OnConnectionRequest(const wchar_t* IP, unsigned short PORT)
{
	// ...
	return true;
}

void LoginServer::OnClientJoin(uint64_t sessionID)
{
	if (!mStartFlag)
	{
		ResumeThread(mMoniteringThread);
		mStartFlag = true;
	}

	// �α��� ������ accept
}

void LoginServer::OnClientLeave(uint64_t sessionID)
{
}

void LoginServer::OnRecv(uint64_t sessionID, CPacket* packet)
{
	LoginJob* job = mJobPool.Alloc();
	job->type = JobType::MSG_PACKET;
	job->sessionID = sessionID;
	job->packet = packet;

	mJobQ.Enqueue(job);
	SetEvent(mJobEvent);
}

void LoginServer::OnError(int errorCode, const wchar_t* msg)
{

}

// Network Logic ���κ��� timeout ó���� �߻��Ǹ� timeout Handler ȣ��
void LoginServer::OnTimeout(uint64_t sessionID)
{
	LoginJob* job = mJobPool.Alloc();
	job->type = JobType::TIMEOUT;
	job->sessionID = sessionID;
	job->packet = nullptr;

	mJobQ.Enqueue(job);
	InterlockedIncrement64(&mJobUpdatecnt);
	SetEvent(mJobEvent);
}


bool LoginServer::JobWorkerThread_serv()
{
	while (true)
	{
		// Handler Job Queue�� �۾��� Enqueue�Ǿ��ٴ� �̺�Ʈ�� �ñ׳θ��Ǹ� ���
		WaitForSingleObject(mJobEvent, INFINITE);

		LoginJob* loginJob = nullptr;

		// Queue�� Job�� ���� ������ update ����
		while (mJobQ.GetSize() > 0)
		{
			if (mJobQ.Dequeue(loginJob))
			{
				// Job Type�� ���� �б� ó��
				switch (loginJob->type)
				{
				// Ŭ���̾�Ʈ���� �� ���� ��Ŷ ó��
				case JobType::MSG_PACKET:
					PacketProc(loginJob->sessionID, loginJob->packet);	
					break;

				// ���������� �߻��� �α��� ���� ��Ŷ ó��
				case JobType::LOGIN_RES:
					NetPacketProc_ResLogin(loginJob->sessionID, loginJob->packet);
					break;

				// DB ��û�� ���� ��� ó��
				case JobType::DB_RES:
					DBProc(loginJob->sessionID, loginJob->packet);
					break;

				// ���� Ÿ�Ӿƿ�
				case JobType::TIMEOUT:
					DisconnectSession(loginJob->sessionID);
					break;
				
				// ��Ŷ Ÿ�� ����
				default:
					DisconnectSession(loginJob->sessionID);
					break;
				}

				if (loginJob->packet != nullptr)
					CPacket::Free(loginJob->packet);

				mJobPool.Free(loginJob);

				InterlockedIncrement64(&mJobUpdatecnt);
				InterlockedIncrement64(&mJobUpdateTPS);
			}
		}
	}
}

void LoginServer::PacketProc(uint64_t sessionID, CPacket* packet)
{
	WORD type;
	*packet >> type;

	switch (type)
	{
	case en_PACKET_CS_LOGIN_REQ_LOGIN:
		// �α��� ��û
		NetPacketProc_ReqLogin(sessionID, packet);
		break;

	default:
		// �߸��� ��Ŷ
		mLog->logger(dfLOG_LEVEL_ERROR, __LINE__, L"PacketProc Packet Type Error > %d", type);
		DisconnectSession(sessionID);
		break;
	}
}

void LoginServer::DBProc(uint64_t sessionID, CPacket* packet)
{
	WORD type;
	*packet >> type;

	switch (type)
	{
	case en_PACKET_SS_RES_SELECT_ACCOUNT:
		// account table select ��� ó��
		NetDBProc_ResAccountSelect(sessionID, packet);
		break;

	default:
		// �߸��� ��Ŷ
		mLog->logger(dfLOG_LEVEL_ERROR, __LINE__, L"DBProc Packet Type Error > %d", type);
		DisconnectSession(sessionID);
		break;
	}
}

void LoginServer::NetDBProc_ResAccountSelect(uint64_t sessionID, CPacket* packet)
{
	INT64 _accountNo;
	*packet >> _accountNo;

	char SessionKey[MSGMAXLEN + 1] = { 0 };
	packet->GetData((char*)SessionKey, MSGMAXLEN);
	SessionKey[MSGMAXLEN] = '\0';

	// select ���� �ش� ���� �÷� �� ���� (��� ����)
	wchar_t ID[IDMAXLEN] = { 0 };
	wchar_t Nickname[NICKNAMEMAXLEN] = { 0 };

	packet->GetData((char*)ID, IDMAXLEN * sizeof(wchar_t));
	packet->GetData((char*)Nickname, NICKNAMEMAXLEN * sizeof(wchar_t));

	// ------------------------------------------------------------------------
	// Redis�� ���� ��ū ���� ("accountNo", "sessionKey")
	// ------------------------------------------------------------------------
	std::string accountNoStr = std::to_string(_accountNo);
	std::string sessionKeyStr(SessionKey);
	BYTE status = en_PACKET_CS_LOGIN_RES_LOGIN::dfLOGIN_STATUS_OK;

	// �񵿱�
	CPacket* resLoginPacket = CPacket::Alloc();

	MPResLogin(resLoginPacket, _accountNo, status, ID, Nickname, mGameServerIp, mGameServerPort, mChatIP, mChatPort);

	// redis thread�� redis �� �ѱ�
	mRedisWorkerThread->EnqueueJob(RedisWorkerThread::REDISTYPE::SET, sessionID, accountNoStr, sessionKeyStr, resLoginPacket);
}

// �α��� ��û
void LoginServer::NetPacketProc_ReqLogin(uint64_t sessionID, CPacket* packet)
{
	InterlockedIncrement64(&mLoginCount);
	InterlockedIncrement64(&mLoginTPS);

	// Packet ũ�⿡ ���� ���� ó�� 
	if (packet->GetDataSize() < sizeof(INT64) + MSGMAXLEN * sizeof(char))
	{
		int size = packet->GetDataSize() + sizeof(WORD);
		mLog->logger(dfLOG_LEVEL_ERROR, __LINE__, L"Login Request Packet # size error :  %d", size);

		DisconnectSession(sessionID);

		return;
	}

	INT64 _accountNo;
	
	// �ʱ� ���� - ����
	BYTE status = en_PACKET_CS_LOGIN_RES_LOGIN::dfLOGIN_STATUS_OK;
	
	// accountNo�� ������ȭ�ؼ� ����
	*packet >> _accountNo;
	
	// �߸��� ���� ��ȣ - ���� ����
	if (_accountNo <= 0)
	{
		mLog->logger(dfLOG_LEVEL_ERROR, __LINE__, L"Login Request Packet # account error :  %IId", _accountNo);
	
		DisconnectSession(sessionID);
	
		return;
	}
	
	// MSGMAXLEN�� 64
	char SessionKey[MSGMAXLEN + 1] = { 0 };
	wchar_t ID[20] = { 0 };
	wchar_t Nickname[20] = { 0 };
	
	// Redis�� ������ ������ū�� ������ȭ�ؼ� ����
	// ���� ���������� Dummy Client�� ������ū�� ���� ��û�� �ϱ� ������ �̸� �ŷ���
	packet->GetData((char*)SessionKey, MSGMAXLEN);
	
	SessionKey[MSGMAXLEN] = '\0';
	
	// ���� Ű ���� �ƹ��͵� ���� ���...
	if (SessionKey[0] == '\0')
	{
		mLog->logger(dfLOG_LEVEL_ERROR, __LINE__, L"Login Request Packet # sessionKey is null");
		DisconnectSession(sessionID);
		return;
	}


	// ---------------------------------------------------------------------
	// �ܺ� �÷��� API�� �����Ͽ� ��ū�� ������ �۾��� ���ϰ� ū �۾�
	// �̷��� ���� ���ٵ� ������ �� �ִ��� �ľ��ϱ� ����
	// DB ������ ���� ����� ��Ȳ ���� (���ϰ� �ɸ��� �۾�)

	// DB ������ ���� �� ���� �Ű������� �����ϴ� ������ ��û
	// �Ű����� ���ε� �� ���� ��û / ���� ��� �ļ� ó��
	// ���� ��û ��, �ļ� ��� ó���� ���� �ڵ鷯 �Լ� ȣ��

	// db �۾� �񵿱� ó��
	
	std::wstring query = L"SELECT userid, usernick FROM accountdb.account WHERE accountno = ?";
	CPacket* paramPacket = CPacket::Alloc();

	MPReqSelectAccount(_accountNo, SessionKey, paramPacket);

	// db thread�� �� �ѱ�
	mDBWorkerThread->EnqueueJob(DBWorkerThread::DBTYPE::SELECT, sessionID, query, paramPacket);
}

// �񵿱� redis ��û ����� ���� ��, ���� �α��� job ó��
void LoginServer::NetPacketProc_ResLogin(uint64_t sessionID, CPacket* packet)
{
	// account table�� �ִ� �����̹Ƿ� �α��� ���� & ���� ����
	InterlockedIncrement64(&mLoginResJobUpdateTPS);

	// �α��� ����
	SendPacket(sessionID, packet);
}