#include "../PCH.h"
#include "LoginServer.h"
#include <conio.h>


HANDLE g_endEvent = NULL;

// Job Worker Thread
unsigned __stdcall JobWorkerThread(PVOID param)
{
	LoginServer* loginServ = (LoginServer*)param;

	loginServ->JobWorkerThread_serv();

	return 0;
}

//// Job Worker Thread
//unsigned __stdcall DBJobWorkerThread(PVOID param)
//{
//	LoginServer* loginServ = (LoginServer*)param;
//
//	loginServ->DBJobWorkerThread_serv();
//
//	return 0;
//}

// Redis Job Worker Thread
unsigned __stdcall RedisJobWorkerThread(PVOID param)
{
	LoginServer* logServ = (LoginServer*)param;

	logServ->RedisJobWorkerThread_serv();

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
	loginLog = new Log(L"LoginLog");

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

	wmemcpy_s(mDBName, 64, dbName, 64);

	// DBConnector ��ü ���� �� DB ����
	dbConn = new DBConnector(host, user, password, dbName, port, true);
	dbConn->Open();

	loginServerInfoTxt.GetValue(L"CHATSERVER.BIND_IP", chatIP);
	loginServerInfoTxt.GetValue(L"CHATSERVER.BIND_PORT", &chatPort);

	wchar_t ip[20];
	loginServerInfoTxt.GetValue(L"LOGINSERVER.BIND_IP", ip);

	m_tempIp = ip;
	int len = WideCharToMultiByte(CP_UTF8, 0, m_tempIp.c_str(), -1, NULL, 0, NULL, NULL);
	std::string result(len - 1, '\0');
	WideCharToMultiByte(CP_UTF8, 0, m_tempIp.c_str(), -1, &result[0], len, NULL, NULL);
	m_ip = result;

	performMoniter.AddInterface(m_ip);

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

	loginServerInfoTxt.GetValue(L"LOGINSERVER.USER_MAX", &m_userMAXCnt);

	int packet_code;
	loginServerInfoTxt.GetValue(L"LOGINSERVER.PACKET_CODE", &packet_code);

	int packet_key;
	loginServerInfoTxt.GetValue(L"LOGINSERVER.PACKET_KEY", &packet_key);

	loginServerInfoTxt.GetValue(L"SERVICE.TIMEOUT_DISCONNECT", &m_timeout);

	// Login Lan Client Start
	bool clientRet = lanClient.MonitoringLanClientStart();

	if (!clientRet)
	{
		loginLog->logger(dfLOG_LEVEL_ERROR, __LINE__, L"LanClient Start Error");
		return false;
	}

	// Network Logic Start
	bool ret = this->Start(ip, port, workerThread, runningThread, nagleOff, zeroCopyOff, sessionMAXCnt, packet_code, packet_key, m_timeout);
	if (!ret)
	{
		loginLog->logger(dfLOG_LEVEL_ERROR, __LINE__, L"NetServer Start Error");
		return false;
	}

	wchar_t redisIP[20];
	loginServerInfoTxt.GetValue(L"REDIS.IP", redisIP);

	int redisPort;
	loginServerInfoTxt.GetValue(L"REDIS.PORT", &redisPort);

	mRedis = new CRedis;
	mRedis->Connect(redisIP, redisPort);

	// Create Manual Event
	m_runEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	if (m_runEvent == NULL)
	{
		int eventError = WSAGetLastError();
		loginLog->logger(dfLOG_LEVEL_ERROR, __LINE__, L"CreateEvent() Error : %d", eventError);

		return false;
	}

	// Create Auto Event
	m_moniterEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	if (m_moniterEvent == NULL)
	{
		int eventError = WSAGetLastError();
		loginLog->logger(dfLOG_LEVEL_ERROR, __LINE__, L"CreateEvent() Error : %d", eventError);

		return false;
	}
	// Create Auto Event
	m_jobEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
	if (m_jobEvent == NULL)
	{
		int eventError = WSAGetLastError();
		loginLog->logger(dfLOG_LEVEL_ERROR, __LINE__, L"CreateEvent() Error : %d", eventError);

		return false;
	}

	//// Create Auto Event
	//m_dbJobEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
	//if (m_dbJobEvent == NULL)
	//{
	//	int eventError = WSAGetLastError();
	//	loginLog->logger(dfLOG_LEVEL_ERROR, __LINE__, L"CreateEvent() Error : %d", eventError);

	//	return false;
	//}

	// Create Auto Event
	m_redisJobEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
	if (m_redisJobEvent == NULL)
	{
		int eventError = WSAGetLastError();
		loginLog->logger(dfLOG_LEVEL_ERROR, __LINE__, L"CreateEvent() Error : %d", eventError);

		return false;
	}


	g_endEvent = CreateEvent(NULL, TRUE, FALSE, NULL); // ���� ���� �̺�Ʈ ����

	// Monitering Thread
	m_moniteringThread = (HANDLE)_beginthreadex(NULL, 0, MoniteringThread, this, CREATE_SUSPENDED, NULL);
	if (m_moniteringThread == NULL)
	{
		int threadError = GetLastError();
		loginLog->logger(dfLOG_LEVEL_ERROR, __LINE__, L"_beginthreadex() Error : %d", threadError);

		return false;
	}

	// Job Worker Thread
	m_jobHandle = (HANDLE)_beginthreadex(NULL, 0, JobWorkerThread, this, 0, NULL);
	if (m_jobHandle == NULL)
	{
		int threadError = GetLastError();
		loginLog->logger(dfLOG_LEVEL_ERROR, __LINE__, L"_beginthreadex() Error : %d", threadError);
		return false;
	}

	//// DB Job Worker Thread
	//m_dbJobHandle = (HANDLE)_beginthreadex(NULL, 0, DBJobWorkerThread, this, 0, NULL);
	//if (m_dbJobHandle == NULL)
	//{
	//	int threadError = GetLastError();
	//	loginLog->logger(dfLOG_LEVEL_ERROR, __LINE__, L"_beginthreadex() Error : %d", threadError);
	//	return false;
	//}

	// Redis Job Worker Thread
	m_redisJobHandle = (HANDLE)_beginthreadex(NULL, 0, RedisJobWorkerThread, this, 0, NULL);
	if (m_redisJobHandle == NULL)
	{
		int threadError = GetLastError();
		loginLog->logger(dfLOG_LEVEL_ERROR, __LINE__, L"_beginthreadex() Error : %d", threadError);

		return false;
	}

	loginLog->logger(dfLOG_LEVEL_DEBUG, __LINE__, L"Create Job Worker Thread");

	WaitForSingleObject(m_moniteringThread, INFINITE);
	WaitForSingleObject(m_jobHandle, INFINITE);
	WaitForSingleObject(m_redisJobHandle, INFINITE);


	return true;
}

bool LoginServer::LoginServerStop()
{
	loginLog->~Log();
	logger->~Log();

	CloseHandle(m_jobHandle);
	CloseHandle(m_jobEvent);

	//CloseHandle(m_dbJobHandle);
	//CloseHandle(m_dbJobEvent);

	CloseHandle(m_redisJobHandle);
	CloseHandle(m_redisJobEvent);
	
	CloseHandle(m_moniteringThread);
	CloseHandle(m_moniterEvent);
	CloseHandle(m_runEvent);

	delete mRedis;
	delete dbConn;

	this->Stop();

	return true;
}

void SaveProfilingData()
{
	SYSTEMTIME st;
	GetLocalTime(&st);

	wchar_t buffer[20];
	swprintf_s(buffer, L"%02d%02d%02d_%02d%02d.txt", st.wYear % 100, st.wMonth, st.wDay, st.wHour, st.wMinute);

	wchar_t name[256] = L"Profiling_";
	wcscat_s(name, buffer);

	PRO_TEXT(name);
	PRO_RESET();
}


// Monitering Thread
bool LoginServer::MoniterThread_serv()
{
	DWORD threadID = GetCurrentThreadId();

	HANDLE events[2] = { m_moniterEvent, g_endEvent };

	while (true)
	{
		// 1�ʸ��� ����͸� -> Ÿ�Ӿƿ� �ǵ� ó��
		DWORD ret = WaitForMultipleObjects(2, events, FALSE, 1000);

		//// 1�ʸ��� ����͸� -> Ÿ�Ӿƿ� �ǵ� ó��
		//DWORD ret = WaitForSingleObject(m_moniterEvent, 1000);

		if (ret == WAIT_TIMEOUT)
		{
			// ����͸� ���� ���ۿ� ������
			__int64 iSessionCnt = sessionCnt;
			__int64 iAuthCnt = InterlockedExchange64(&m_loginSuccessTPS, 0);

			__int64 iJobThreadUpdateCnt = InterlockedExchange64(&m_jobThreadUpdateCnt, 0);

			__int64 jobPoolCapacity = jobPool.GetCapacity();
			__int64 jobPoolUseCnt = jobPool.GetObjectUseCount();
			__int64 jobPoolAllocCnt = jobPool.GetObjectAllocCount();
			__int64 jobPoolFreeCnt = jobPool.GetObjectFreeCount();

			__int64 packetPoolCapacity = CPacket::GetPoolCapacity();
			__int64 packetPoolUseCnt = CPacket::GetPoolUseCnt();
			__int64 packetPoolAllocCnt = CPacket::GetPoolTotalAllocCnt();
			__int64 packetPoolFreeCnt = CPacket::GetPoolTotalFreeCnt();

			wprintf(L"------------------------[Moniter]----------------------------\n");
			performMoniter.PrintMonitorData();

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
			wprintf(L"------------------------[Contents]----------------------------\n");
			wprintf(L"[JobQ                 ] Size     : %10I64d\n", jobQ.GetSize());
			wprintf(L"[Job                  ] Enq TPS  : %10I64d      Update TPS : %10I64d\n", InterlockedExchange64(&m_jobUpdatecnt, 0), iJobThreadUpdateCnt);
			wprintf(L"[Job Login Res        ] TPS      : %10I64d\n", InterlockedExchange64(&m_loginResJobUpdateTPS, 0));
			wprintf(L"[Job Pool             ] Capacity : %10llu      Use        : %10llu    Alloc : %10llu    Free : %10llu\n",
				jobPoolCapacity, jobPoolUseCnt, jobPoolAllocCnt, jobPoolFreeCnt);
			wprintf(L"[Redis Update         ] TPS      : %10I64d\n", InterlockedExchange64(&m_redisJobThreadUpdateTPS, 0));
			wprintf(L"[DB                   ] Total    : %10I64d      TPS        : %10I64d\n",
				m_dbQueryTotal, InterlockedExchange64(&m_dbQueryTPS, 0));
			wprintf(L"[Packet Pool          ] Capacity : %10llu      Use        : %10llu    Alloc : %10llu    Free : %10llu\n",
				packetPoolCapacity, packetPoolUseCnt, packetPoolAllocCnt, packetPoolFreeCnt);
			wprintf(L"[Login Packet         ] Total    : %10I64d      TPS        : %10I64d \n",
				m_loginCount, InterlockedExchange64(&m_loginTPS, 0));
			wprintf(L"[Login Success        ] Total    : %10I64d      TPS        : %10I64d \n",
				m_loginSuccessCount, iAuthCnt);
			wprintf(L"[Login Fail           ] Total    : %10I64d      TPS        : %10I64d \n",
				m_loginFailCount, InterlockedExchange64(&m_loginFailTPS, 0));
			wprintf(L"==============================================================\n\n");
			
			// ����͸� ������ ������ ����
			int iTime = (int)time(NULL);
			BYTE serverNo = SERVERTYPE::LOGIN_SERVER_TYPE;

			// LoginServer ���� ���� ON / OFF
			CPacket* onPacket = CPacket::Alloc();
			lanClient.mpUpdateDataToMonitorServer(serverNo, MONITOR_DATA_TYPE_LOGIN_SERVER_RUN, true, iTime, onPacket);
			lanClient.SendPacket(onPacket);
			CPacket::Free(onPacket);

			// LoginServer CPU ����
			CPacket* cpuPacket = CPacket::Alloc();
			lanClient.mpUpdateDataToMonitorServer(serverNo, MONITOR_DATA_TYPE_LOGIN_SERVER_CPU, (int)performMoniter.GetProcessCpuTotal(), iTime, cpuPacket);
			lanClient.SendPacket(cpuPacket);
			CPacket::Free(cpuPacket);

			// LoginServer �޸� ��� MByte
			CPacket* memoryPacket = CPacket::Alloc();
			lanClient.mpUpdateDataToMonitorServer(serverNo, MONITOR_DATA_TYPE_LOGIN_SERVER_MEM, (int)performMoniter.GetProcessUserMemoryByMB(), iTime, memoryPacket);
			lanClient.SendPacket(memoryPacket);
			CPacket::Free(memoryPacket);

			// LoginServer ���� �� (���ؼ� ��)
			CPacket* sessionPacket = CPacket::Alloc();
			lanClient.mpUpdateDataToMonitorServer(serverNo, MONITOR_DATA_TYPE_LOGIN_SESSION, (int)iSessionCnt, iTime, sessionPacket);
			lanClient.SendPacket(sessionPacket);
			CPacket::Free(sessionPacket);

			// LoginServer ���� ó�� �ʴ� Ƚ��
			CPacket* authPacket = CPacket::Alloc();
			lanClient.mpUpdateDataToMonitorServer(serverNo, MONITOR_DATA_TYPE_LOGIN_AUTH_TPS, (int)iAuthCnt, iTime, authPacket);
			lanClient.SendPacket(authPacket);
			CPacket::Free(authPacket);

			// LoginServer ��ŶǮ ��뷮
			CPacket* poolPacket = CPacket::Alloc();
			lanClient.mpUpdateDataToMonitorServer(serverNo, MONITOR_DATA_TYPE_LOGIN_PACKET_POOL, (int)packetPoolUseCnt, iTime, poolPacket);
			lanClient.SendPacket(poolPacket);
			CPacket::Free(poolPacket);

			if (_kbhit())
			{
				int ch = _getch();
				if (ch == 'y')
					SetEvent(g_endEvent);
			}
		}
		else if(ret == WAIT_OBJECT_0 + 1)
		{
			// 'y' Ű �Է� �̺�Ʈ�� �߻��ϸ� �������ϸ� ������ ����
			SaveProfilingData();
			wprintf(L"################################# Save Profiling Text #################################\n");
			ResetEvent(g_endEvent); // �̺�Ʈ ����
		}
	}

	return true;
}

//bool LoginServer::JobWorkerThread_serv()
//{
//	DWORD threadID = GetCurrentThreadId();
//
//	while (true)
//	{
//		// JobQ�� Job�� ���ԵǸ� �̺�Ʈ �߻��Ͽ� ���
//		WaitForSingleObject(m_jobEvent, INFINITE);
//
//		LoginJob* loginJob = nullptr;
//
//		// Job�� ���� ������ update �ݺ�
//		while (loginJobQ.GetSize() > 0)
//		{
//			PRO_BEGIN(L"Job_Queue");
//			if (loginJobQ.Dequeue(loginJob))
//			{
//				// Job Type�� ���� �б� ó��
//				switch (loginJob->type)
//				{
//				case JobType::MSG_PACKET:
//					PacketProc(loginJob->sessionID, loginJob->packet);	// ��Ŷ ó��
//					break;
//
//				case JobType::REDIS_RES:
//					PRO_BEGIN(L"Login_Res");
//					// �񵿱� �α��� ��û ��� ó��
//					netPacketProc_ResLoginRedis(loginJob->sessionID, loginJob->packet);
//					PRO_END(L"Login_Res");
//					break;
//
//				case JobType::TIMEOUT:
//					// ���� Ÿ�Ӿƿ�
//					DisconnectSession(loginJob->sessionID);
//					break;
//
//				default:
//					DisconnectSession(loginJob->sessionID);
//					break;
//				}
//
//				// ����, ���� Job�� packet�� nullptr�̱� ������ ��ȯ�� Packet�� ����
//				if (loginJob->packet != nullptr)
//					CPacket::Free(loginJob->packet);
//
//				// JobPool�� Job ��ü ��ȯ
//				jobPool.Free(loginJob);
//
//				InterlockedIncrement64(&m_jobThreadUpdateCnt);
//			}
//			PRO_END(L"Job_Queue");
//		}
//	}
//}

bool LoginServer::JobWorkerThread_serv()
{
	while (true)
	{
		// Handler Job Queue�� �۾��� Enqueue�Ǿ��ٴ� �̺�Ʈ�� �ñ׳θ��Ǹ� ���
		WaitForSingleObject(m_jobEvent, INFINITE);

		LoginJob* loginJob = nullptr;

		// Queue�� Job�� ���� ������ update ����
		while (jobQ.GetSize() > 0)
		{
			PRO_BEGIN(L"Job Time");
			if (jobQ.Dequeue(loginJob))
			{
				// Job Type�� ���� �б� ó��
				switch (loginJob->type)
				{
				// ���� ��Ŷ ó��
				case JobType::MSG_PACKET:
					PRO_BEGIN(L"Login_Request");
					PacketProc(loginJob->sessionID, loginJob->packet);	
					PRO_END(L"Login_Request");
					break;

				// ���������� �߻��� ��Ŷ ó��
				case JobType::JOB_PACKET:
					PRO_BEGIN(L"Login_Response");
					netPacketProc_ResLogin(loginJob->sessionID, loginJob->packet);
					PRO_END(L"Login_Response");
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

				jobPool.Free(loginJob);

				InterlockedIncrement64(&m_jobThreadUpdateCnt);
			}
			PRO_END(L"Job Time");
		}
	}
}

//bool LoginServer::DBJobWorkerThread_serv()
//{
//	while (true)
//	{
//		// DB Job Queue�� �۾��� Enqueue�Ǿ��ٴ� �̺�Ʈ�� �ñ׳θ��Ǹ� ���
//		WaitForSingleObject(m_dbJobEvent, INFINITE);
//
//		DBJob* dbJob = nullptr;
//
//		// Queue�� Job�� ���� ������ update ����
//		while (dbJobQ.GetSize() > 0)
//		{
//			PRO_BEGIN(L"DB Job Time");
//			if (dbJobQ.Dequeue(dbJob))
//			{
//				// Job Type�� ���� �б� ó��
//				switch (dbJob->type)
//				{
//					// ���� ��Ŷ ó��
//				case JobType::MSG_PACKET:
//					PacketProc(loginJob->sessionID, loginJob->packet);
//					break;
//
//					// ���� Ÿ�Ӿƿ�
//				case JobType::TIMEOUT:
//					DisconnectSession(loginJob->sessionID);
//					break;
//
//					// ��Ŷ Ÿ�� ����
//				default:
//					DisconnectSession(loginJob->sessionID);
//					break;
//				}
//
//				if (dbJob->packet != nullptr)
//					CPacket::Free(dbJob->packet);
//
//				dbJobPool.Free(dbJob);
//
//				InterlockedIncrement64(&m_jobThreadUpdateCnt);
//			}
//			PRO_END(L"Job Time");
//		}
//	}
//}

bool LoginServer::RedisJobWorkerThread_serv()
{
	DWORD threadID = GetCurrentThreadId();

	while (true)
	{
		// Redis Job Queue�� �۾��� Enqueue�Ǿ��ٴ� �̺�Ʈ�� �ñ׳θ��Ǹ� ���
		WaitForSingleObject(m_redisJobEvent, INFINITE);

		RedisJob* redisJob = nullptr;

		// Queue�� Job�� ���� ������ update ����
		while (redisJobQ.GetSize() > 0)
		{
			if (redisJobQ.Dequeue(redisJob))
			{
				PRO_BEGIN(L"Redis_Proc");
				RedisProc(redisJob);
				PRO_END(L"Redis_Proc");

				InterlockedIncrement64(&m_redisJobThreadUpdateTPS);
			}
		}
	}
}

void LoginServer::RedisProc(RedisJob* redisJob)
{
	// �񵿱� redis set��û
	mRedis->asyncSet(redisJob->accountNo, redisJob->sessionKey, 30, [=](const cpp_redis::reply& reply)
	{
		// redis set �Ϸ� �ݹ�
		if (reply.is_string() && reply.as_string() == "OK")
		{
			// ���� ���� ��, �α��� ���� ó���� ���� �۾��� Job Worker Thread�� �ѱ�
			LoginJob* job = jobPool.Alloc();
			job->sessionID = redisJob->sessionID;
			job->type = JobType::JOB_PACKET;
			job->packet = redisJob->packet;

			jobQ.Enqueue(job);
			SetEvent(m_jobEvent);

			redisJobPool.Free(redisJob);
		}
		else
		{
			// ���� ó��
			OnError(ErrorCode::REDISSETERROR, L"Redis Set failed!");
		}
	});
}

void LoginServer::PacketProc(uint64_t sessionID, CPacket* packet)
{
	WORD type;
	*packet >> type;

	switch (type)
	{
	case en_PACKET_CS_LOGIN_REQ_LOGIN:
		// �α��� ��û
		netPacketProc_ReqLogin(sessionID, packet);
		break;

	default:
		// �߸��� ��Ŷ
		loginLog->logger(dfLOG_LEVEL_ERROR, __LINE__, L"Packet Type Error > %d", type);
		DisconnectSession(sessionID);
		break;
	}
}

bool LoginServer::OnConnectionRequest(const wchar_t* IP, unsigned short PORT)
{
	return true;
}

void LoginServer::OnClientJoin(uint64_t sessionID)
{
	if (!startFlag)
	{
		ResumeThread(m_moniteringThread);
		startFlag = true;
	}

	// �α��� ������ accept
}

void LoginServer::OnClientLeave(uint64_t sessionID)
{
	//InterlockedIncrement64(&m_jobUpdatecnt);
}

void LoginServer::OnRecv(uint64_t sessionID, CPacket* packet)
{
	LoginJob* job = jobPool.Alloc();
	job->type = JobType::MSG_PACKET;
	job->sessionID = sessionID;
	job->packet = packet;

	jobQ.Enqueue(job);
	SetEvent(m_jobEvent);
}

void LoginServer::OnError(int errorCode, const wchar_t* msg)
{

}

// Network Logic ���κ��� timeout ó���� �߻��Ǹ� timeout Handler ȣ��
void LoginServer::OnTimeout(uint64_t sessionID)
{
	//LoginJob* job = jobPool.Alloc();
	//job->type = JobType::TIMEOUT;
	//job->sessionID = sessionID;
	//job->packet = nullptr;

	//jobQ.Enqueue(job);
	//InterlockedIncrement64(&m_jobUpdatecnt);
	//SetEvent(m_jobEvent);
}

// �α��� ��û - db ������ ���� �񵿱� �۵��ϵ��� �����ϱ�
void LoginServer::netPacketProc_ReqLogin(uint64_t sessionID, CPacket* packet)
{
	InterlockedIncrement64(&m_loginCount);
	InterlockedIncrement64(&m_loginTPS);

	// Packet ũ�⿡ ���� ���� ó�� 
	if (packet->GetDataSize() < sizeof(INT64) + MSGMAXLEN * sizeof(char))
	{
		int size = packet->GetDataSize() + sizeof(WORD);
		loginLog->logger(dfLOG_LEVEL_ERROR, __LINE__, L"Login Request Packet # size error :  %d", size);

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
		loginLog->logger(dfLOG_LEVEL_ERROR, __LINE__, L"Login Request Packet # account error :  %IId", _accountNo);
	
		DisconnectSession(sessionID);
	
		return;
	}
	
	// MSGMAXLEN�� 64
	char SessionKey[MSGMAXLEN + 1] = { 0 };
	wchar_t ID[20] = { 0 };
	wchar_t Nickname[20] = { 0 };
	wchar_t gameServerIp[16] = { 0 };
	USHORT gameServerPort = 0;
	
	// Redis�� ������ ������ū�� ������ȭ�ؼ� ����
	// ���� ���������� Dummy Client�� ������ū�� ���� ��û�� �ϱ� ������ �̸� �ŷ���
	packet->GetData((char*)SessionKey, MSGMAXLEN);
	
	SessionKey[MSGMAXLEN] = '\0';
	
	// ���� Ű ���� �ƹ��͵� ���� ���...
	if (SessionKey[0] == '\0')
	{
		loginLog->logger(dfLOG_LEVEL_ERROR, __LINE__, L"Login Request Packet # sessionKey is null");
		DisconnectSession(sessionID);
		return;
	}


	// ---------------------------------------------------------------------
	// �ܺ� �÷��� API�� �����Ͽ� ��ū�� ������ �۾��� ���ϰ� ū �۾�
	// �̷��� ���� ���ٵ� ������ �� �ִ��� �ľ��ϱ� ����
	// DB ������ ���� ����� ��Ȳ ���� (���ϰ� �ɸ��� �۾�)

	// DB ������ ���� �� ���� �Ű������� �����ϴ� ������ ��û
	// �Ű����� ���ε� �� ���� ��û / ���� ��� �ļ� ó��
	// 

	// ���� ��û ��, �ļ� ��� ó���� ���� �ڵ鷯 �Լ� ȣ��

	// -----------------------------------------------------------------
	// account ���̺� select
	// -----------------------------------------------------------------
	auto resultHandler = [&](MYSQL_STMT* stmt, Log* dbLog) -> bool {
		// select ���� �ش� ���� �÷� �� ���� (��� ����)
		char id[IDMAXLEN] = { 0 };
		char nickname[NICKNAMEMAXLEN] = { 0 };

		// ��� ��ġ �� ���ε�
		int fetchResult = dbConn->FetchResult(stmt, id, nickname);

		// ����
		if (fetchResult == -1)
		{
			dbLog->logger(dfLOG_LEVEL_ERROR, __LINE__, L"Result binding failed : %s", mysql_stmt_error(stmt));
			return false;
		}
		// ���̺� ���ڵ� ����
		else if (fetchResult == MYSQL_NO_DATA)
		{
			InterlockedIncrement64(&m_loginFailCount);
			InterlockedIncrement64(&m_loginFailTPS);

			// account ���̺� �ش� ���� ������ ����
			status = en_PACKET_CS_LOGIN_RES_LOGIN::dfLOGIN_STATUS_ACCOUNT_MISS;

			CPacket* resLoginPacket = CPacket::Alloc();

			mpResLogin(resLoginPacket, _accountNo, status, ID, Nickname, gameServerIp, gameServerPort, chatIP, chatPort);

			SendPacket(sessionID, resLoginPacket);

			CPacket::Free(resLoginPacket);

			return false;
		}
		// ���̺� ���ڵ� ����
		else if (fetchResult == 0)
		{
			// ���� ���� - ���� ����
			std::wstring idStr(id, id + strlen(id));
			std::wstring nicknameStr(nickname, nickname + strlen(nickname));

			wcscpy_s(ID, idStr.c_str());
			wcscpy_s(Nickname, nicknameStr.c_str());

			return true;
		}
		else
		{
			dbLog->logger(dfLOG_LEVEL_ERROR, __LINE__, L"Error fetching result: : %s", mysql_stmt_error(stmt));
			return false;
		}
	};

	// accountNo�� �ش��ϴ� account table ���� select
	std::wstring accountQuery = L"SELECT userid, usernick FROM accountdb.account WHERE accountno = ?";

	// �Ű����� ���ε� & ���� ��û
	if (!dbConn->ExecuteQuery(accountQuery.c_str(), resultHandler, _accountNo))
	{
		loginLog->logger(dfLOG_LEVEL_ERROR, __LINE__, L"Login Request Packet # query execution failed");
		return;
	}
	InterlockedIncrement64(&m_dbQueryTotal);
	InterlockedIncrement64(&m_dbQueryTPS);




	// -----------------------------------------------------------------
	// sessionkey ���̺� update
	// -----------------------------------------------------------------
	std::wstring updateQuery = L"UPDATE accountdb.sessionkey SET sessionkey = ? WHERE accountno = ?";
	std::string sessionKeyStr2(SessionKey);

	PRO_BEGIN(L"DB_SessionKey_Update");
	if (!dbConn->ExecuteQuery(updateQuery, nullptr, sessionKeyStr2, _accountNo))
	{
		loginLog->logger(dfLOG_LEVEL_ERROR, __LINE__, L"Failed to update sessionKey table");
		PRO_END(L"DB_SessionKey_Update");
		return;
	}

	PRO_END(L"DB_SessionKey_Update");
	InterlockedIncrement64(&m_dbQueryTotal);
	InterlockedIncrement64(&m_dbQueryTPS);



	// -----------------------------------------------------------------
	// status ���̺� select
	// -----------------------------------------------------------------
	auto resultHandler2 = [&](MYSQL_STMT* stmt, Log* dbLog) -> bool {
		int _status;

		int fetchResult = dbConn->FetchResult(stmt, _status);

		if (fetchResult == -1)
		{
			dbLog->logger(dfLOG_LEVEL_ERROR, __LINE__, L"Result binding failed : %s", mysql_stmt_error(stmt));
			return false;
		}
		// ���� ���� ��� - ���� ������ ����!
		else if (fetchResult == MYSQL_NO_DATA)
		{
			InterlockedIncrement64(&m_loginFailCount);
			InterlockedIncrement64(&m_loginFailTPS);

			status = en_PACKET_CS_LOGIN_RES_LOGIN::dfLOGIN_STATUS_STATUS_MISS;

			CPacket* resLoginPacket = CPacket::Alloc();

			mpResLogin(resLoginPacket, _accountNo, status, ID, Nickname, gameServerIp, gameServerPort, chatIP, chatPort);

			SendPacket(sessionID, resLoginPacket);

			CPacket::Free(resLoginPacket);

			return false;
		}
		// ���� ���� ��� - ���� ������ ����!
		else if (fetchResult == 0)
		{
			// ���� ����
			return true;
		}
	};

	// accountNo�� �ش��ϴ� status table ���� select
	std::wstring statusQuery = L"SELECT status FROM accountdb.status WHERE accountno = ?";

	PRO_BEGIN(L"DB_Status_Select");
	if (!dbConn->ExecuteQuery(statusQuery.c_str(), resultHandler2, &_accountNo))
	{
		loginLog->logger(dfLOG_LEVEL_ERROR, __LINE__, L"Login Request Packet # query execution failed");
		PRO_END(L"DB_Status_Select");
		return;
	}
	PRO_END(L"DB_Status_Select");

	InterlockedIncrement64(&m_dbQueryTotal);
	InterlockedIncrement64(&m_dbQueryTPS);



	// ------------------------------------------------------------------------
	// Redis�� ���� ��ū ���� ("accountNo", "sessionKey")
	// ------------------------------------------------------------------------
	std::string accountNoStr = std::to_string(_accountNo);
	std::string sessionKeyStr(SessionKey);

	// �񵿱�
	CPacket* resLoginPacket = CPacket::Alloc();

	mpResLogin(resLoginPacket, _accountNo, status, ID, Nickname, gameServerIp, gameServerPort, chatIP, chatPort);

	RedisJob* job = redisJobPool.Alloc();
	job->sessionID = sessionID;
	job->accountNo = accountNoStr;
	job->sessionKey = sessionKeyStr;
	job->packet = resLoginPacket;

	PRO_BEGIN(L"Redis_Queue_EQ");
	
	redisJobQ.Enqueue(job);
	
	PRO_END(L"Redis_Queue_EQ");

	SetEvent(m_redisJobEvent);


	////// ����
	////PRO_BEGIN(L"Redis_Sync");
	////// redis�� ���� ��ū ���� (30�� �Ŀ� ��ū ����) - ����
	////bool flag = redis_TLS->syncSet(accountNoStr, sessionKeyStr, 30);

	////PRO_END(L"Redis_Sync");

	//	// ����
	//PRO_BEGIN(L"Redis_Sync");

	//// redis�� ���� ��ū ���� (30�� �Ŀ� ��ū ����) - ����
	//bool flag = mRedis->syncSet(accountNoStr, sessionKeyStr, 30);

	//PRO_END(L"Redis_Sync");

	//InterlockedIncrement64(&m_redisJobThreadUpdateTPS);

	//if (!flag)
	//{
	//	// redis set ���� �� ���� ����
	//	status = en_PACKET_CS_LOGIN_RES_LOGIN::dfLOGIN_STATUS_NONE;
	//}

	//// account table�� �ִ� �����̹Ƿ� �α��� ���� & ���� ����
	//InterlockedIncrement64(&m_loginSuccessCount);
	//InterlockedIncrement64(&m_loginSuccessTPS);

	//CPacket* resLoginPacket = CPacket::Alloc();

	//mpResLogin(resLoginPacket, _accountNo, status, ID, Nickname, gameServerIp, gameServerPort, chatIP, chatPort);

	////// ������ ���� ��, 100ms �ڿ� �α��� �������� ������ ����
	////SendPacketAndDisconnect(sessionID, resLoginPacket, 100);

	//PRO_BEGIN(L"Login_SendPacket");
	//// �α��� ����
	//SendPacket(sessionID, resLoginPacket);
	//PRO_END(L"Login_SendPacket");

	//CPacket::Free(resLoginPacket);

	//PRO_END(L"Login");
}

//// �α��� ��û
//void LoginServer::netPacketProc_ReqLogin(uint64_t sessionID, CPacket* packet)
//{
//	InterlockedIncrement64(&m_loginCount);
//	InterlockedIncrement64(&m_loginTPS);
//
//	// Packet ũ�⿡ ���� ���� ó�� 
//	if (packet->GetDataSize() < sizeof(INT64) + MSG_MAX_LEN * sizeof(char))
//	{
//		int size = packet->GetDataSize() + sizeof(WORD);
//		loginLog->logger(dfLOG_LEVEL_ERROR, __LINE__, L"Login Request Packet # size error :  %d", size);
//
//		DisconnectSession(sessionID);
//
//		return;
//	}
//
//	INT64 _accountNo;
//
//	// �ʱ� ���� - ����
//	BYTE status = en_PACKET_CS_LOGIN_RES_LOGIN::dfLOGIN_STATUS_OK;
//
//	// accountNo�� ������ȭ�ؼ� ����
//	*packet >> _accountNo;
//
//	if (_accountNo <= 0)
//	{
//		loginLog->logger(dfLOG_LEVEL_ERROR, __LINE__, L"Login Request Packet # account error :  %IId", _accountNo);
//
//		DisconnectSession(sessionID);
//
//		return;
//	}
//
//	char SessionKey[65];
//	wchar_t ID[20];
//	wchar_t Nickname[20];
//	wchar_t gameServerIp[16];
//	USHORT gameServerPort = 0;
//
//	packet->GetData((char*)ID, ID_MAX_LEN * sizeof(wchar_t));
//	packet->GetData((char*)Nickname, NICKNAME_MAX_LEN * sizeof(wchar_t));
//
//	// Redis�� ������ ������ū�� ������ȭ�ؼ� ����
//	// ���� ���������� Dummy Client�� ������ū�� ���� ��û�� �ϱ� ������ �̸� �ŷ���
//	packet->GetData((char*)SessionKey, MSG_MAX_LEN);
//
//	SessionKey[MSG_MAX_LEN] = L'\0';
//
//	if (strcmp(SessionKey, '\0') == 0)
//	{
//		loginLog->logger(dfLOG_LEVEL_ERROR, __LINE__, L"Login Request Packet # sessionKey is null");
//		DisconnectSession(sessionID);
//		return;
//	}
//
//	// ---------------------------------------------------------------------
//	// DB �񵿱� ó��
//	// �ܺ� �÷��� API�� �����Ͽ� ��ū�� ������ �۾��� ���ϰ� ū �۾�
//	// �̷��� ���� ���ٵ� ������ �� �ִ��� �ľ��ϱ� ����
//	// DB ������ ���� ����� ��Ȳ ���� (���ϰ� �ɸ��� �۾�)
//
//	//DBJob* dbJob = dbJobPool.Alloc();
//	//dbJob->type = JobType::DB_SELECT;
//	//dbJob->sessionID = sessionID;
//	//dbJob->accountNo = _accountNo;
//	//memcpy_s(dbJob->sessionKey, MSG_MAX_LEN, SessionKey, MSG_MAX_LEN);
//
//	//dbJobQ.Enqueue(dbJob);
//	//SetEvent(m_dbJobEvent);
//
//	PRO_BEGIN(L"DB");
//
//	// account table�� accountNo�� �ش��ϴ� row�� �ִ��� select query ��û
//	std::wstring query = L"select * from accountdb.account where accountno=";
//	query += std::to_wstring(_accountNo);
//	query += L";";
//
//	PRO_BEGIN(L"DB_Select_Account");
//	int queryRet = dbConn->Query(query.c_str());
//	PRO_END(L"DB_Select_Account");
//
//	// ���� ����
//	if (queryRet < -1)
//	{
//		loginLog->logger(dfLOG_LEVEL_ERROR, __LINE__, L"Login Request Packet # account select query fail");
//
//		return;
//	}
//	// account table�� accountNo ���� -> ��û ���п� ���� ���� ����
//	else if (queryRet == 0)
//	{
//		dbConn->FreeResult();
//
//		InterlockedIncrement64(&m_loginFailCount);
//		InterlockedIncrement64(&m_loginFailTPS);
//
//		status = en_PACKET_CS_LOGIN_RES_LOGIN::dfLOGIN_STATUS_ACCOUNT_MISS;
//
//		CPacket* resLoginPacket = CPacket::Alloc();
//
//		mpResLogin(resLoginPacket, _accountNo, status, ID, Nickname, gameServerIp, gameServerPort, chatIP, chatPort);
//
//		//SendPacketAndDisconnect(sessionID, resLoginPacket, 100);
//		SendPacket(sessionID, resLoginPacket);
//
//		CPacket::Free(resLoginPacket);
//
//		return;
//	}
//
//	// -----------------------------------------------------------
//	// ���� ����
//	// -----------------------------------------------------------
//
//	InterlockedIncrement64(&m_dbQueryTotal);
//	InterlockedIncrement64(&m_dbQueryTPS);
//
//	// result[1] : id
//	// resultRow[3] : nickname
//
//	// select ���� ���� ��, �ش� row�� ����
//	MYSQL_ROW resultRow = dbConn->FetchRow();
//
//	// resultRow[1]�� wideLen
//	int wideCharLen = MultiByteToWideChar(CP_UTF8, 0, resultRow[1], strlen(resultRow[1]), 0, 0);
//	if (wideCharLen > ID_MAX_LEN)
//	{
//		loginLog->logger(dfLOG_LEVEL_ERROR, __LINE__, L"Login Request Packet # Multibyte To WideChar error > result[1] is too much size");
//		dbConn->FreeResult();
//
//		return;
//	}
//
//	MultiByteToWideChar(CP_UTF8, 0, resultRow[1], strlen(resultRow[1]), ID, wideCharLen * sizeof(wchar_t));
//	ID[wideCharLen] = L'\0';
//
//	// resultRow[3]�� wideLen
//	wideCharLen = MultiByteToWideChar(CP_UTF8, 0, resultRow[3], strlen(resultRow[3]), 0, 0);
//	if (wideCharLen > NICKNAME_MAX_LEN)
//	{
//		loginLog->logger(dfLOG_LEVEL_ERROR, __LINE__, L"Login Request Packet # Multibyte To WideChar error > result[3] is too much size");
//		dbConn->FreeResult();
//
//		return;
//	}
//
//	MultiByteToWideChar(CP_UTF8, 0, resultRow[3], strlen(resultRow[3]), Nickname, wideCharLen * sizeof(wchar_t));
//	Nickname[wideCharLen] = L'\0';
//
//	dbConn->FreeResult();
//
//
//	// accountNo�� �ش��ϴ� sessionKey table ���� select
//	query = L"select sessionkey from accountdb.sessionkey where accountno=";
//	query += std::to_wstring(_accountNo);
//	query += L";";
//
//	PRO_BEGIN(L"DB_Select_Session");
//	queryRet = dbConn->Query(query.c_str());
//	PRO_END(L"DB_Select_Session");
//
//	if (queryRet == -1)
//	{
//		loginLog->logger(dfLOG_LEVEL_ERROR, __LINE__, L"Login Request Packet # sessionkey select query fail");
//
//		return;
//	}
//	else if (queryRet == 0)
//	{
//		dbConn->FreeResult();
//
//		InterlockedIncrement64(&m_loginFailCount);
//		InterlockedIncrement64(&m_loginFailTPS);
//
//		status = en_PACKET_CS_LOGIN_RES_LOGIN::dfLOGIN_STATUS_SESSION_MISS;
//
//		CPacket* resLoginPacket = CPacket::Alloc();
//
//		mpResLogin(resLoginPacket, _accountNo, status, ID, Nickname, gameServerIp, gameServerPort, chatIP, chatPort);
//
//		//SendPacketAndDisconnect(sessionID, resLoginPacket, 100);
//		SendPacket(sessionID, resLoginPacket);
//
//		CPacket::Free(resLoginPacket);
//
//		return;
//	}
//
//	InterlockedIncrement64(&m_dbQueryTotal);
//	InterlockedIncrement64(&m_dbQueryTPS);
//
//	dbConn->FreeResult();
//
//	// accountNo�� �ش��ϴ� status table ���� select
//	query = L"select status from accountdb.status where accountno=";
//	query += std::to_wstring(_accountNo);
//	query += L";";
//
//	PRO_BEGIN(L"DB_Select_Status");
//	queryRet = dbConn->Query(query.c_str());
//	PRO_END(L"DB_Select_Status");
//
//	if (queryRet == -1)
//	{
//		loginLog->logger(dfLOG_LEVEL_ERROR, __LINE__, L"Login Request Packet # status select query fail");
//		return;
//	}
//	else if (queryRet == 0)
//	{
//		dbConn->FreeResult();
//
//		InterlockedIncrement64(&m_loginFailCount);
//		InterlockedIncrement64(&m_loginFailTPS);
//
//		status = en_PACKET_CS_LOGIN_RES_LOGIN::dfLOGIN_STATUS_STATUS_MISS;
//
//		CPacket* resLoginPacket = CPacket::Alloc();
//
//		mpResLogin(resLoginPacket, _accountNo, status, ID, Nickname, gameServerIp, gameServerPort, chatIP, chatPort);
//
//		//SendPacketAndDisconnect(sessionID, resLoginPacket, 100);
//		SendPacket(sessionID, resLoginPacket);
//
//		CPacket::Free(resLoginPacket);
//
//		return;
//	}
//
//	InterlockedIncrement64(&m_dbQueryTotal);
//	InterlockedIncrement64(&m_dbQueryTPS);
//
//	dbConn->FreeResult();
//
//	PRO_END(L"DB");
//
//	std::string accountNoStr = std::to_string(_accountNo);
//	std::string sessionKeyStr;
//	sessionKeyStr.assign(SessionKey);
//
//	// ------------------------------------------------------------------------
//	// Redis�� ���� ��ū ���� ("accountNo", "sessionKey") - Redis Update Thread�� �۾� �ѱ� (�񵿱�)
//	// ------------------------------------------------------------------------
//	CPacket* resLoginPacket = CPacket::Alloc();
//
//	// �α��� ����� ��Ŷ ���� �Լ�
//	mpResLogin(resLoginPacket, _accountNo, status, ID, Nickname, gameServerIp, gameServerPort, chatIP, chatPort);
//
//	RedisJob* job = redisJobPool.Alloc();
//	job->sessionID = sessionID;
//	job->accountNo = accountNoStr;
//	job->sessionKey = sessionKeyStr;
//	job->packet = resLoginPacket;
//
//	PRO_BEGIN(L"RedisEq");
//	redisJobQ.Enqueue(job);
//	PRO_END(L"RedisEq");
//
//	SetEvent(m_redisJobEvent);
//
//
//	//// redis�� ���� ��ū ���� (30�� �Ŀ� ��ū ����) - ����
//	//bool flag = mRedis->syncSet(accountNoStr, sessionKeyStr, 30);
//	//InterlockedIncrement64(&m_redisJobThreadUpdateTPS);
//
//	//if (!flag)
//	//{
//	//	// redis set ���� �� ���� ����
//	//	status = en_PACKET_CS_LOGIN_RES_LOGIN::dfLOGIN_STATUS_NONE;
//	//}
//
//	//// account table�� �ִ� �����̹Ƿ� �α��� ���� & ���� ����
//	//InterlockedIncrement64(&m_loginSuccessCount);
//	//InterlockedIncrement64(&m_loginSuccessTPS);
//
//	//CPacket* resLoginPacket = CPacket::Alloc();
//
//	//mpResLogin(resLoginPacket, _accountNo, status, ID, Nickname, gameServerIp, gameServerPort, chatIP, chatPort);
//
//	////// ������ ���� ��, 100ms �ڿ� �α��� �������� ������ ����
//	////SendPacketAndDisconnect(sessionID, resLoginPacket, 100);
//
//	//// �α��� ����
//	//SendPacket(sessionID, resLoginPacket);
//
//	//CPacket::Free(resLoginPacket);
//}

// �񵿱� redis ��û ����� ���� ��, ���� �α��� job ó��
void LoginServer::netPacketProc_ResLogin(uint64_t sessionID, CPacket* packet)
{
	// account table�� �ִ� �����̹Ƿ� �α��� ���� & ���� ����
	InterlockedIncrement64(&m_loginSuccessCount);
	InterlockedIncrement64(&m_loginSuccessTPS);

	//// ������ ���� ��, 100ms �ڿ� �α��� �������� ������ ����
	//SendPacketAndDisconnect(sessionID, packet, 100);
	
	// �α��� ����
	SendPacket(sessionID, packet);
}