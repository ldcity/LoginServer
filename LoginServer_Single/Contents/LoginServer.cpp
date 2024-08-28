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

	// login server 설정파일을 Parsing하여 읽어옴
	TextParser loginServerInfoTxt;

	const wchar_t* txtName = L"LoginServer.txt";
	loginServerInfoTxt.LoadFile(txtName);

	// DB 관련 변수
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

	// DBConnector 객체 생성 및 DB 연결
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


	g_endEvent = CreateEvent(NULL, TRUE, FALSE, NULL); // 수동 리셋 이벤트 생성

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
		// 1초마다 모니터링 -> 타임아웃 건도 처리
		DWORD ret = WaitForMultipleObjects(2, events, FALSE, 1000);

		//// 1초마다 모니터링 -> 타임아웃 건도 처리
		//DWORD ret = WaitForSingleObject(m_moniterEvent, 1000);

		if (ret == WAIT_TIMEOUT)
		{
			// 모니터링 서버 전송용 데이터
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
			
			// 모니터링 서버로 데이터 전송
			int iTime = (int)time(NULL);
			BYTE serverNo = SERVERTYPE::LOGIN_SERVER_TYPE;

			// LoginServer 실행 여부 ON / OFF
			CPacket* onPacket = CPacket::Alloc();
			lanClient.mpUpdateDataToMonitorServer(serverNo, MONITOR_DATA_TYPE_LOGIN_SERVER_RUN, true, iTime, onPacket);
			lanClient.SendPacket(onPacket);
			CPacket::Free(onPacket);

			// LoginServer CPU 사용률
			CPacket* cpuPacket = CPacket::Alloc();
			lanClient.mpUpdateDataToMonitorServer(serverNo, MONITOR_DATA_TYPE_LOGIN_SERVER_CPU, (int)performMoniter.GetProcessCpuTotal(), iTime, cpuPacket);
			lanClient.SendPacket(cpuPacket);
			CPacket::Free(cpuPacket);

			// LoginServer 메모리 사용 MByte
			CPacket* memoryPacket = CPacket::Alloc();
			lanClient.mpUpdateDataToMonitorServer(serverNo, MONITOR_DATA_TYPE_LOGIN_SERVER_MEM, (int)performMoniter.GetProcessUserMemoryByMB(), iTime, memoryPacket);
			lanClient.SendPacket(memoryPacket);
			CPacket::Free(memoryPacket);

			// LoginServer 세션 수 (컨넥션 수)
			CPacket* sessionPacket = CPacket::Alloc();
			lanClient.mpUpdateDataToMonitorServer(serverNo, MONITOR_DATA_TYPE_LOGIN_SESSION, (int)iSessionCnt, iTime, sessionPacket);
			lanClient.SendPacket(sessionPacket);
			CPacket::Free(sessionPacket);

			// LoginServer 인증 처리 초당 횟수
			CPacket* authPacket = CPacket::Alloc();
			lanClient.mpUpdateDataToMonitorServer(serverNo, MONITOR_DATA_TYPE_LOGIN_AUTH_TPS, (int)iAuthCnt, iTime, authPacket);
			lanClient.SendPacket(authPacket);
			CPacket::Free(authPacket);

			// LoginServer 패킷풀 사용량
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
			// 'y' 키 입력 이벤트가 발생하면 프로파일링 데이터 저장
			SaveProfilingData();
			wprintf(L"################################# Save Profiling Text #################################\n");
			ResetEvent(g_endEvent); // 이벤트 리셋
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
//		// JobQ에 Job이 삽입되면 이벤트 발생하여 깨어남
//		WaitForSingleObject(m_jobEvent, INFINITE);
//
//		LoginJob* loginJob = nullptr;
//
//		// Job이 없을 때까지 update 반복
//		while (loginJobQ.GetSize() > 0)
//		{
//			PRO_BEGIN(L"Job_Queue");
//			if (loginJobQ.Dequeue(loginJob))
//			{
//				// Job Type에 따른 분기 처리
//				switch (loginJob->type)
//				{
//				case JobType::MSG_PACKET:
//					PacketProc(loginJob->sessionID, loginJob->packet);	// 패킷 처리
//					break;
//
//				case JobType::REDIS_RES:
//					PRO_BEGIN(L"Login_Res");
//					// 비동기 로그인 요청 결과 처리
//					netPacketProc_ResLoginRedis(loginJob->sessionID, loginJob->packet);
//					PRO_END(L"Login_Res");
//					break;
//
//				case JobType::TIMEOUT:
//					// 세션 타임아웃
//					DisconnectSession(loginJob->sessionID);
//					break;
//
//				default:
//					DisconnectSession(loginJob->sessionID);
//					break;
//				}
//
//				// 접속, 해제 Job은 packet이 nullptr이기 때문에 반환할 Packet이 없음
//				if (loginJob->packet != nullptr)
//					CPacket::Free(loginJob->packet);
//
//				// JobPool에 Job 객체 반환
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
		// Handler Job Queue에 작업이 Enqueue되었다는 이벤트가 시그널링되면 깨어남
		WaitForSingleObject(m_jobEvent, INFINITE);

		LoginJob* loginJob = nullptr;

		// Queue에 Job이 없을 때까지 update 수행
		while (jobQ.GetSize() > 0)
		{
			PRO_BEGIN(L"Job Time");
			if (jobQ.Dequeue(loginJob))
			{
				// Job Type에 따른 분기 처리
				switch (loginJob->type)
				{
				// 수신 패킷 처리
				case JobType::MSG_PACKET:
					PRO_BEGIN(L"Login_Request");
					PacketProc(loginJob->sessionID, loginJob->packet);	
					PRO_END(L"Login_Request");
					break;

				// 컨텐츠에서 발생한 패킷 처리
				case JobType::JOB_PACKET:
					PRO_BEGIN(L"Login_Response");
					netPacketProc_ResLogin(loginJob->sessionID, loginJob->packet);
					PRO_END(L"Login_Response");
					break;

				// 세션 타임아웃
				case JobType::TIMEOUT:
					DisconnectSession(loginJob->sessionID);
					break;
				
				// 패킷 타입 에러
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
//		// DB Job Queue에 작업이 Enqueue되었다는 이벤트가 시그널링되면 깨어남
//		WaitForSingleObject(m_dbJobEvent, INFINITE);
//
//		DBJob* dbJob = nullptr;
//
//		// Queue에 Job이 없을 때까지 update 수행
//		while (dbJobQ.GetSize() > 0)
//		{
//			PRO_BEGIN(L"DB Job Time");
//			if (dbJobQ.Dequeue(dbJob))
//			{
//				// Job Type에 따른 분기 처리
//				switch (dbJob->type)
//				{
//					// 수신 패킷 처리
//				case JobType::MSG_PACKET:
//					PacketProc(loginJob->sessionID, loginJob->packet);
//					break;
//
//					// 세션 타임아웃
//				case JobType::TIMEOUT:
//					DisconnectSession(loginJob->sessionID);
//					break;
//
//					// 패킷 타입 에러
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
		// Redis Job Queue에 작업이 Enqueue되었다는 이벤트가 시그널링되면 깨어남
		WaitForSingleObject(m_redisJobEvent, INFINITE);

		RedisJob* redisJob = nullptr;

		// Queue에 Job이 없을 때까지 update 수행
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
	// 비동기 redis set요청
	mRedis->asyncSet(redisJob->accountNo, redisJob->sessionKey, 30, [=](const cpp_redis::reply& reply)
	{
		// redis set 완료 콜백
		if (reply.is_string() && reply.as_string() == "OK")
		{
			// 저장 성공 시, 로그인 응답 처리에 대한 작업을 Job Worker Thread로 넘김
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
			// 실패 처리
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
		// 로그인 요청
		netPacketProc_ReqLogin(sessionID, packet);
		break;

	default:
		// 잘못된 패킷
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

	// 로그인 서버에 accept
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

// Network Logic 으로부터 timeout 처리가 발생되면 timeout Handler 호출
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

// 로그인 요청 - db 스레드 빼서 비동기 작동하도록 수정하기
void LoginServer::netPacketProc_ReqLogin(uint64_t sessionID, CPacket* packet)
{
	InterlockedIncrement64(&m_loginCount);
	InterlockedIncrement64(&m_loginTPS);

	// Packet 크기에 대한 예외 처리 
	if (packet->GetDataSize() < sizeof(INT64) + MSGMAXLEN * sizeof(char))
	{
		int size = packet->GetDataSize() + sizeof(WORD);
		loginLog->logger(dfLOG_LEVEL_ERROR, __LINE__, L"Login Request Packet # size error :  %d", size);

		DisconnectSession(sessionID);

		return;
	}

	INT64 _accountNo;
	
	// 초기 상태 - 성공
	BYTE status = en_PACKET_CS_LOGIN_RES_LOGIN::dfLOGIN_STATUS_OK;
	
	// accountNo를 역직렬화해서 얻어옴
	*packet >> _accountNo;
	
	// 잘못된 계정 번호 - 연결 끊기
	if (_accountNo <= 0)
	{
		loginLog->logger(dfLOG_LEVEL_ERROR, __LINE__, L"Login Request Packet # account error :  %IId", _accountNo);
	
		DisconnectSession(sessionID);
	
		return;
	}
	
	// MSGMAXLEN는 64
	char SessionKey[MSGMAXLEN + 1] = { 0 };
	wchar_t ID[20] = { 0 };
	wchar_t Nickname[20] = { 0 };
	wchar_t gameServerIp[16] = { 0 };
	USHORT gameServerPort = 0;
	
	// Redis에 저장할 인증토큰을 역직렬화해서 얻어옴
	// 현재 로직에서는 Dummy Client가 인증토큰을 갖고 요청을 하기 때문에 이를 신뢰함
	packet->GetData((char*)SessionKey, MSGMAXLEN);
	
	SessionKey[MSGMAXLEN] = '\0';
	
	// 세션 키 값이 아무것도 없는 경우...
	if (SessionKey[0] == '\0')
	{
		loginLog->logger(dfLOG_LEVEL_ERROR, __LINE__, L"Login Request Packet # sessionKey is null");
		DisconnectSession(sessionID);
		return;
	}


	// ---------------------------------------------------------------------
	// 외부 플랫폼 API에 접근하여 토큰을 얻어오는 작업은 부하가 큰 작업
	// 이러한 느린 접근도 대응할 수 있는지 파악하기 위해
	// DB 접근을 통한 비슷한 상황 유도 (부하가 걸리는 작업)

	// DB 인젝션 공격 방어를 위해 매개변수를 주입하는 쿼리문 요청
	// 매개변수 바인딩 및 쿼리 요청 / 이후 결과 후속 처리
	// 

	// 쿼리 요청 후, 후속 결과 처리를 위한 핸들러 함수 호출

	// -----------------------------------------------------------------
	// account 테이블 select
	// -----------------------------------------------------------------
	auto resultHandler = [&](MYSQL_STMT* stmt, Log* dbLog) -> bool {
		// select 이후 해당 행의 컬럼 값 추출 (결과 버퍼)
		char id[IDMAXLEN] = { 0 };
		char nickname[NICKNAMEMAXLEN] = { 0 };

		// 결과 패치 및 바인딩
		int fetchResult = dbConn->FetchResult(stmt, id, nickname);

		// 실패
		if (fetchResult == -1)
		{
			dbLog->logger(dfLOG_LEVEL_ERROR, __LINE__, L"Result binding failed : %s", mysql_stmt_error(stmt));
			return false;
		}
		// 테이블에 레코드 없음
		else if (fetchResult == MYSQL_NO_DATA)
		{
			InterlockedIncrement64(&m_loginFailCount);
			InterlockedIncrement64(&m_loginFailTPS);

			// account 테이블에 해당 계정 정보가 없음
			status = en_PACKET_CS_LOGIN_RES_LOGIN::dfLOGIN_STATUS_ACCOUNT_MISS;

			CPacket* resLoginPacket = CPacket::Alloc();

			mpResLogin(resLoginPacket, _accountNo, status, ID, Nickname, gameServerIp, gameServerPort, chatIP, chatPort);

			SendPacket(sessionID, resLoginPacket);

			CPacket::Free(resLoginPacket);

			return false;
		}
		// 테이블에 레코드 있음
		else if (fetchResult == 0)
		{
			// 쿼리 성공 - 정보 추출
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

	// accountNo에 해당하는 account table 정보 select
	std::wstring accountQuery = L"SELECT userid, usernick FROM accountdb.account WHERE accountno = ?";

	// 매개변수 바인딩 & 쿼리 요청
	if (!dbConn->ExecuteQuery(accountQuery.c_str(), resultHandler, _accountNo))
	{
		loginLog->logger(dfLOG_LEVEL_ERROR, __LINE__, L"Login Request Packet # query execution failed");
		return;
	}
	InterlockedIncrement64(&m_dbQueryTotal);
	InterlockedIncrement64(&m_dbQueryTPS);




	// -----------------------------------------------------------------
	// sessionkey 테이블 update
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
	// status 테이블 select
	// -----------------------------------------------------------------
	auto resultHandler2 = [&](MYSQL_STMT* stmt, Log* dbLog) -> bool {
		int _status;

		int fetchResult = dbConn->FetchResult(stmt, _status);

		if (fetchResult == -1)
		{
			dbLog->logger(dfLOG_LEVEL_ERROR, __LINE__, L"Result binding failed : %s", mysql_stmt_error(stmt));
			return false;
		}
		// 행이 없을 경우 - 계정 정보가 없음!
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
		// 행이 있을 경우 - 계정 정보가 있음!
		else if (fetchResult == 0)
		{
			// 쿼리 성공
			return true;
		}
	};

	// accountNo에 해당하는 status table 정보 select
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
	// Redis에 인증 토큰 저장 ("accountNo", "sessionKey")
	// ------------------------------------------------------------------------
	std::string accountNoStr = std::to_string(_accountNo);
	std::string sessionKeyStr(SessionKey);

	// 비동기
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


	////// 동기
	////PRO_BEGIN(L"Redis_Sync");
	////// redis에 인증 토큰 저장 (30초 후에 토큰 만료) - 동기
	////bool flag = redis_TLS->syncSet(accountNoStr, sessionKeyStr, 30);

	////PRO_END(L"Redis_Sync");

	//	// 동기
	//PRO_BEGIN(L"Redis_Sync");

	//// redis에 인증 토큰 저장 (30초 후에 토큰 만료) - 동기
	//bool flag = mRedis->syncSet(accountNoStr, sessionKeyStr, 30);

	//PRO_END(L"Redis_Sync");

	//InterlockedIncrement64(&m_redisJobThreadUpdateTPS);

	//if (!flag)
	//{
	//	// redis set 실패 시 실패 상태
	//	status = en_PACKET_CS_LOGIN_RES_LOGIN::dfLOGIN_STATUS_NONE;
	//}

	//// account table에 있는 정보이므로 로그인 성공 & 인증 성공
	//InterlockedIncrement64(&m_loginSuccessCount);
	//InterlockedIncrement64(&m_loginSuccessTPS);

	//CPacket* resLoginPacket = CPacket::Alloc();

	//mpResLogin(resLoginPacket, _accountNo, status, ID, Nickname, gameServerIp, gameServerPort, chatIP, chatPort);

	////// 응답을 보낸 뒤, 100ms 뒤에 로그인 서버와의 연결을 끊음
	////SendPacketAndDisconnect(sessionID, resLoginPacket, 100);

	//PRO_BEGIN(L"Login_SendPacket");
	//// 로그인 응답
	//SendPacket(sessionID, resLoginPacket);
	//PRO_END(L"Login_SendPacket");

	//CPacket::Free(resLoginPacket);

	//PRO_END(L"Login");
}

//// 로그인 요청
//void LoginServer::netPacketProc_ReqLogin(uint64_t sessionID, CPacket* packet)
//{
//	InterlockedIncrement64(&m_loginCount);
//	InterlockedIncrement64(&m_loginTPS);
//
//	// Packet 크기에 대한 예외 처리 
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
//	// 초기 상태 - 성공
//	BYTE status = en_PACKET_CS_LOGIN_RES_LOGIN::dfLOGIN_STATUS_OK;
//
//	// accountNo를 역직렬화해서 얻어옴
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
//	// Redis에 저장할 인증토큰을 역직렬화해서 얻어옴
//	// 현재 로직에서는 Dummy Client가 인증토큰을 갖고 요청을 하기 때문에 이를 신뢰함
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
//	// DB 비동기 처리
//	// 외부 플랫폼 API에 접근하여 토큰을 얻어오는 작업은 부하가 큰 작업
//	// 이러한 느린 접근도 대응할 수 있는지 파악하기 위해
//	// DB 접근을 통한 비슷한 상황 유도 (부하가 걸리는 작업)
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
//	// account table에 accountNo에 해당하는 row가 있는지 select query 요청
//	std::wstring query = L"select * from accountdb.account where accountno=";
//	query += std::to_wstring(_accountNo);
//	query += L";";
//
//	PRO_BEGIN(L"DB_Select_Account");
//	int queryRet = dbConn->Query(query.c_str());
//	PRO_END(L"DB_Select_Account");
//
//	// 쿼리 실패
//	if (queryRet < -1)
//	{
//		loginLog->logger(dfLOG_LEVEL_ERROR, __LINE__, L"Login Request Packet # account select query fail");
//
//		return;
//	}
//	// account table에 accountNo 없음 -> 요청 실패에 대한 응답 전송
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
//	// 쿼리 성공
//	// -----------------------------------------------------------
//
//	InterlockedIncrement64(&m_dbQueryTotal);
//	InterlockedIncrement64(&m_dbQueryTPS);
//
//	// result[1] : id
//	// resultRow[3] : nickname
//
//	// select 쿼리 성공 시, 해당 row를 얻어옴
//	MYSQL_ROW resultRow = dbConn->FetchRow();
//
//	// resultRow[1]의 wideLen
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
//	// resultRow[3]의 wideLen
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
//	// accountNo에 해당하는 sessionKey table 정보 select
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
//	// accountNo에 해당하는 status table 정보 select
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
//	// Redis에 인증 토큰 저장 ("accountNo", "sessionKey") - Redis Update Thread에 작업 넘김 (비동기)
//	// ------------------------------------------------------------------------
//	CPacket* resLoginPacket = CPacket::Alloc();
//
//	// 로그인 응답용 패킷 생성 함수
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
//	//// redis에 인증 토큰 저장 (30초 후에 토큰 만료) - 동기
//	//bool flag = mRedis->syncSet(accountNoStr, sessionKeyStr, 30);
//	//InterlockedIncrement64(&m_redisJobThreadUpdateTPS);
//
//	//if (!flag)
//	//{
//	//	// redis set 실패 시 실패 상태
//	//	status = en_PACKET_CS_LOGIN_RES_LOGIN::dfLOGIN_STATUS_NONE;
//	//}
//
//	//// account table에 있는 정보이므로 로그인 성공 & 인증 성공
//	//InterlockedIncrement64(&m_loginSuccessCount);
//	//InterlockedIncrement64(&m_loginSuccessTPS);
//
//	//CPacket* resLoginPacket = CPacket::Alloc();
//
//	//mpResLogin(resLoginPacket, _accountNo, status, ID, Nickname, gameServerIp, gameServerPort, chatIP, chatPort);
//
//	////// 응답을 보낸 뒤, 100ms 뒤에 로그인 서버와의 연결을 끊음
//	////SendPacketAndDisconnect(sessionID, resLoginPacket, 100);
//
//	//// 로그인 응답
//	//SendPacket(sessionID, resLoginPacket);
//
//	//CPacket::Free(resLoginPacket);
//}

// 비동기 redis 요청 결과를 얻은 뒤, 이후 로그인 job 처리
void LoginServer::netPacketProc_ResLogin(uint64_t sessionID, CPacket* packet)
{
	// account table에 있는 정보이므로 로그인 성공 & 인증 성공
	InterlockedIncrement64(&m_loginSuccessCount);
	InterlockedIncrement64(&m_loginSuccessTPS);

	//// 응답을 보낸 뒤, 100ms 뒤에 로그인 서버와의 연결을 끊음
	//SendPacketAndDisconnect(sessionID, packet, 100);
	
	// 로그인 응답
	SendPacket(sessionID, packet);
}