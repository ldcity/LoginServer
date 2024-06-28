#include "../PCH.h"

DWORD LoginServer::_DBTlsIdx = TlsAlloc();

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
	mysql_library_init(0, NULL, NULL); // MySQL 라이브러리 초기화

	loginLog = new Log(L"LoginLog");

	// login server 설정파일을 Parsing하여 읽어옴
	TextParser loginServerInfoTxt;

	const wchar_t* txtName = L"LoginServer.txt";
	loginServerInfoTxt.LoadFile(txtName);

	loginServerInfoTxt.GetValue(L"DB.HOST", host);
	loginServerInfoTxt.GetValue(L"DB.USER", user);
	loginServerInfoTxt.GetValue(L"DB.PASSWORD", password);
	loginServerInfoTxt.GetValue(L"DB.DBNAME", dbName);
	loginServerInfoTxt.GetValue(L"DB.PORT", &dbPort);

	int port;

	//// DBConnector_TLS 객체 생성
	//dbConn_TLS = new DBConnector_TLS(host, user, password, dbName, port, true);

	loginServerInfoTxt.GetValue(L"CHATSERVER.BIND_IP", chatIP);
	loginServerInfoTxt.GetValue(L"CHATSERVER.BIND_PORT", &chatPort);

	wchar_t ip[20];

	loginServerInfoTxt.GetValue(L"LOGINSERVER.BIND_IP", ip);
	loginServerInfoTxt.GetValue(L"LOGINSERVER.BIND_PORT", &port);

	m_tempIp = ip;
	int len = WideCharToMultiByte(CP_UTF8, 0, m_tempIp.c_str(), -1, NULL, 0, NULL, NULL);
	std::string result(len - 1, '\0');
	WideCharToMultiByte(CP_UTF8, 0, m_tempIp.c_str(), -1, &result[0], len, NULL, NULL);
	m_ip = result;

	performMoniter.AddInterface(m_ip);

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

	// 스레드별 MySQL 초기화
	for (int i = 0; i < workerThread; ++i)
	{
		mysql_thread_init(); // 스레드별 MySQL 초기화
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
	m_redisJobEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
	if (m_redisJobEvent == NULL)
	{
		int eventError = WSAGetLastError();
		loginLog->logger(dfLOG_LEVEL_ERROR, __LINE__, L"CreateEvent() Error : %d", eventError);

		return false;
	}
 
	// Monitering Thread
	m_moniteringThread = (HANDLE)_beginthreadex(NULL, 0, MoniteringThread, this, CREATE_SUSPENDED, NULL);
	if (m_moniteringThread == NULL)
	{
		int threadError = GetLastError();
		loginLog->logger(dfLOG_LEVEL_ERROR, __LINE__, L"_beginthreadex() Error : %d", threadError);

		return false;
	}

	// Redis Job Worker Thread
	m_redisJobHandle = (HANDLE)_beginthreadex(NULL, 0, RedisJobWorkerThread, this, 0, NULL);
	if (m_redisJobHandle == NULL)
	{
		int threadError = GetLastError();
		loginLog->logger(dfLOG_LEVEL_ERROR, __LINE__, L"_beginthreadex() Error : %d", threadError);

		return false;
	}

	WaitForSingleObject(m_moniteringThread, INFINITE);
	WaitForSingleObject(m_redisJobHandle, INFINITE);

	return true;
}

bool LoginServer::LoginServerStop()
{
	loginLog->~Log();
	logger->~Log();

	DBConnector* dbConn;

	// 리소스 정리 작업을 위해 필요한 LockFreeStack에서 DBConnector 객체 pop
	while (tlsDBObjects.Pop(&dbConn))
		delete dbConn;

	TlsFree(_DBTlsIdx);

	delete mRedis;

	CloseHandle(m_moniteringThread);
	CloseHandle(m_moniterEvent);
	CloseHandle(m_runEvent);

	CloseHandle(m_redisJobEvent);
	CloseHandle(m_redisJobHandle);

	mysql_library_end(); // MySQL 라이브러리 종료

	return true;
}


// Monitering Thread
bool LoginServer::MoniterThread_serv()
{
	DWORD threadID = GetCurrentThreadId();

	//logger->logger(dfLOG_LEVEL_DEBUG, __LINE__, L"MoniteringThread[%d] Start...", threadID);

	while (true)
	{
		// 1초마다 모니터링 -> 타임아웃 건도 처리
		DWORD ret = WaitForSingleObject(m_moniterEvent, 1000);

		if (ret == WAIT_TIMEOUT)
		{
			// 모니터링 서버 전송용 데이터
			//__int64 iJobThreadUpdateCnt = InterlockedExchange64(&m_jobThreadUpdateCnt, 0);
			__int64 iSessionCnt = sessionCnt;
			__int64 iAuthCnt = InterlockedExchange64(&m_loginSuccessTPS, 0);

			__int64 packetPoolCapacity = CPacket::GetPoolCapacity();
			__int64 packetPoolUseCnt = CPacket::GetPoolUseCnt();
			__int64 packetPoolAllocCnt = CPacket::GetPoolTotalAllocCnt();
			__int64 packetPoolFreeCnt = CPacket::GetPoolTotalFreeCnt();

			wprintf(L"------------------------[Moniter]----------------------------\n");
			performMoniter.PrintMonitorData();

			wprintf(L"------------------------[Network]----------------------------\n");
			wprintf(L"[Session              ] Total    : %10I64d\n", iSessionCnt);
			wprintf(L"[Accept               ] Total    : %10I64d    TPS : %10I64d\n", acceptCount, InterlockedExchange64(&acceptTPS, 0));
			wprintf(L"[Release              ] Total    : %10I64d    TPS : %10I64d\n", releaseCount, InterlockedExchange64(&releaseTPS, 0));
			wprintf(L"[Recv Call            ] Total    : %10I64d    TPS : %10I64d\n", recvCallCount, InterlockedExchange64(&recvCallTPS, 0));
			wprintf(L"[Send Call            ] Total    : %10I64d    TPS : %10I64d\n", sendCallCount, InterlockedExchange64(&sendCallTPS, 0));
			wprintf(L"[Recv Bytes           ] Total    : %10I64d    TPS : %10I64d\n", recvBytes, InterlockedExchange64(&recvBytesTPS, 0));
			wprintf(L"[Send Bytes           ] Total    : %10I64d    TPS : %10I64d\n", sendBytes, InterlockedExchange64(&sendBytesTPS, 0));
			wprintf(L"[Recv  Packet         ] Total    : %10I64d    TPS : %10I64d\n", recvMsgCount, InterlockedExchange64(&recvMsgTPS, 0));
			wprintf(L"[Send  Packet         ] Total    : %10I64d    TPS : %10I64d\n", sendMsgCount, InterlockedExchange64(&sendMsgTPS, 0));
			wprintf(L"[Pending TPS          ] Recv     : %10I64d    Send: %10I64d\n", InterlockedExchange64(&recvPendingTPS, 0), InterlockedExchange64(&sendPendingTPS, 0));
			wprintf(L"------------------------[Contents]----------------------------\n");
			wprintf(L"[Update               ] Total    : %10I64d    TPS        : %10I64d\n", m_updateTotal, InterlockedExchange64(&m_updateTPS, 0));
			wprintf(L"[RedisQ               ] Size     : %10I64d\n", redisJobQ.GetSize());
			wprintf(L"[Redis Job Pool       ] Capacity : %10llu     Use        : %10llu    Alloc : %10llu    Free : %10llu\n",
				redisJobPool.GetCapacity(), redisJobPool.GetObjectUseCount(), redisJobPool.GetObjectAllocCount(), redisJobPool.GetObjectFreeCount());
			wprintf(L"[Packet Pool          ] Capacity : %10llu     Use        : %10llu    Alloc : %10llu    Free : %10llu\n",
				packetPoolCapacity, packetPoolUseCnt, packetPoolAllocCnt, packetPoolFreeCnt);
			wprintf(L"[Login Packet         ] Total    : %10I64d    TPS        : %10I64d \n",
				m_loginCount, InterlockedExchange64(&m_loginTPS, 0));
			wprintf(L"[Login Success        ] Total    : %10I64d    TPS        : %10I64d \n",
				m_loginSuccessCount, iAuthCnt);
			wprintf(L"[Login Fail           ] Total    : %10I64d    TPS        : %10I64d \n",
				m_loginFailCount, InterlockedExchange64(&m_loginFailTPS, 0));
			wprintf(L"[DB                   ] Total    : %10I64d    TPS        : %10I64d\n",
				m_dbQueryTotal, InterlockedExchange64(&m_dbQueryTPS, 0));
			wprintf(L"[Redis Update         ] Enqueue  : %10I64d    TPS         : %10I64d\n", InterlockedExchange64(&m_redisJobEnqueueTPS, 0), InterlockedExchange64(&m_redisJobThreadUpdateTPS, 0));
			wprintf(L"[Redis Set            ] Total    : %10I64d    TPS         : %10I64d\n", m_redisSetCnt, InterlockedExchange64(&m_redisSetTPS, 0));
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
		}
	}

	return true;
}

bool LoginServer::RedisJobWorkerThread_serv()
{
	DWORD threadID = GetCurrentThreadId();

	while (true)
	{
		// JobQ에 Job이 삽입되면 이벤트 발생하여 깨어남
		WaitForSingleObject(m_redisJobEvent, INFINITE);

		RedisJob* redisJob = nullptr;

		// Job이 없을 때까지 update 반복
		while (redisJobQ.GetSize() > 0)
		{
			if (redisJobQ.Dequeue(redisJob))
			{
				// 비동기 redis set요청
				mRedis->asyncSet(redisJob->accountNo, redisJob->sessionKey, 30, [=](const cpp_redis::reply& reply) {

					// redis set 완료 콜백
					if (reply.is_string() && reply.as_string() == "OK")
					{
						// 비동기 요청이 성공하면 이후 로그인 응답 처리에 대한 일감을 PQCS로 던짐
						JobPQCS(redisJob->sessionID, redisJob->packet);

						// JobPool에 Job 객체 반환
						redisJobPool.Free(redisJob);

						InterlockedIncrement64(&m_redisJobThreadUpdateTPS);
					}
					else
					{
						// 실패 처리
						loginLog->logger(dfLOG_LEVEL_ERROR, __LINE__, L"Redis Set failed for accountNo : %IId", redisJob->accountNo);
						CRASH();
					}
				});
			}
		}
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

}

void LoginServer::OnRecv(uint64_t sessionID, CPacket* packet)
{
	WORD type = 0;
	*packet >> type;

	// Packet Handler 호출
	PacketProc(sessionID, packet, type);

	if (packet != nullptr)
		CPacket::Free(packet);

	InterlockedIncrement64(&m_updateTotal);
	InterlockedIncrement64(&m_updateTPS);
}

void LoginServer::OnJob(uint64_t sessionID, CPacket* packet)
{
	netPacketProc_ResLoginRedis(sessionID, packet);

	if (packet != nullptr)
		CPacket::Free(packet);

	InterlockedIncrement64(&m_updateTotal);
	InterlockedIncrement64(&m_updateTPS);
}

void LoginServer::OnError(int errorCode, const wchar_t* msg)
{

}

// Network Logic 으로부터 timeout 처리가 발생되면 timeout Handler 호출
void LoginServer::OnTimeout(uint64_t sessionID)
{
	PacketProc(sessionID, nullptr, en_PACKET_ON_TIMEOUT);

	InterlockedIncrement64(&m_updateTotal);
	InterlockedIncrement64(&m_updateTPS);
}

void LoginServer::PacketProc(uint64_t sessionID, CPacket* packet, WORD type)
{
	switch (type)
	{
	case en_PACKET_CS_LOGIN_REQ_LOGIN:
		// 로그인 요청
		netPacketProc_ReqLogin(sessionID, packet);
		break;

	case en_PACKET_ON_TIMEOUT:
		// 세션 타임아웃
		DisconnectSession(sessionID);
	break;

	default:
		// 잘못된 패킷
		loginLog->logger(dfLOG_LEVEL_ERROR, __LINE__, L"Packet Type Error > %d", type);
		DisconnectSession(sessionID);

		break;
	}
}

// 로그인 요청
void LoginServer::netPacketProc_ReqLogin(uint64_t sessionID, CPacket* packet)
{
	InterlockedIncrement64(&m_loginCount);
	InterlockedIncrement64(&m_loginTPS);

	// Packet 크기에 대한 예외 처리 
	if (packet->GetDataSize() < sizeof(INT64) + MSG_MAX_LEN * sizeof(char))
	{
		int size = packet->GetDataSize() + sizeof(WORD);
		loginLog->logger(dfLOG_LEVEL_ERROR, __LINE__, L"Login Request Packet # size error :  %d", size);

		DisconnectSession(sessionID);

		return;
	}

	INT64 _accountNo = 0;
	BYTE status = en_PACKET_CS_LOGIN_RES_LOGIN::dfLOGIN_STATUS_OK;

	// accountNo를 역직렬화해서 얻어옴
	*packet >> _accountNo;

	if (_accountNo < 0)
	{
		loginLog->logger(dfLOG_LEVEL_ERROR, __LINE__, L"Login Request Packet # account error :  %IId", _accountNo);

		DisconnectSession(sessionID);

		return;
	}

	char sessionKey[65];
	wchar_t ID[20];
	wchar_t Nickname[20];
	wchar_t gameServerIp[16];
	USHORT gameServerPort = 0;

	// Redis에 저장할 인증토큰을 역직렬화해서 얻어옴
	// 현재 로직에서는 Dummy Client가 인증토큰을 갖고 요청을 하기 때문에 이를 신뢰함
	packet->GetData((char*)sessionKey, MSG_MAX_LEN);

	sessionKey[MSG_MAX_LEN] = L'\0';

	if (sessionKey == nullptr)
	{
		loginLog->logger(dfLOG_LEVEL_ERROR, __LINE__, L"Login Request Packet # sessionKey is null");
		DisconnectSession(sessionID);
		return;
	}

	DBConnector* dbConn_TLS = (DBConnector*)TlsGetValue(this->_DBTlsIdx);
	if (dbConn_TLS == nullptr)
	{
		dbConn_TLS = new DBConnector(host, user, password, dbName, dbPort, true);
		dbConn_TLS->Open();

		TlsSetValue(this->_DBTlsIdx, dbConn_TLS);
		tlsDBObjects.Push(dbConn_TLS);
	}

	// ---------------------------------------------------------------------
	// 외부 플랫폼 API에 접근하여 토큰을 얻어오는 작업은 부하가 큰 작업
	// 이러한 느린 접근도 대응할 수 있는지 파악하기 위해
	// DB 접근을 통한 비슷한 상황 유도 (부하가 걸리는 작업)

	// accountNo에 해당하는 account table 정보 select
	std::wstring query = L"select * from accountdb.account where accountno=";
	query += std::to_wstring(_accountNo);
	query += L";";

	int queryRet = dbConn_TLS->Query(query.c_str());

	// 쿼리 실패
	if (queryRet < -1)
	{
		loginLog->logger(dfLOG_LEVEL_ERROR, __LINE__, L"Login Request Packet # account select query fail");

		return;
	}
	// account table에 accountNo 없음 -> 요청 실패에 대한 응답 전송
	else if (queryRet == 0)
	{
		dbConn_TLS->FreeResult();

		InterlockedIncrement64(&m_loginFailCount);
		InterlockedIncrement64(&m_loginFailTPS);

		status = en_PACKET_CS_LOGIN_RES_LOGIN::dfLOGIN_STATUS_ACCOUNT_MISS;

		CPacket* resLoginPacket = CPacket::Alloc();

		mpResLogin(resLoginPacket, _accountNo, status, ID, Nickname, gameServerIp, gameServerPort, chatIP, chatPort);

		SendPacketAndDisconnect(sessionID, resLoginPacket, 100);
		
		CPacket::Free(resLoginPacket);

		return;
	}

	// -----------------------------------------------------------
	// 쿼리 성공
	// -----------------------------------------------------------

	InterlockedIncrement64(&m_dbQueryTotal);
	InterlockedIncrement64(&m_dbQueryTPS);

	// row를 얻어와 column에 맞는 데이터 셋팅
	// result[1] : id
	// resultRow[3] : nickname
	MYSQL_ROW resultRow = dbConn_TLS->FetchRow();

	// resultRow[1]의 wideLen
	int wideCharLen = MultiByteToWideChar(CP_UTF8, 0, resultRow[1], strlen(resultRow[1]), 0, 0);
	if (wideCharLen > ID_MAX_LEN)
	{
		loginLog->logger(dfLOG_LEVEL_ERROR, __LINE__, L"Login Request Packet # Multibyte To WideChar error > result[1] is too much size");
		dbConn_TLS->FreeResult();

		return;
	}

	MultiByteToWideChar(CP_UTF8, 0, resultRow[1], strlen(resultRow[1]), ID, wideCharLen * sizeof(wchar_t));
	ID[wideCharLen] = L'\0';

	// resultRow[3]의 wideLen
	wideCharLen = MultiByteToWideChar(CP_UTF8, 0, resultRow[3], strlen(resultRow[3]), 0, 0);
	if (wideCharLen > NICKNAME_MAX_LEN)
	{
		loginLog->logger(dfLOG_LEVEL_ERROR, __LINE__, L"Login Request Packet # Multibyte To WideChar error > result[3] is too much size");
		dbConn_TLS->FreeResult();

		return;
	}

	MultiByteToWideChar(CP_UTF8, 0, resultRow[3], strlen(resultRow[3]), Nickname, wideCharLen * sizeof(wchar_t));
	Nickname[wideCharLen] = L'\0';

	dbConn_TLS->FreeResult();


	// accountNo에 해당하는 sessionKey table 정보 select
	query = L"select sessionkey from accountdb.sessionkey where accountno=";
	query += std::to_wstring(_accountNo);
	query += L";";

	queryRet = dbConn_TLS->Query(query.c_str());

	if (queryRet == -1)
	{
		loginLog->logger(dfLOG_LEVEL_ERROR, __LINE__, L"Login Request Packet # sessionkey select query fail");

		return;
	}
	else if (queryRet == 0)
	{
		dbConn_TLS->FreeResult();

		InterlockedIncrement64(&m_loginFailCount);
		InterlockedIncrement64(&m_loginFailTPS);

		status = en_PACKET_CS_LOGIN_RES_LOGIN::dfLOGIN_STATUS_SESSION_MISS;

		CPacket* resLoginPacket = CPacket::Alloc();

		mpResLogin(resLoginPacket, _accountNo, status, ID, Nickname, gameServerIp, gameServerPort, chatIP, chatPort);

		SendPacketAndDisconnect(sessionID, resLoginPacket, 100);

		CPacket::Free(resLoginPacket);

		return;
	}

	InterlockedIncrement64(&m_dbQueryTotal);
	InterlockedIncrement64(&m_dbQueryTPS);

	dbConn_TLS->FreeResult();

	// accountNo에 해당하는 status table 정보 select
	query = L"select status from accountdb.status where accountno=";
	query += std::to_wstring(_accountNo);
	query += L";";

	queryRet = dbConn_TLS->Query(query.c_str());

	if (queryRet == -1)
	{
		loginLog->logger(dfLOG_LEVEL_ERROR, __LINE__, L"Login Request Packet # status select query fail");
		return;
	}
	else if (queryRet == 0)
	{
		dbConn_TLS->FreeResult();

		InterlockedIncrement64(&m_loginFailCount);
		InterlockedIncrement64(&m_loginFailTPS);

		status = en_PACKET_CS_LOGIN_RES_LOGIN::dfLOGIN_STATUS_STATUS_MISS;

		CPacket* resLoginPacket = CPacket::Alloc();

		mpResLogin(resLoginPacket, _accountNo, status, ID, Nickname, gameServerIp, gameServerPort, chatIP, chatPort);

		SendPacketAndDisconnect(sessionID, resLoginPacket, 100);

		CPacket::Free(resLoginPacket);

		return;
	}

	InterlockedIncrement64(&m_dbQueryTotal);
	InterlockedIncrement64(&m_dbQueryTPS);

	dbConn_TLS->FreeResult();

	// ------------------------------------------------------------------------
	// Redis에 인증 토큰 저장 ("accountNo", "sessionKey")
	// ------------------------------------------------------------------------
	std::string accountNoStr = std::to_string(_accountNo);
	std::string sessionKeyStr;
	sessionKeyStr.assign(sessionKey);

	CPacket* resLoginPacket = CPacket::Alloc();

	mpResLogin(resLoginPacket, _accountNo, status, ID, Nickname, gameServerIp, gameServerPort, chatIP, chatPort);

	RedisJob* job = redisJobPool.Alloc();
	job->sessionID = sessionID;
	job->accountNo = accountNoStr;
	job->sessionKey = sessionKeyStr;
	job->packet = resLoginPacket;

	redisJobQ.Enqueue(job);
	SetEvent(m_redisJobEvent);
	InterlockedIncrement64(&m_redisJobEnqueueTPS);

	//// redis에 인증 토큰 저장 (30초 후에 토큰 만료)
	//if (!mRedis->syncSet(accountNoStr, sessionKeyStr, 30))
	//{
	//	// redis set 실패 시 동작
	//	status = en_PACKET_CS_LOGIN_RES_LOGIN::dfLOGIN_STATUS_NONE;

	//	CPacket* resLoginPacket = CPacket::Alloc();

	//	mpResLogin(resLoginPacket, _accountNo, status, ID, Nickname, gameServerIp, gameServerPort, chatIP, chatPort);

	//	SendPacketAndDisconnect(sessionID, resLoginPacket, 100);

	//	CPacket::Free(resLoginPacket);
	//}

	//InterlockedIncrement64(&m_redisSetCnt);
	//InterlockedIncrement64(&m_redisSetTPS);

	//// account table에 있는 정보이므로 로그인 성공 & 인증 성공
	//InterlockedIncrement64(&m_loginSuccessCount);
	//InterlockedIncrement64(&m_loginSuccessTPS);

	//CPacket* resLoginPacket = CPacket::Alloc();

	//mpResLogin(resLoginPacket, _accountNo, status, ID, Nickname, gameServerIp, gameServerPort, chatIP, chatPort);

	//// 응답을 보낸 뒤, 100ms 뒤에 로그인 서버와의 연결을 끊음
	//SendPacketAndDisconnect(sessionID, resLoginPacket, 100);

	//CPacket::Free(resLoginPacket);
}

// 비동기 redis 요청 결과를 얻은 뒤, 이후 로그인 job 처리
void LoginServer::netPacketProc_ResLoginRedis(uint64_t sessionID, CPacket* packet)
{
	// account table에 있는 정보이므로 로그인 성공 & 인증 성공
	InterlockedIncrement64(&m_loginSuccessCount);
	InterlockedIncrement64(&m_loginSuccessTPS);

	//// 응답을 보낸 뒤, 100ms 뒤에 로그인 서버와의 연결을 끊음
	//SendPacketAndDisconnect(sessionID, packet, 100);

	// 로그인 응답
	SendPacket(sessionID, packet);
}