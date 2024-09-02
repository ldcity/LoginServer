#include "../PCH.h"
#include <conio.h>


DWORD LoginServer::_DBTlsIdx = TlsAlloc();
DWORD LoginServer::_RedisTlsIdx = TlsAlloc();

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

	loginServerInfoTxt.GetValue(L"CHATSERVER.BIND_IP", chatIP);
	loginServerInfoTxt.GetValue(L"CHATSERVER.BIND_PORT", &chatPort);

	wchar_t ip[20];
	int port;

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

	loginServerInfoTxt.GetValue(L"LOGINSERVER.USER_MAX", &mUserMAXCnt);

	int packet_code;
	loginServerInfoTxt.GetValue(L"LOGINSERVER.PACKET_CODE", &packet_code);

	int packet_key;
	loginServerInfoTxt.GetValue(L"LOGINSERVER.PACKET_KEY", &packet_key);

	loginServerInfoTxt.GetValue(L"SERVICE.TIMEOUT_DISCONNECT", &mTimeout);

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

	loginServerInfoTxt.GetValue(L"REDIS.IP", redisIP);
	loginServerInfoTxt.GetValue(L"REDIS.PORT", &redisPort);

	// Create Manual Event
	mRunEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	if (mRunEvent == NULL)
	{
		int eventError = WSAGetLastError();
		loginLog->logger(dfLOG_LEVEL_ERROR, __LINE__, L"CreateEvent() Error : %d", eventError);

		return false;
	}

	// Create Auto Event
	mMoniterEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	if (mMoniterEvent == NULL)
	{
		int eventError = WSAGetLastError();
		loginLog->logger(dfLOG_LEVEL_ERROR, __LINE__, L"CreateEvent() Error : %d", eventError);

		return false;
	}

 
	// Monitering Thread
	mMoniteringThread = (HANDLE)_beginthreadex(NULL, 0, MoniteringThread, this, CREATE_SUSPENDED, NULL);
	if (mMoniteringThread == NULL)
	{
		int threadError = GetLastError();
		loginLog->logger(dfLOG_LEVEL_ERROR, __LINE__, L"_beginthreadex() Error : %d", threadError);

		return false;
	}

	WaitForSingleObject(mMoniteringThread, INFINITE);

	return true;
}

bool LoginServer::LoginServerStop()
{
	DBConnector* dbConn;

	// 리소스 정리 작업을 위해 필요한 LockFreeStack에서 DBConnector 객체 pop
	while (tlsDBObjects.Pop(&dbConn))
		delete dbConn;

	TlsFree(_DBTlsIdx);

	CRedis* redis;

	// 리소스 정리 작업을 위해 필요한 LockFreeStack에서 DBConnector 객체 pop
	while (tlsRedisObjects.Pop(&redis))
		delete redis;

	TlsFree(_RedisTlsIdx);

	CloseHandle(mMoniteringThread);
	CloseHandle(mMoniterEvent);
	CloseHandle(mRunEvent);

	mysql_library_end(); // MySQL 라이브러리 종료

	return true;
}

// Monitering Thread
bool LoginServer::MoniterThread_serv()
{
	while (true)
	{
		// 1초마다 모니터링 -> 타임아웃 건도 처리
		DWORD ret = WaitForSingleObject(mMoniterEvent, 1000);
		if (ret == WAIT_TIMEOUT)
		{
			// 모니터링 서버 전송용 데이터
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
			wprintf(L"[Update               ] TPS      : %10I64d\n", InterlockedExchange64(&m_updateTPS, 0));
			wprintf(L"[Login Res Update     ] TPS      : %10I64d\n", InterlockedExchange64(&m_loginResJobUpdateTPS, 0));
			wprintf(L"[Redis Update         ] TPS      : %10I64d\n", InterlockedExchange64(&m_redisJobThreadUpdateTPS, 0));
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

bool LoginServer::OnConnectionRequest(const wchar_t* IP, unsigned short PORT)
{
	return true;
}

void LoginServer::OnClientJoin(uint64_t sessionID)
{
	if (!startFlag)
	{
		ResumeThread(mMoniteringThread);
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

	InterlockedIncrement64(&m_updateTPS);
}

void LoginServer::OnError(int errorCode, const wchar_t* msg)
{

}

// Network Logic 으로부터 timeout 처리가 발생되면 timeout Handler 호출
void LoginServer::OnTimeout(uint64_t sessionID)
{
	PacketProc(sessionID, nullptr, en_PACKET_ON_TIMEOUT);

	InterlockedIncrement64(&m_updateTPS);
}

void LoginServer::PacketProc(uint64_t sessionID, CPacket* packet, WORD type)
{
	switch (type)
	{
	case en_PACKET_CS_LOGIN_REQ_LOGIN:
		// 로그인 요청
		NetPacketProc_ReqLogin(sessionID, packet);
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
void LoginServer::NetPacketProc_ReqLogin(uint64_t sessionID, CPacket* packet)
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

	DBConnector* mDBConn = (DBConnector*)TlsGetValue(this->_DBTlsIdx);
	if (mDBConn == nullptr)
	{
		mDBConn = new DBConnector(host, user, password, dbName, dbPort, true);
		mDBConn->Open();

		TlsSetValue(this->_DBTlsIdx, mDBConn);
		tlsDBObjects.Push(mDBConn);
	}

	// ---------------------------------------------------------------------
	// 외부 플랫폼 API에 접근하여 토큰을 얻어오는 작업은 부하가 큰 작업
	// 이러한 느린 접근도 대응할 수 있는지 파악하기 위해
	// DB 접근을 통한 비슷한 상황 유도 (부하가 걸리는 작업)

	// select 이후 해당 행의 컬럼 값 추출 (결과 버퍼)
	char id[ID_MAX_LEN] = { 0 };
	char nickname[NICKNAME_MAX_LEN] = { 0 };

	std::wstring query = L"SELECT userid, usernick FROM accountdb.account WHERE accountno = ?";

	// 매개변수 바인딩 & 쿼리 요청
	bool isDBSuccess = mDBConn->ExecuteQuery(query, [&, this](MYSQL_STMT* stmt, Log* dblog) -> bool {
		int fetchResult = mDBConn->FetchResult(stmt, id, nickname);

		// 실패
		if (fetchResult == -1)
		{
			loginLog->logger(dfLOG_LEVEL_ERROR, __LINE__, L"Result binding failed : %s", mysql_stmt_error(stmt));
			return false;
		}
		// 테이블에 레코드 없음
		else if (fetchResult == MYSQL_NO_DATA)
		{
			// account 테이블에 해당 계정 정보가 없음
			BYTE status = en_PACKET_CS_LOGIN_RES_LOGIN::dfLOGIN_STATUS_ACCOUNT_MISS;

			CPacket* resLoginPacket = CPacket::Alloc();

			wchar_t nonID[ID_MAX_LEN] = { 0 };
			wchar_t nonNickname[NICKNAME_MAX_LEN] = { 0 };

			CPacket* resLoginPacket = CPacket::Alloc();

			MPResLogin(resLoginPacket, _accountNo, status, ID, Nickname, gameServerIp, gameServerPort, chatIP, chatPort);

			SendPacket(sessionID, resLoginPacket);

			CPacket::Free(resLoginPacket);

			return false;
		}
		// 테이블에 레코드 있음
		else if (fetchResult == 0)
		{
			// 쿼리 성공 - 정보 추출
			wchar_t ID[ID_MAX_LEN] = { 0 };
			wchar_t Nickname[NICKNAME_MAX_LEN] = { 0 };

			int length = MultiByteToWideChar(CP_UTF8, 0, id, strlen(id), NULL, NULL);
			MultiByteToWideChar(CP_UTF8, 0, id, strlen(id), ID, length);

			length = MultiByteToWideChar(CP_UTF8, 0, nickname, strlen(nickname), NULL, NULL);
			MultiByteToWideChar(CP_UTF8, 0, nickname, strlen(nickname), Nickname, length);

			return true;
		}
		else
		{
			loginLog->logger(dfLOG_LEVEL_ERROR, __LINE__, L"Error fetching result: : %s", mysql_stmt_error(stmt));
			return false;
		}
		return true;

	}, _accountNo, id, nickname);


	// ------------------------------------------------------------------------
	// Redis에 인증 토큰 저장 ("accountNo", "sessionKey")
	// ------------------------------------------------------------------------
	CRedis* mRedis = (CRedis*)TlsGetValue(this->_RedisTlsIdx);
	if (mRedis == nullptr)
	{
		mRedis = new CRedis;
		mRedis->Connect(redisIP, redisPort);

		TlsSetValue(this->_RedisTlsIdx, mRedis);
		tlsRedisObjects.Push(mRedis);
	}
	
	std::string accountNoStr = std::to_string(_accountNo);
	std::string sessionKeyStr;
	sessionKeyStr.assign(sessionKey);

	CPacket* resLoginPacket = CPacket::Alloc();

	MPResLogin(resLoginPacket, _accountNo, status, ID, Nickname, gameServerIp, gameServerPort, chatIP, chatPort);


	// redis에 인증 토큰 저장 (30초 후에 토큰 만료)
	if (!mRedis->syncSet(accountNoStr, sessionKeyStr, 30))
	{
		// redis set 실패 시 동작
		status = en_PACKET_CS_LOGIN_RES_LOGIN::dfLOGIN_STATUS_NONE;

		CPacket* resLoginPacket = CPacket::Alloc();

		MPResLogin(resLoginPacket, _accountNo, status, ID, Nickname, gameServerIp, gameServerPort, chatIP, chatPort);

		SendPacket(sessionID, resLoginPacket);

		CPacket::Free(resLoginPacket);
	}

	// account table에 있는 정보이므로 로그인 성공 & 인증 성공
	InterlockedIncrement64(&m_loginSuccessCount);
	InterlockedIncrement64(&m_loginSuccessTPS);

	CPacket* resLoginPacket = CPacket::Alloc();

	MPResLogin(resLoginPacket, _accountNo, status, ID, Nickname, gameServerIp, gameServerPort, chatIP, chatPort);

	// 응답을 보낸 뒤, 100ms 뒤에 로그인 서버와의 연결을 끊음
	SendPacket(sessionID, resLoginPacket);

	CPacket::Free(resLoginPacket);
}