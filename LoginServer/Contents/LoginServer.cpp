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
	mysql_library_init(0, NULL, NULL); // MySQL ���̺귯�� �ʱ�ȭ

	loginLog = new Log(L"LoginLog");

	// login server ���������� Parsing�Ͽ� �о��
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

	// �����庰 MySQL �ʱ�ȭ
	for (int i = 0; i < workerThread; ++i)
	{
		mysql_thread_init(); // �����庰 MySQL �ʱ�ȭ
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

	// ���ҽ� ���� �۾��� ���� �ʿ��� LockFreeStack���� DBConnector ��ü pop
	while (tlsDBObjects.Pop(&dbConn))
		delete dbConn;

	TlsFree(_DBTlsIdx);

	CRedis* redis;

	// ���ҽ� ���� �۾��� ���� �ʿ��� LockFreeStack���� DBConnector ��ü pop
	while (tlsRedisObjects.Pop(&redis))
		delete redis;

	TlsFree(_RedisTlsIdx);

	CloseHandle(mMoniteringThread);
	CloseHandle(mMoniterEvent);
	CloseHandle(mRunEvent);

	mysql_library_end(); // MySQL ���̺귯�� ����

	return true;
}

// Monitering Thread
bool LoginServer::MoniterThread_serv()
{
	while (true)
	{
		// 1�ʸ��� ����͸� -> Ÿ�Ӿƿ� �ǵ� ó��
		DWORD ret = WaitForSingleObject(mMoniterEvent, 1000);
		if (ret == WAIT_TIMEOUT)
		{
			// ����͸� ���� ���ۿ� ������
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

	// �α��� ������ accept
}

void LoginServer::OnClientLeave(uint64_t sessionID)
{

}

void LoginServer::OnRecv(uint64_t sessionID, CPacket* packet)
{
	WORD type = 0;
	*packet >> type;

	// Packet Handler ȣ��
	PacketProc(sessionID, packet, type);

	if (packet != nullptr)
		CPacket::Free(packet);

	InterlockedIncrement64(&m_updateTPS);
}

void LoginServer::OnError(int errorCode, const wchar_t* msg)
{

}

// Network Logic ���κ��� timeout ó���� �߻��Ǹ� timeout Handler ȣ��
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
		// �α��� ��û
		NetPacketProc_ReqLogin(sessionID, packet);
		break;

	case en_PACKET_ON_TIMEOUT:
		// ���� Ÿ�Ӿƿ�
		DisconnectSession(sessionID);
	break;

	default:
		// �߸��� ��Ŷ
		loginLog->logger(dfLOG_LEVEL_ERROR, __LINE__, L"Packet Type Error > %d", type);
		DisconnectSession(sessionID);

		break;
	}
}

// �α��� ��û
void LoginServer::NetPacketProc_ReqLogin(uint64_t sessionID, CPacket* packet)
{
	InterlockedIncrement64(&m_loginCount);
	InterlockedIncrement64(&m_loginTPS);

	// Packet ũ�⿡ ���� ���� ó�� 
	if (packet->GetDataSize() < sizeof(INT64) + MSG_MAX_LEN * sizeof(char))
	{
		int size = packet->GetDataSize() + sizeof(WORD);
		loginLog->logger(dfLOG_LEVEL_ERROR, __LINE__, L"Login Request Packet # size error :  %d", size);

		DisconnectSession(sessionID);

		return;
	}

	INT64 _accountNo = 0;
	BYTE status = en_PACKET_CS_LOGIN_RES_LOGIN::dfLOGIN_STATUS_OK;

	// accountNo�� ������ȭ�ؼ� ����
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

	// Redis�� ������ ������ū�� ������ȭ�ؼ� ����
	// ���� ���������� Dummy Client�� ������ū�� ���� ��û�� �ϱ� ������ �̸� �ŷ���
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
	// �ܺ� �÷��� API�� �����Ͽ� ��ū�� ������ �۾��� ���ϰ� ū �۾�
	// �̷��� ���� ���ٵ� ������ �� �ִ��� �ľ��ϱ� ����
	// DB ������ ���� ����� ��Ȳ ���� (���ϰ� �ɸ��� �۾�)

	// select ���� �ش� ���� �÷� �� ���� (��� ����)
	char id[ID_MAX_LEN] = { 0 };
	char nickname[NICKNAME_MAX_LEN] = { 0 };

	std::wstring query = L"SELECT userid, usernick FROM accountdb.account WHERE accountno = ?";

	// �Ű����� ���ε� & ���� ��û
	bool isDBSuccess = mDBConn->ExecuteQuery(query, [&, this](MYSQL_STMT* stmt, Log* dblog) -> bool {
		int fetchResult = mDBConn->FetchResult(stmt, id, nickname);

		// ����
		if (fetchResult == -1)
		{
			loginLog->logger(dfLOG_LEVEL_ERROR, __LINE__, L"Result binding failed : %s", mysql_stmt_error(stmt));
			return false;
		}
		// ���̺� ���ڵ� ����
		else if (fetchResult == MYSQL_NO_DATA)
		{
			// account ���̺� �ش� ���� ������ ����
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
		// ���̺� ���ڵ� ����
		else if (fetchResult == 0)
		{
			// ���� ���� - ���� ����
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
	// Redis�� ���� ��ū ���� ("accountNo", "sessionKey")
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


	// redis�� ���� ��ū ���� (30�� �Ŀ� ��ū ����)
	if (!mRedis->syncSet(accountNoStr, sessionKeyStr, 30))
	{
		// redis set ���� �� ����
		status = en_PACKET_CS_LOGIN_RES_LOGIN::dfLOGIN_STATUS_NONE;

		CPacket* resLoginPacket = CPacket::Alloc();

		MPResLogin(resLoginPacket, _accountNo, status, ID, Nickname, gameServerIp, gameServerPort, chatIP, chatPort);

		SendPacket(sessionID, resLoginPacket);

		CPacket::Free(resLoginPacket);
	}

	// account table�� �ִ� �����̹Ƿ� �α��� ���� & ���� ����
	InterlockedIncrement64(&m_loginSuccessCount);
	InterlockedIncrement64(&m_loginSuccessTPS);

	CPacket* resLoginPacket = CPacket::Alloc();

	MPResLogin(resLoginPacket, _accountNo, status, ID, Nickname, gameServerIp, gameServerPort, chatIP, chatPort);

	// ������ ���� ��, 100ms �ڿ� �α��� �������� ������ ����
	SendPacket(sessionID, resLoginPacket);

	CPacket::Free(resLoginPacket);
}