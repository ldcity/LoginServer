#include "../PCH.h"
#include "NetServer.h"

// ========================================================================
// Thread Call
// ========================================================================
// Accept Thread Call
unsigned __stdcall AcceptThread(void* param)
{
	NetServer* netServ = (NetServer*)param;

	netServ->AcceptThread_serv();

	return 0;
}

// Worker Thread Call
unsigned __stdcall WorkerThread(void* param)
{
	NetServer* netServ = (NetServer*)param;

	netServ->WorkerThread_serv();

	return 0;
}

// Timeout Thread Call
unsigned __stdcall TimeoutThread(void* param)
{
	NetServer* netServ = (NetServer*)param;

	netServ->TimeoutThread_serv();

	return 0;
}

NetServer::NetServer() : ListenSocket(INVALID_SOCKET), ServerPort(0), IOCPHandle(0), mAcceptThread(0), mWorkerThreads{ 0 },
RunEvent(0), ExitEvent(0), SessionArray{ nullptr }, acceptCount(0), releaseCount(0), recvMsgTPS(0), sendMsgTPS(0),
recvMsgCount(0), sendMsgCount(0), recvCallTPS(0), sendCallTPS(0), recvCallCount(0), sendCallCount(0), recvPendingTPS(0), sendPendingTPS(0),
recvBytesTPS(0), sendBytesTPS(0), recvBytes(0), sendBytes(0), mWorkerThreadCount(0), mRunningThreadCount(0), mMaxAcceptCount(0), startMonitering(false)
{
	// ========================================================================
	// Initialize
	// ========================================================================
	logger = new Log(L"NetServer");

	wprintf(L"Login Server Initializing...\n");

	WSADATA  wsaData;

	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
	{
		int initError = WSAGetLastError();
		logger->logger(dfLOG_LEVEL_ERROR, __LINE__, L"WSAStartup() Error : %d", initError);

		return;
	}
}

NetServer::~NetServer()
{
	Stop();
}

bool NetServer::Start(const wchar_t* IP, unsigned short PORT, int createWorkerThreadCnt, int runningWorkerThreadCnt, bool nagelOff, bool zeroCopyOff, int maxAcceptCnt, unsigned char packet_code, unsigned char packet_key, DWORD timeout)
{
	// 서버의 현재 시간
	// 세션들이 서버의 현재 시간을 기준으로 타임아웃 됐는지 판별하기 위해 필요
	mServerTime = timeGetTime();
	mTimeout = timeout;

	CPacket::SetCode(packet_code);
	CPacket::SetKey(packet_key);

	mMaxAcceptCount = maxAcceptCnt;

	SessionArray = new stSESSION[mMaxAcceptCount];

	// 프리 인덱스를 오름차순으로 꺼내기 위해 max index부터 push
	for (int i = mMaxAcceptCount - 1; i >= 0; i--)
	{
		// 사용 가능한 인덱스 push
		AvailableIndexStack.Push(i);
	}

	// Create Listen Socket
	ListenSocket = socket(AF_INET, SOCK_STREAM, 0);

	if (INVALID_SOCKET == ListenSocket)
	{
		int sockError = WSAGetLastError();
		logger->logger(dfLOG_LEVEL_ERROR, __LINE__, L"socket() Error : %d", sockError);

		return false;
	}

	SOCKADDR_IN serverAddr;
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons(PORT);
	InetPtonW(AF_INET, IP, &serverAddr.sin_addr);

	// bind
	if (bind(ListenSocket, (SOCKADDR*)&serverAddr, sizeof(SOCKADDR_IN)) == SOCKET_ERROR)
	{
		int bindError = WSAGetLastError();
		logger->logger(dfLOG_LEVEL_ERROR, __LINE__, L"bind() Error : %d", bindError);

		return false;
	}

	if (!zeroCopyOff)
	{
		// TCP Send Buffer Remove - zero copy
		int sendVal = 0;
		if (setsockopt(ListenSocket, SOL_SOCKET, SO_SNDBUF, (const char*)&sendVal, sizeof(sendVal)) == SOCKET_ERROR)
		{
			int setsockoptError = WSAGetLastError();
			logger->logger(dfLOG_LEVEL_ERROR, __LINE__, L"setsockopt() Error : %d", setsockoptError);

			return false;
		}
	}

	if (nagelOff)
	{
		// Nagle off
		if (setsockopt(ListenSocket, IPPROTO_TCP, TCP_NODELAY, (const char*)&nagelOff, sizeof(nagelOff)) == SOCKET_ERROR)
		{
			int setsockoptError = WSAGetLastError();
			logger->logger(dfLOG_LEVEL_ERROR, __LINE__, L"setsockopt() Error : %d", setsockoptError);

			return false;
		}
	}

	// TIME_WAIT off
	struct linger ling;
	ling.l_onoff = 1;
	ling.l_linger = 0;
	if (setsockopt(ListenSocket, SOL_SOCKET, SO_LINGER, (const char*)&ling, sizeof(ling)) == SOCKET_ERROR)
	{
		int setsockoptError = WSAGetLastError();
		logger->logger(dfLOG_LEVEL_ERROR, __LINE__, L"setsockopt() Error : %d", setsockoptError);

		return false;
	}

	// listen
	if (listen(ListenSocket, SOMAXCONN) == SOCKET_ERROR)
	{
		int listenError = WSAGetLastError();
		logger->logger(dfLOG_LEVEL_ERROR, __LINE__, L"listen() Error : %d", listenError);

		return false;
	}

	// Create Manual Event
	ExitEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	if (ExitEvent == NULL)
	{
		int eventError = WSAGetLastError();
		logger->logger(dfLOG_LEVEL_ERROR, __LINE__, L"CreateEvent() Error : %d", eventError);

		return false;
	}

	SYSTEM_INFO si;
	GetSystemInfo(&si);

	// CPU Core Counting
	// Worker Thread 개수가 0 이하라면, 코어 개수 * 2 로 재설정
	if (createWorkerThreadCnt <= 0)
		mWorkerThreadCount = si.dwNumberOfProcessors * 2;
	else
		mWorkerThreadCount = createWorkerThreadCnt;

	// Running Thread가 CPU Core 개수를 초과한다면 CPU Core 개수로 재설정
	if (runningWorkerThreadCnt > si.dwNumberOfProcessors)
		mRunningThreadCount = si.dwNumberOfProcessors;
	else
		mRunningThreadCount = runningWorkerThreadCnt;

	// Create I/O Completion Port
	IOCPHandle = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, NULL, mRunningThreadCount);
	if (IOCPHandle == NULL)
	{
		int iocpError = WSAGetLastError();
		logger->logger(dfLOG_LEVEL_ERROR, __LINE__, L"CreateIoCompletionPort() Error : %d", iocpError);

		return false;
	}

	logger->logger(dfLOG_LEVEL_SYSTEM, __LINE__, L"Init Success");

	// ========================================================================
	// Create Thread
	// ========================================================================
	logger->logger(dfLOG_LEVEL_SYSTEM, __LINE__, L"Create Thread");

	// Accept Thread
	mAcceptThread = (HANDLE)_beginthreadex(NULL, 0, AcceptThread, this, 0, NULL);
	if (AcceptThread == NULL)
	{
		int threadError = GetLastError();
		logger->logger(dfLOG_LEVEL_ERROR, __LINE__, L"_beginthreadex() Error : %d", threadError);

		return false;
	}

	// Worker Thread
	mWorkerThreads.resize(mWorkerThreadCount);
	for (int i = 0; i < mWorkerThreads.size(); i++)
	{
		mWorkerThreads[i] = (HANDLE)_beginthreadex(NULL, 0, WorkerThread, this, 0, NULL);
		if (mWorkerThreads[i] == NULL)
		{
			int threadError = GetLastError();
			logger->logger(dfLOG_LEVEL_ERROR, __LINE__, L"_beginthreadex() Error : %d", threadError);

			return false;
		}
	}

	logger->logger(dfLOG_LEVEL_DEBUG, __LINE__, L"Create Worker Thread > Count : %d", mWorkerThreadCount);

	// Timeout Thread
	mTimeoutThread = (HANDLE)_beginthreadex(NULL, 0, TimeoutThread, this, 0, NULL);
	if (AcceptThread == NULL)
	{
		int threadError = GetLastError();
		logger->logger(dfLOG_LEVEL_ERROR, __LINE__, L"_beginthreadex() Error : %d", threadError);

		return false;
	}

	return true;
}

// Accept Thread
bool NetServer::AcceptThread_serv()
{
	DWORD threadID = GetCurrentThreadId();

	wprintf(L"AcceptThread[%d] Start...\n", threadID);

	SOCKADDR_IN clientAddr;
	int addrLen = sizeof(SOCKADDR_IN);
	SOCKET clientSocket;
	DWORD recvBytes;

	// 접속한 클라 정보 출력
	wchar_t szClientIP[16] = { 0 };


	unsigned long long s_sessionUniqueID = 0;				// Unique Value

	while (true)
	{
		// accept
		clientSocket = accept(ListenSocket, (SOCKADDR*)&clientAddr, &addrLen);

		if (clientSocket == INVALID_SOCKET)
		{
			int acceptError = GetLastError();

			break;
		}

		InetNtopW(AF_INET, &clientAddr.sin_addr, szClientIP, 16);


		if (!OnConnectionRequest(szClientIP, ntohs(clientAddr.sin_port)))
		{
			// 접속 거부
			// ...
			closesocket(clientSocket);
			break;
		}

		// 사용 가능한 index 추출
		int index;

		// 비어있는 배열 찾기
		// index stack이 비어있으면 배열이 다 사용중 (full!)
		if (!AvailableIndexStack.Pop(&index))
		{
			// 방금 accept 했던 소켓 종료
			closesocket(clientSocket);

			continue;
		}

		// 세션 수
		InterlockedIncrement64(&acceptTPS);
		InterlockedIncrement64(&acceptCount);

		// 해당 index의 세션 셋팅
		stSESSION* session = &SessionArray[index];

		// 세션 참조카운트 증가 -> accept 함수 마지막에 정리 
		// -> accept 단계에서 소켓 얻은 후, 세션 사용을 할 때, refcount가 0이 되는 걸 방지
		// increment가 아니라 exchange하는 이유 
		// -> 이전에 사용했던 세션이면 release하면서 남아있던 release flag 잔재 지우기 위해
		InterlockedExchange64(&session->ioRefCount, 1);

		session->sessionID = CreateSessionID(++s_sessionUniqueID, index);

		SetTimeout(session);


		__int64 id = session->sessionID;

		// 링버퍼 내부에 남아있는 거 처리
		session->recvRingBuffer.ClearBuffer();
		ZeroMemory(session->IP_str, sizeof(session->IP_str));
		ZeroMemory(&session->m_stSendOverlapped, sizeof(OVERLAPPED));
		ZeroMemory(&session->m_stRecvOverlapped, sizeof(OVERLAPPED));

		session->IP_num = 0;
		session->PORT = 0;
		//session->LastRecvTime = 0;

		session->m_socketClient = clientSocket;
		wcscpy_s(session->IP_str, _countof(session->IP_str), szClientIP);
		session->PORT = ntohs(clientAddr.sin_port);

		// 종료flag 셋팅
		InterlockedExchange8((char*)&session->isDisconnected, false);
		InterlockedExchange8((char*)&session->sendDisconnFlag, false);

		// IOCP와 소켓 연결
		// 세션 주소값이 키 값
		if (CreateIoCompletionPort((HANDLE)clientSocket, IOCPHandle, (ULONG_PTR)session, 0) == NULL)
		{
			int ciocpError = WSAGetLastError();

			//// 인자에 잘못된 소켓 핸들값이 들어갔을 경우 에러 -> 다른 쓰레드에서 소켓 해제했을 경우 발생
			logger->logger(dfLOG_LEVEL_ERROR, __LINE__, L"AcceptThread - CreateIoCompletionPort Error : %d", ciocpError);

			// accept후 바로 반환하는 것이므로 iocount 감소 후 io 완료 유무 확인
			if (0 == InterlockedDecrement64((LONG64*)&session->ioRefCount))
			{
				ReleaseSession(session);
				continue;
			}
		}

		// 접속 처리
		// 사전에 받아놓은 id를 매개변수로 전달 -> 세션의 id 멤버변수에 직접 접근해 전달하게 되면
		// 그 사이에 재할당되어 다른 세션이 될 때, 해당 id를 가진 player가 삭제될 수 없음
		// ex) 더미 클라이언트 껐을 때, 세션은 다 정리됐는데 player가 남아있는 문제 발생
		OnClientJoin(id);

		InterlockedIncrement64(&sessionCnt);

		// 비동기 recv I/O 요청
		RecvPost(session);

		// accept에서 올린 참조카운트 감소
		if (0 == InterlockedDecrement64(&session->ioRefCount))
		{
			ReleaseSession(session);
		}
	}

	return true;
}

// Worker Thread
bool NetServer::WorkerThread_serv()
{
	DWORD threadID = GetCurrentThreadId();

	stSESSION* pSession = nullptr;
	BOOL bSuccess = true;
	long cbTransferred = 0;
	LPOVERLAPPED pOverlapped = nullptr;

	bool completionOK;
	// client가 send조차 하지않고 바로 disconnect 할 경우 -> WorkerThread에서 recv 0을 위한 GQCS가 깨어남
	while (true)
	{
		// 초기화
		cbTransferred = 0;
		pSession = nullptr;
		pOverlapped = nullptr;
		completionOK = false;

		// GQCS call
		bSuccess = GetQueuedCompletionStatus(IOCPHandle, (LPDWORD)&cbTransferred, (PULONG_PTR)&pSession,
			&pOverlapped, INFINITE);

		// IOCP Error or TIMEOUT or PQCS로 직접 NULL 던짐
		if (pOverlapped == NULL)
		{
			int iocpError = WSAGetLastError();

			// 모든 IOCP Worker Thread를 종료시키기 위한 PQCS를 호출함
			PostQueuedCompletionStatus(IOCPHandle, 0, 0, 0);
			logger->logger(dfLOG_LEVEL_ERROR, __LINE__, L"worker # iocp error %d", iocpError);
			break;
		}

		// SendPost 작업이 PQCS로 들어왔을 경우 
		if (cbTransferred == 0 && (unsigned char)pOverlapped == PQCSTYPE::SENDPOST)
		{
			// WSASend 1회 제한을 하기 위한 sendFlag를 다시 송신 가능 상태로 변경시킴
			InterlockedExchange8((char*)&pSession->sendFlag, false);
			
			// 다른 IOCP worker thread에 의해서 dequeue되어 sendQ가 비어버리면 SendPost 함수에 진입할 필요가 없음
			if (pSession->sendQ.GetSize() > 0)
				SendPost(pSession);
		}
		// SendPost 작업을 한 이후, 일정 시간이 지나면 연결을 끊음
		else if (cbTransferred == 0 && (unsigned char)pOverlapped == PQCSTYPE::SENDPOSTDICONN)
		{
			// WSASend 1회 제한을 하기 위한 sendFlag를 다시 송신 가능 상태로 변경시킴
			InterlockedExchange8((char*)&pSession->sendFlag, false);

			// 다른 IOCP worker thread에 의해서 dequeue되어 sendQ가 비어버리면 함수에 진입할 필요가 없음
			if (pSession->sendQ.GetSize() > 0)
				SendPostReservedDisconnect(pSession);
		}
		// rlease
		else if (cbTransferred == 0 && (unsigned char)pOverlapped == PQCSTYPE::RELEASE)
		{
			// ioRefCount가 0인 경우에 PQCS로 IOCP 포트로 enqueue한 것이므로
			// 이미 이 시점에 ioRefCount는 0임 -> continue로 넘겨야 하단에 ioRefCount를 내려주는 로직 skip 가능
			ReleaseSession(pSession);
			continue;
		}
		// Send / Recv Proc
		else if (pOverlapped == &pSession->m_stRecvOverlapped && cbTransferred > 0)
		{
			completionOK = RecvProc(pSession, cbTransferred);
		}
		else if (pOverlapped == &pSession->m_stSendOverlapped && cbTransferred > 0)
		{
			completionOK = SendProc(pSession, cbTransferred);
		}

		// I/O 완료 통지가 더이상 없다면 세션 해제 작업
		if (0 == InterlockedDecrement64(&pSession->ioRefCount))
		{
			ReleaseSession(pSession);
		}
	}

	return true;
}

// 타임아웃 관리를 위한 스레드
bool NetServer::TimeoutThread_serv()
{
	// 2초마다 타임아웃 갱신 (2초 내외의 타임아웃 오차는 허용)
	while (1)
	{
		// 서버의 현재 시간
		// 세션들이 서버의 현재 시간을 기준으로 타임아웃 됐는지 판별하기 위해 필요
		mServerTime = timeGetTime();

		for (int i = 0; i < mMaxAcceptCount; i++)
		{
			// 이 사이에 다른 곳에서 재할당되어 다른 세션이 될 수도 있으니 미리 sessionID 셋팅
			uint64_t sessionID = SessionArray[i].sessionID;

			// 이미 release 된 상태 skip
			if ((InterlockedOr64((LONG64*)&SessionArray[i].ioRefCount, 0) & RELEASEMASKING) != 0) continue;

			// 아직 소켓 할당이 안 된 상태 skip
			if (SessionArray[i].m_socketClient == INVALID_SOCKET) continue;

			// 이미 disconnect 된 상태 skip
			if (SessionArray[i].isDisconnected == true) continue;

			// 재할당되어 다른 세션이 된 상태 skip
			if (sessionID != SessionArray[i].sessionID) continue;

			// 세션에 부여된 타임아웃 예정 시간(Timer)이 현재 서버 시간보다 미래인 상태 (타임아웃까지 여유있음) skip
			if (InterlockedOr((LONG*)&SessionArray[i].Timer, 0) >= mServerTime) continue;

			// ----------------------------------------------------------------------
			// 이곳에 진입한 세션들은 타임아웃 시켜줘야 함
			//OnTimeout(sessionID);		// Contents 서버에서 타임아웃 관련 logic 처리

			// 타임아웃 예약 종료 건이라면 flag 다시 되돌려줌
			if (SessionArray[i].sendDisconnFlag == true)
				InterlockedExchange8((char*)&SessionArray[i].sendDisconnFlag, false);
		}

		Sleep(2000);
	}

	return true;
}

// 타임아웃 주기 : 현재 시간 ~ 서버의 타임아웃 시간 (ms 단위)
void NetServer::SetTimeout(stSESSION * session)
{
	InterlockedExchange(&session->Timer, timeGetTime() + mTimeout);
}

bool NetServer::RecvProc(stSESSION* pSession, long cbTransferred)
{
	pSession->recvRingBuffer.MoveWritePtr(cbTransferred);

	int useSize = pSession->recvRingBuffer.GetUseSize();

	// 보내고 끊기 예약이 되어있는 세션의 경우, 그 사이에 패킷이 와도 타임아웃 주기 업데이트를 하면 안됨
	// -> 만약 구분 없이 수신된 세션들의 주기를 모두 업데이트하면
	// 보내고 끊어야 되는 세션은 계속 타임아웃 주기가 갱신되어 끊기지 않음
	if (!pSession->sendDisconnFlag)
		SetTimeout(pSession);

	// Recv Message Process
	while (useSize > 0)
	{
		NetHeader header;

		// Header 크기만큼 있는지 확인
		if (useSize <= sizeof(NetHeader))
			break;

		// Header Peek
		pSession->recvRingBuffer.Peek((char*)&header, sizeof(NetHeader));

		// packet code 확인
		if (header.code != CPacket::GetCode())
		{
			DisconnectSession(pSession->sessionID);

			return false;
		}

		// Len 확인 (음수거나 받을 수 있는 패킷 크기보다 클 때
		if (header.len < 0 || header.len > MAX_PACKET_LEN)
		{
			DisconnectSession(pSession->sessionID);

			return false;
		}

		// Packet 크기만큼 있는지 확인
		if (useSize < sizeof(NetHeader) + header.len)
			break;

		// packet alloc
		CPacket* packet = CPacket::Alloc();

		// payload 크기만큼 데이터 Dequeue
		pSession->recvRingBuffer.Dequeue(packet->GetBufferPtr(), header.len + CPacket::en_PACKET::DEFAULT_HEADER_SIZE);

		// payload 크기만큼 packet write pos 이동
		packet->MoveWritePos(header.len);

		// 디코딩하여 원본 데이터 비교
		if (!packet->Decoding())
		{
			CPacket::Free(packet);

			DisconnectSession(pSession->sessionID);

			return false;
		}

		// Total Recv Message Count
		InterlockedIncrement64((LONG64*)&recvMsgCount);

		// Recv Message TPS
		InterlockedIncrement64((LONG64*)&recvMsgTPS);

		// Total Recv Bytes
		InterlockedAdd64((LONG64*)&recvBytes, header.len);

		// Recv Bytes TPS
		InterlockedAdd64((LONG64*)&recvBytesTPS, header.len);

		// 컨텐츠 쪽 recv 처리
		OnRecv(pSession->sessionID, packet);

		useSize = pSession->recvRingBuffer.GetUseSize();
	}

	// Recv 재등록
	RecvPost(pSession);


	return true;
}

bool NetServer::SendProc(stSESSION* pSession, long cbTransferred)
{
	// sendPost에서 사이즈 0일 경우를 걸러냈는데도 이 조건이 발생하는 경우는 error
	if (pSession->sendPacketCount == 0)
		return false;

	int totalSendBytes = 0;
	int iSendCount;

	// send 완료 통지된 패킷 제거
	for (iSendCount = 0; iSendCount < pSession->sendPacketCount; iSendCount++)
	{
		totalSendBytes += pSession->SendPackets[iSendCount]->GetDataSize();
		CPacket::Free(pSession->SendPackets[iSendCount]);
	}

	// Total Send Bytes
	InterlockedAdd64((long long*)&sendBytes, totalSendBytes);

	// Send Bytes TPS
	InterlockedAdd64((long long*)&sendBytesTPS, totalSendBytes);

	// Total Send Message Count
	InterlockedAdd64((long long*)&sendMsgCount, pSession->sendPacketCount);

	// Send Message TPS
	InterlockedAdd64((long long*)&sendMsgTPS, pSession->sendPacketCount);

	pSession->sendPacketCount = 0;

	// 전송 중 flag를 다시 미전송 상태로 되돌리기

	// 1회 send 후, sendQ에 쌓여있던 나머지 데이터 모두 send
	if (pSession->sendQ.GetSize() > 0)
	{
		if (pSession->sendFlag == false)
		{
			if (false == InterlockedExchange8((char*)&pSession->sendFlag, true))
			{
				InterlockedIncrement64(&pSession->ioRefCount);
				PostQueuedCompletionStatus(IOCPHandle, 0, (ULONG_PTR)pSession, (LPOVERLAPPED)PQCSTYPE::SENDPOST);
			}
		}
	}

	//// disconn flag가 올라가 있다면 disconnect
	//if (pSession->sendDisconnFlag)
	//{
	//	DisconnectSession(pSession->sessionID);

	//	InterlockedExchange8((char*)&pSession->sendDisconnFlag, false);
	//}

	return true;
}


bool NetServer::RecvPost(stSESSION* pSession)
{
	// recv 걸기 전에 외부에서 disconnect 호출될 수 있음
	// -> recv 안 걸렸을 때 io 취소해도 의미 없으니까 사전에 recvpost 막아버림
	if (pSession->isDisconnected)
		return false;

	// 링버퍼 등록
	WSABUF wsa[2] = { 0 };
	int wsaCnt = 1;
	DWORD flags = 0;

	int freeSize = pSession->recvRingBuffer.GetFreeSize();
	int directEequeueSize = pSession->recvRingBuffer.DirectEnqueueSize();

	if (freeSize == 0)
		return false;

	wsa[0].buf = pSession->recvRingBuffer.GetWriteBufferPtr();
	wsa[0].len = directEequeueSize;

	// 링버퍼 내부에서 빈 공간이 두 섹션으로 나뉠 경우
	if (freeSize > directEequeueSize)
	{
		wsa[1].buf = pSession->recvRingBuffer.GetBufferPtr();
		wsa[1].len = freeSize - directEequeueSize;
		++wsaCnt;
	}

	// recv overlapped I/O 구조체 reset
	ZeroMemory(&pSession->m_stRecvOverlapped, sizeof(OVERLAPPED));

	// recv
	// ioCount : WSARecv 완료 통지가 리턴보다 먼저 떨어질 수 있으므로 WSARecv 호출 전에 증가시켜야 함
	InterlockedIncrement64(&pSession->ioRefCount);
	int recvRet = WSARecv(pSession->m_socketClient, wsa, wsaCnt, NULL, &flags, &pSession->m_stRecvOverlapped, NULL);
	InterlockedIncrement64(&recvCallCount);
	InterlockedIncrement64(&recvCallTPS);

	// 예외처리
	if (recvRet == SOCKET_ERROR)
	{
		int recvError = WSAGetLastError();

		if (recvError != WSA_IO_PENDING)
		{
			if (recvError != ERROR_10054 && recvError != ERROR_10058 && recvError != ERROR_10060)
			{
				// 에러
				OnError(recvError, L"RecvPost # WSARecv Error\n");
			}

			// Pending이 아닐 경우, 완료 통지 실패
			if (0 == InterlockedDecrement64(&pSession->ioRefCount))
			{
				ReleaseSession(pSession);
			}
			return false;
		}
		// Pending일 경우
		else
		{
			InterlockedIncrement64(&recvPendingTPS);

			// Pending 걸렸는데, 이 시점에 disconnect되면 비동기 io 정리해줘야함
			if (pSession->isDisconnected)
			{
				CancelIoEx((HANDLE)pSession->m_socketClient, NULL);
			}

		}
	}

	return true;
}

bool NetServer::SendPost(stSESSION* pSession)
{
	// 1회 송신 제한을 위한 flag 확인 (send call 횟수 줄이려고 -> send call 자체가 느림
	// true면 최조 사용 아님
	// false -> true 면 최초 사용
	// true -> true 면 최초 사용이 아님
	if ((pSession->sendFlag == true) || true == InterlockedExchange8((char*)&pSession->sendFlag, true))
		return false;

	// SendQ가 비어있을 수 있음
	// -> 다른 스레드에서 Dequeue 진행했을 경우
	if (pSession->sendQ.GetSize() <= 0)
	{
		// * 일어날 수 있는 상황
		// 다른 스레드에서 dequeue를 전부 해서 size가 0이 돼서 이 조건문에 진입한건데
		// 이 위치에서 또다른 스레드에서 패킷이 enqueue되고 sendpost가 일어나게 되면
		// 아직 sendFlag가 false로 변경되지 않은 상태이기 때문에 sendpost 함수 상단 조건에 걸려 빠져나가게 됨
		// 그 후, 이 스레드로 다시 돌아오게 될 경우, 
		// sendQ에 패킷이 있는 상태이므로 sendFlas를 false로 바꿔주기만 하고 리턴하는게 아니라
		// 한번 더 sendQ의 size 확인 후 sendpost PQCS 날릴 지 결졍
		InterlockedExchange8((char*)&pSession->sendFlag, false);

		// 그 사이에 SendQ에 Enqueue 됐다면 다시 SendPost Call 
		if (pSession->sendQ.GetSize() > 0)
		{
			// sendpost 함수 내에서 send call을 1회 제한함
			// sendpost 함수를 호출하기 위한 PQCS도 1회 제한을 둬야 성능 개선됨
			// -> 그렇지 않을 경우, sendpacket 오는대로 계속 PQCS 호출하게 되어 성능이 생각한대로 안나올 수 있음 
			if (pSession->sendFlag == false)
			{
				if (false == InterlockedExchange8((char*)&pSession->sendFlag, true))
				{
					InterlockedIncrement64(&pSession->ioRefCount);
					PostQueuedCompletionStatus(IOCPHandle, 0, (ULONG_PTR)pSession, (LPOVERLAPPED)PQCSTYPE::SENDPOST);
				}
			}
		}
		return false;
	}

	int deqIdx = 0;

	// 링버퍼 등록
	WSABUF wsa[MAX_WSA_BUF] = { 0 };

	while (pSession->sendQ.Dequeue(pSession->SendPackets[deqIdx]))
	{
		// net 헤더포함 buffer ptr & len
		wsa[deqIdx].buf = pSession->SendPackets[deqIdx]->GetNetBufferPtr();
		wsa[deqIdx].len = pSession->SendPackets[deqIdx]->GetNetDataSize();

		deqIdx++;

		if (deqIdx >= MAX_WSA_BUF)
			break;
	}

	pSession->sendPacketCount = deqIdx;

	// send overlapped I/O 구조체 reset
	ZeroMemory(&pSession->m_stSendOverlapped, sizeof(OVERLAPPED));


	// send
	// ioCount : WSASend 완료 통지가 리턴보다 먼저 떨어질 수 있으므로 WSASend 호출 전에 증가시켜야 함
	InterlockedIncrement64(&pSession->ioRefCount);
	int sendRet = WSASend(pSession->m_socketClient, wsa, deqIdx, NULL, 0, &pSession->m_stSendOverlapped, NULL);
	InterlockedIncrement64(&sendCallCount);
	InterlockedIncrement64(&sendCallTPS);

	// 예외처리
	if (sendRet == SOCKET_ERROR)
	{
		int sendError = WSAGetLastError();

		// default error는 무시
		if (sendError != WSA_IO_PENDING)
		{
			if (sendError != ERROR_10054 && sendError != ERROR_10058 && sendError != ERROR_10060)
			{
				OnError(sendError, L"SendPost # WSASend Error\n");
			}

			// Pending이 아닐 경우, 완료 통지 실패 -> IOCount값 복원
			if (0 == InterlockedDecrement64(&pSession->ioRefCount))
			{
				ReleaseSession(pSession);
			}


			return false;
		}
		else
			InterlockedIncrement64(&sendPendingTPS);
	}

	return true;
}

// 송신 등록 - Packet 전송 후, 일정 시간이 지나면 연결을 끊어줌
bool NetServer::SendPostReservedDisconnect(stSESSION* pSession)
{
	// 1회 송신 제한을 위한 flag 확인 (send 함수 호출하는 작업 자체가 느리기 때문에 call 횟수를 줄이기 위해 사용)
	// false 면 미송신 상태이므로 send 작업 진행
	// true 면 송신 중이므로 완료 통지가 오기 전까지 send 작업을 하면 안됨
	if ((pSession->sendFlag == true) || true == InterlockedExchange8((char*)&pSession->sendFlag, true))
		return false;

	// 다른 스레드에서 Dequeue 진행했을 경우 SendQ가 비어버릴 수 있음
	if (pSession->sendQ.GetSize() <= 0)
	{
		// * 문제가 일어날 수 있는 상황
		// 다른 스레드에서 dequeue를 전부 해서 size가 0이 되어 이 조건문에 진입한건데
		// 이 위치에서 또다른 스레드에서 패킷이 enqueue되고 sendpost가 일어나게 되면
		// 아직 sendFlag가 false로 변경되지 않은 상태이기 때문에 sendpost 함수 상단 조건에 걸려 빠져나가게 됨
		// 그 후, 이 스레드로 다시 돌아오게 될 경우, 
		// sendQ에 패킷이 있는 상태이므로 sendFlas를 false로 바꿔주기만 하고 리턴하는게 아니라
		// 한번 더 sendQ의 size 확인 후 sendpost PQCS 날릴 지 결정해야 함
		InterlockedExchange8((char*)&pSession->sendFlag, false);

		// 그 사이에 SendQ에 Enqueue 됐다면 다시 SendPost Call 
		if (pSession->sendQ.GetSize() > 0)
		{
			// sendpost 함수 내에서 send call을 1회 제한함
			// sendpost 함수를 호출하기 위한 PQCS도 1회 제한을 둬야 성능 개선됨
			// -> 그렇지 않을 경우, sendpacket 오는대로 계속 PQCS 호출하게 되어 성능이 좋지 않을 수 있음 
			if (pSession->sendFlag == false)
			{
				if (false == InterlockedExchange8((char*)&pSession->sendFlag, true))
				{
					InterlockedIncrement64(&pSession->ioRefCount);
					PostQueuedCompletionStatus(IOCPHandle, 0, (ULONG_PTR)pSession, (LPOVERLAPPED)PQCSTYPE::SENDPOSTDICONN);
				}
			}
		}
		return false;
	}

	// 링버퍼 등록을 위한 변수
	WSABUF wsa[MAX_WSA_BUF] = { 0 };
	int deqIdx = 0;

	// sendQ에 쌓인 패킷들을 Dequeue하여 송신용 패킷 배열로 얻어옴
	while (pSession->sendQ.Dequeue(pSession->SendPackets[deqIdx]))
	{
		// 얻은 패킷을 WSABUF에 셋팅
		wsa[deqIdx].buf = pSession->SendPackets[deqIdx]->GetNetBufferPtr();
		wsa[deqIdx].len = pSession->SendPackets[deqIdx]->GetNetDataSize();

		deqIdx++;

		// WSABUF 전송 최대 갯수만큼 담음
		if (deqIdx >= MAX_WSA_BUF) break;
	}

	// 완료 통지 시, PacketPool에 반환할 패킷 갯수
	pSession->sendPacketCount = deqIdx;

	// send overlapped I/O 구조체 reset
	ZeroMemory(&pSession->m_stSendOverlapped, sizeof(OVERLAPPED));

	// send disconnect flag 올림 
	// 해당 flag가 올라가 있으면 예약종료 해야하는 Session이란 뜻이므로
	// 패킷이 수신돼도 timeout 주기를 업데이트하지 않음
	// -> Timeout Thread에서 timeout 된 걸 확인 후, 해당 flag보고 disconnect 처리
	InterlockedExchange8((char*)&pSession->sendDisconnFlag, true);

	// send 전에 타임아웃 주기 업데이트
	SetTimeout(pSession, pSession->Timeout);

	// send
	// ioCount : WSASend 완료 통지가 리턴보다 먼저 떨어질 수 있으므로 WSASend 호출 전에 증가시켜야 함
	InterlockedIncrement64(&pSession->ioRefCount);
	int sendRet = WSASend(pSession->m_socketClient, wsa, deqIdx, NULL, 0, &pSession->m_stSendOverlapped, NULL);
	InterlockedIncrement64(&sendCallCount);
	InterlockedIncrement64(&sendCallTPS);

	// 예외처리
	if (sendRet == SOCKET_ERROR)
	{
		int sendError = WSAGetLastError();

		// default error는 무시
		if (sendError != WSA_IO_PENDING)
		{
			if (sendError != ERROR_10054 && sendError != ERROR_10058 && sendError != ERROR_10060)
				OnError(sendError, L"SendPost # WSASend Error\n");

			// Pending이 아닐 경우, 완료 통지 실패 -> IOCount값 복원
			if (0 == InterlockedDecrement64(&pSession->ioRefCount))	
				ReleaseSession(pSession);

			return false;
		}
		else InterlockedIncrement64(&sendPendingTPS);
	}

	return true;
}

// Packet 전송 후, 일정 시간이 지나면 연결을 끊어줌
bool NetServer::SendPacketAndDisconnect(uint64_t sessionID, CPacket* packet, DWORD timeout)
{
	// Session Index를 찾을 후 Session 얻음
	int index = GetSessionIndex(sessionID);
	if (index < 0 || index >= mMaxAcceptCount) return false;

	stSESSION* pSession = &SessionArray[index];
	if (pSession == nullptr) return false;

	// 세션 사용 참조카운트 증가와 현재 세션이 Release 중인지 동시 확인 (인터락 연산으로 원자적 연산 보장)
	// Release 비트값이 1(ioRefCount에서 상위 31bit 위치를 Release flag처럼 사용)이면 Release 작업 진행 중이라는 의미
	// 어처피 다시 release가서 해제될 세션이므로 ioRefCount 감소 안해도 됨
	if ((InterlockedIncrement64(&pSession->ioRefCount) & RELEASEMASKING)) return false;

	// ------------------------------------------------------------------------------------
	// 이때부터는 Release 함수 진입도 못하고 온전히 SendPacket 과정을 진행할 수 있음

	// 해당 세션이 맞는지 다시 확인 (다른 곳에서 세션 해제 & 할당되어, 다른 세션이 됐을 수도 있음)
	// 해당 세션이 아닐 경우, 이전에 증가했던 ioCount를 되돌려놔야 함 (되돌리지 않으면 재할당 세션의 io가 0이 될 수가 없음)
	if (sessionID != pSession->sessionID)
	{
		// 외부 컨텐츠 로직의 성능 개선을 위해 Release 함수 처리도 PQCS 함수를 호출하여 비동기적으로 진행
		if (0 == InterlockedDecrement64(&pSession->ioRefCount))
			ReleasePQCS(pSession);

		return false;
	}

	// 외부 컨텐츠에서 disconnect 하는 상태
	if (pSession->isDisconnected)
	{
		if (0 == InterlockedDecrement64(&pSession->ioRefCount))
			ReleasePQCS(pSession);
		return false;
	}

	// 헤더 셋팅 & 인코딩
	packet->Encoding();

	// Enqueue한 패킷은 Dequeue하기 전까지 해제되면 안되기 때문에 패킷 참조카운트 증가 -> Dequeue할 때 감소
	packet->addRefCnt();

	// packet 포인터를 SendQ에 enqueue
	pSession->sendQ.Enqueue(packet);

	// sendpost 함수 내에서 send call을 1회 제한함
	// sendpost 함수를 호출하기 위한 PQCS도 1회 제한을 둬야 성능 개선됨
	// -> 그렇지 않을 경우, sendpacket 오는대로 계속 PQCS 호출하게 되어 성능이 생각한대로 안나올 수 있음 
	if (pSession->sendFlag == false)
	{
		if (false == InterlockedExchange8((char*)&pSession->sendFlag, true))
		{
			InterlockedIncrement64(&pSession->ioRefCount);

			// 해당 세션의 Timeout 설정 
			InterlockedExchange(&pSession->Timeout, timeout);

			// PQCS Call
			PostQueuedCompletionStatus(IOCPHandle, 0, (ULONG_PTR)pSession, (LPOVERLAPPED)PQCSTYPE::SENDPOSTDICONN);
		}
	}

	// sendPacket 함수에서 증가시킨 세션 참조 카운트 감소
	if (0 == InterlockedDecrement64(&pSession->ioRefCount))
	{
		ReleasePQCS(pSession);

		return false;
	}
}

bool NetServer::SendPacket(uint64_t sessionID, CPacket* packet)
{
	// find session할 때도 io 참조카운트 증가시켜서 보장받아야함	
	// index 찾기 -> out of indexing 예외 처리
	int index = GetSessionIndex(sessionID);
	if (index < 0 || index >= mMaxAcceptCount)
	{
		return false;
	}

	stSESSION* pSession = &SessionArray[index];

	if (pSession == nullptr)
	{
		return false;
	}

	// 세션 사용 참조카운트 증가 & Release 중인지 동시 확인
	// Release 비트값이 1이면 ReleaseSession 함수에서 ioCount = 0, releaseFlag = 1 인 상태
	// -> 이 사이에 Release 함수에서 ioCount도 0인걸 확인한 상태임 (decrement 안해도 됨)
	if ((InterlockedIncrement64(&pSession->ioRefCount) & RELEASEMASKING))
	{
		return false;
	}

	// ------------------------------------------------------------------------------------
	// Release 수행 없이 이곳에서만 세션 사용하려는 상태

	// 내 세션이 맞는지 다시 확인 (다른 곳에서 세션 해제 & 할당되어, 다른 세션이 됐을 수도 있음)
	// 내 세션이 아닐 경우, 이전에 증가했던 ioCount를 되돌려야 함 (되돌리지 않으면 재할당 세션의 io가 0이 될 수가 없음)
	if (sessionID != pSession->sessionID)
	{
		if (0 == InterlockedDecrement64(&pSession->ioRefCount))
		{
			ReleasePQCS(pSession);
		}

		return false;
	}

	// 외부에서 disconnect 하는 상태
	if (pSession->isDisconnected)
	{
		if (0 == InterlockedDecrement64(&pSession->ioRefCount))
		{
			ReleasePQCS(pSession);
		}

		return false;
	}

	// 헤더 셋팅 & 인코딩
	packet->Encoding();

	// Enqueue한 패킷을 다른 곳에서 사용하므로 패킷 참조카운트 증가 -> Dequeue할 때 감소
	packet->addRefCnt();

	// packet 포인터 enqueue
	pSession->sendQ.Enqueue(packet);

	// sendpost 함수 내에서 send call을 1회 제한함
	// sendpost 함수를 호출하기 위한 PQCS도 1회 제한을 둬야 성능 개선됨
	// -> 그렇지 않을 경우, sendpacket 오는대로 계속 PQCS 호출하게 되어 성능이 생각한대로 안나올 수 있음 
	if (pSession->sendFlag == false)
	{
		if (false == InterlockedExchange8((char*)&pSession->sendFlag, true))
		{
			InterlockedIncrement64(&pSession->ioRefCount);
			PostQueuedCompletionStatus(IOCPHandle, 0, (ULONG_PTR)pSession, (LPOVERLAPPED)PQCSTYPE::SENDPOST);
		}
	}

	// sendPacket 함수에서 증가시킨 세션 참조 카운트 감소
	if (0 == InterlockedDecrement64(&pSession->ioRefCount))
	{
		ReleasePQCS(pSession);

		return false;
	}
}

void NetServer::ReleaseSession(stSESSION* pSession)
{
	// 세션 송신 다 마치고 종료해야함 
	// 세션 메모리 정리
	// 소켓 정리
	// 세선 해제
	// ioCount == 0 && releaseFlag == 0 => release = 1 (인터락 함수로 해결)
	// 다른 곳에서 해당 세션을 사용하는지 확인
	if (InterlockedCompareExchange64(&pSession->ioRefCount, RELEASEMASKING, 0) != 0)
	{
		return;
	}

	//-----------------------------------------------------------------------------------
	// Release 실제 진입부
	//-----------------------------------------------------------------------------------
	//ioCount = 0, releaseFlag = 1 인 상태

	uint64_t sessionID = pSession->sessionID;

	pSession->sessionID = -1;

	SOCKET sock = pSession->m_socketClient;

	// 소켓 Invalid 처리하여 더이상 해당 소켓으로 I/O 못받게 함
	pSession->m_socketClient = INVALID_SOCKET;

	// recv는 더이상 받으면 안되므로 소켓 close
	closesocket(sock);

	InterlockedExchange8((char*)&pSession->sendFlag, false);

	Sleep(0);

	// Send Packet 관련 리소스 정리
	// SendQ에서 Dqeueue하여 SendPacket 배열에 넣었지만 아직 WSASend 못해서 남아있는 패킷 정리
	for (int iSendCount = 0; iSendCount < pSession->sendPacketCount; iSendCount++)
	{
		CPacket::Free(pSession->SendPackets[iSendCount]);
	}

	pSession->sendPacketCount = 0;

	// SendQ에 남아있다는 건 WSABUF에 꽂아넣지도 못한 상태 
	if (pSession->sendQ.GetSize() > 0)
	{
		CPacket* packet = nullptr;
		while (pSession->sendQ.Dequeue(packet))
		{
			CPacket::Free(packet);
		}
	}

	// 미사용 index를 stack에 push
	AvailableIndexStack.Push(GetSessionIndex(sessionID));

	// 사용자(Player) 관련 리소스 해제 (호출 후에 해당 세션이 사용되면 안됨)
	OnClientLeave(sessionID);

	// 접속중인 client 수 차감
	InterlockedDecrement64(&sessionCnt);

	// 접속 해제한 clinet 수 증가
	InterlockedIncrement64(&releaseCount);
	InterlockedIncrement64(&releaseTPS);
}

bool NetServer::DisconnectSession(uint64_t sessionID)
{
	// 세션 검색
	// index 찾기
	int index = GetSessionIndex(sessionID);
	if (index < 0 || index >= mMaxAcceptCount)
	{
		return false;
	}

	stSESSION* pSession = &SessionArray[index];

	if (pSession == nullptr)
	{
		return false;
	}

	// 세션 사용 참조카운트 증가 & Release 중인지 동시 확인
	// Release 비트값이 1이면 ReleaseSession 함수에서 ioCount = 0, releaseFlag = 1 인 상태
	// 어처피 다시 release가서 해제될 세션이므로 ioRefCount 감소시키지 않아도 됨
	if (InterlockedIncrement64(&pSession->ioRefCount) & RELEASEMASKING)
	{
		return false;
	}

	// Release 수행 없이 이곳에서만 세션 사용하려는 상태

	// 내 세션이 맞는지 다시 확인 (다른 곳에서 세션 해제&할당되어, 다른 세션이 됐을 수도 있음)
	// -> 이미 외부에서 disconnect 된 다음 accept되어 새로 session이 할당되었을 경우
	// 이전에 증가했던 ioCount를 되돌려야 함 (0이면 Release 진행)
	if (sessionID != pSession->sessionID)
	{
		if (0 == InterlockedDecrement64(&pSession->ioRefCount))
		{
			ReleasePQCS(pSession);
		}

		return false;
	}

	// 외부에서 disconnect 하는 상태
	if (pSession->isDisconnected)
	{
		if (0 == InterlockedDecrement64(&pSession->ioRefCount))
		{
			ReleasePQCS(pSession);
		}

		return false;
	}

	// ------------------------ Disconnect 확정 ------------------------
	// 그냥 closesocket을 하게 되면 closesocket 함수와 CancelIoEx 함수 사이에서 해제된 세션이 
	// 재할당되어 다른 세션이 될 수 있음
	// 그때 재할당된 세션의 IO 작업들이 CancelIoEx에 의해 제거되는 문제 발생
	// disconnected flag를 true로 변경하면 sendPacket 과 recvPost 함수 진입을 막음
	InterlockedExchange8((char*)&pSession->isDisconnected, true);

	// 현재 IO 작업 모두 취소
	CancelIoEx((HANDLE)pSession->m_socketClient, NULL);

	// Disconnect 함수에서 증가시킨 세션 참조 카운트 감소
	if (0 == InterlockedDecrement64(&pSession->ioRefCount))
	{
		ReleasePQCS(pSession);

		return false;
	}

	return true;
}

void NetServer::Stop()
{
	// stop 함수 추후 구현 완료

	// worker thread로 종료 PQCS 날김
	for (int i = 0; i < mWorkerThreadCount; i++)
	{
		PostQueuedCompletionStatus(IOCPHandle, 0, 0, 0);
	}


	WaitForMultipleObjects(mWorkerThreadCount, &mWorkerThreads[0], TRUE, INFINITE);
	closesocket(ListenSocket);

	WaitForSingleObject(mAcceptThread, INFINITE);
	WaitForSingleObject(mTimeoutThread, INFINITE);

	CloseHandle(ExitEvent);
	CloseHandle(RunEvent);
	CloseHandle(IOCPHandle);
	CloseHandle(mAcceptThread);
	CloseHandle(mTimeoutThread);

	for (int i = 0; i < mWorkerThreadCount; i++)
		CloseHandle(mWorkerThreads[i]);

	if (SessionArray != nullptr)
		delete[] SessionArray;

	WSACleanup();
}
