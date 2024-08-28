#include "../PCH.h"
#include "LanClient.h"

// ========================================================================
// Thread Call
// ========================================================================

// Worker Thread Call
unsigned __stdcall LanWorkerThread(void* param)
{
	LanClient* lanServ = (LanClient*)param;

	lanServ->LanWorkerThread_serv();

	return 0;
}


LanClient::LanClient() :  IOCPHandle(0), mIP{ 0 }, mPORT(0), mWorkerThreads{ 0 }, recvMsgTPS(0), sendMsgTPS(0),
recvMsgCount(0), sendMsgCount(0), recvCallTPS(0), sendCallTPS(0), recvCallCount(0), sendCallCount(0), recvPendingTPS(0), sendPendingTPS(0),
recvBytesTPS(0), sendBytesTPS(0), recvBytes(0), sendBytes(0), s_workerThreadCount(0), s_runningThreadCount(0), startMonitering(false)
{
	// ========================================================================
	// Initialize
	// ========================================================================
	wprintf(L"LanClient Initializing...\n");

	mSession.sessionID = -1;
	mSession.m_socketClient = INVALID_SOCKET;
	ZeroMemory(mSession.IP_str, sizeof(mSession.IP_str));
	mSession.IP_num = 0;
	mSession.PORT = 0;
	//LastRecvTime = 0;

	ZeroMemory(&mSession.m_stRecvOverlapped, sizeof(OVERLAPPED));
	ZeroMemory(&mSession.m_stSendOverlapped, sizeof(OVERLAPPED));
	mSession.recvRingBuffer.ClearBuffer();

	mSession.sendPacketCount = 0;
	mSession.ioRefCount = 0;			// accept ���� �ٷ� recv �ɾ������ ������ �׻� default�� 1
	mSession.sendFlag = false;
	mSession.isDisconnected = false;
	mSession.isUsed = false;

	mOk = false;

	logger = new Log(L"LanClient");

	WSADATA  wsaData;

	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
	{
		int initError = WSAGetLastError();

		return;
	}
}

LanClient::~LanClient()
{
	Stop();
}

bool LanClient::Start(const wchar_t* IP, unsigned short PORT, int createWorkerThreadCnt, int runningWorkerThreadCnt, bool nagelOff) 
{
	wmemcpy_s(mIP, wcslen(IP) + 1, IP, wcslen(IP) + 1);
	mPORT = PORT;
	mNagleOff = nagelOff;

	SYSTEM_INFO si;
	GetSystemInfo(&si);

	// CPU Core Counting
	// Worker Thread ������ 0 ���϶��, �ھ� ���� * 2 �� �缳��
	if (createWorkerThreadCnt <= 0)
		s_workerThreadCount = si.dwNumberOfProcessors * 2;
	else
		s_workerThreadCount = createWorkerThreadCnt;
	
	// Running Thread�� CPU Core ������ �ʰ��Ѵٸ� CPU Core ������ �缳��
	if (runningWorkerThreadCnt > si.dwNumberOfProcessors)
		s_runningThreadCount = si.dwNumberOfProcessors;
	else
		s_runningThreadCount = runningWorkerThreadCnt;

	// Create I/O Completion Port
	IOCPHandle = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, NULL, s_runningThreadCount);
	if (IOCPHandle == NULL)
	{
		int iocpError = WSAGetLastError();
		
		return false;
	}

	// ========================================================================
	// Create Thread
	// ======================================================================== 
 
	// Worker Thread
	mWorkerThreads.resize(s_workerThreadCount);
	for (int i = 0; i < mWorkerThreads.size(); i++)
	{
		mWorkerThreads[i] = (HANDLE)_beginthreadex(NULL, 0, LanWorkerThread, this, 0, NULL);
		if (mWorkerThreads[i] == NULL)
		{
			int threadError = GetLastError();

			return false;
		}
	}

	return true;
}

bool LanClient::Connect()
{
	// �̹� �������� ������ �� �����ϸ� �ȵ�
	if (mSession.isUsed == true)
	{
		DisconnectSession();
		return false;
	}

	if (mSession.m_socketClient != INVALID_SOCKET)
		return false;


	// Create Socket
	mSession.m_socketClient = socket(AF_INET, SOCK_STREAM, 0);
	if (INVALID_SOCKET == mSession.m_socketClient)
	{
		int sockError = WSAGetLastError();

		return false;
	}
	
	// TCP Send Buffer Remove - zero copy
	int sendVal = 0;
	if (setsockopt(mSession.m_socketClient, SOL_SOCKET, SO_SNDBUF, (const char*)&sendVal, sizeof(sendVal)) == SOCKET_ERROR)
	{
		int setsockoptError = WSAGetLastError();

		return false;
	}

	if (mNagleOff)
	{
		// Nagle off
		if (setsockopt(mSession.m_socketClient, IPPROTO_TCP, TCP_NODELAY, (const char*)&mNagleOff, sizeof(mNagleOff)) == SOCKET_ERROR)
		{
			int setsockoptError = WSAGetLastError();

			return false;
		}
	}

	// TIME_WAIT off
	struct linger ling;
	ling.l_onoff = 1;
	ling.l_linger = 0;
	if (setsockopt(mSession.m_socketClient, SOL_SOCKET, SO_LINGER, (const char*)&ling, sizeof(ling)) == SOCKET_ERROR)
	{
		int setsockoptError = WSAGetLastError();

		return false;
	}

	SOCKADDR_IN serverAddr;
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons(mPORT);
	InetPtonW(AF_INET, mIP, &serverAddr.sin_addr);
	
	// ���� ���� ī��Ʈ�� �÷���
	InterlockedExchange64(&mSession.ioRefCount, 1);

	if (connect(mSession.m_socketClient, (SOCKADDR*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR)
	{
		int connectError = WSAGetLastError();

		// ���� ó�� ���� ����
		//closesocket(pSession->m_socketClient);
		//pSession->m_socketClient = INVALID_SOCKET;

		closesocket(mSession.m_socketClient);
		mSession.m_socketClient = INVALID_SOCKET;

		return false;
	}

	// ������ ���ο� �����ִ� �� ó��
	mSession.recvRingBuffer.ClearBuffer();
	ZeroMemory(&mSession.m_stSendOverlapped, sizeof(OVERLAPPED));
	ZeroMemory(&mSession.m_stRecvOverlapped, sizeof(OVERLAPPED));

	// ����flag ����
	InterlockedExchange8((char*)&mSession.isDisconnected, false);

	InterlockedExchange8((char*)&mSession.isUsed, true);

	InterlockedExchange8((char*)&mSession.sendFlag, false);

	if (CreateIoCompletionPort((HANDLE)mSession.m_socketClient, IOCPHandle, (ULONG_PTR)&mSession, 0) == NULL)
	{
		int ciocpError = WSAGetLastError();

		closesocket(mSession.m_socketClient);
		mSession.m_socketClient = INVALID_SOCKET;

		CloseHandle(IOCPHandle);

		return false;
	}

	OnClientJoin();

	RecvPost();

	// �ø� ����ī��Ʈ ����
	if (0 == InterlockedDecrement64(&mSession.ioRefCount))
	{
		ReleaseSession();
	}

	
	return true;
}

// Worker Thread
bool LanClient::LanWorkerThread_serv()
{
	DWORD threadID = GetCurrentThreadId();

	stSESSION* pSession = nullptr;
	BOOL bSuccess = true;
	long cbTransferred = 0;
	LPOVERLAPPED pOverlapped = nullptr;

	bool completionOK;

	while (true)
	{
		// �ʱ�ȭ
		cbTransferred = 0;
		pSession = nullptr;
		pOverlapped = nullptr;
		completionOK = false;

		// GQCS call
			// client�� send���� �����ʰ� �ٷ� disconnect �� ��� -> WorkerThread���� recv 0�� ���� GQCS�� ���
		bSuccess = GetQueuedCompletionStatus(IOCPHandle, (LPDWORD)&cbTransferred, (PULONG_PTR)&pSession,
			&pOverlapped, INFINITE);

		// IOCP Error or TIMEOUT or PQCS�� ���� NULL ����
		// ���� ����������� error counting�� �Ͽ� 5ȸ �̻� �߻����� ��, ���� �۾� ���� ���̵� �ֱ� ��
		// �Ϸ������� �ȿ��� ���, �̹� ������ skip
		if (pOverlapped == NULL)
		{
			int iocpError = WSAGetLastError();
			PostQueuedCompletionStatus(IOCPHandle, 0, 0, 0);
			break;
		}

		// Send / Recv Proc
		else if (pOverlapped == &pSession->m_stRecvOverlapped && cbTransferred > 0)
		{
			completionOK = RecvProc(cbTransferred);
		}
		else if (pOverlapped == &pSession->m_stSendOverlapped && cbTransferred > 0)
		{
			completionOK = SendProc(cbTransferred);
		
		}

		// I/O �Ϸ� ������ ���̻� ���ٸ� ���� ���� �۾�
		if (0 == InterlockedDecrement(&pSession->ioRefCount))
		{
			ReleaseSession();
		}

	}

	return true;
}

bool LanClient::RecvProc(long cbTransferred)
{
	mSession.recvRingBuffer.MoveWritePtr(cbTransferred);

	int useSize = mSession.recvRingBuffer.GetUseSize();

	// Recv Message Process
	while (useSize > 0)
	{
		LanHeader header;

		// Header ũ�⸸ŭ �ִ��� Ȯ��
		if (useSize <= sizeof(LanHeader))
			break;

		// Header Peek
		mSession.recvRingBuffer.Peek((char*)&header, sizeof(LanHeader));

		// Len Ȯ�� (���̷ε� ���� Ȯ��)
		if (header.len <= 0 || header.len > CPacket::en_PACKET::eBUFFER_DEFAULT)
		{
			DisconnectSession();

			return false;
		}

		// Packet ũ�⸸ŭ �ִ��� Ȯ��
		if (useSize < sizeof(LanHeader) + header.len)
		{
			//// ��Ŷ ���̰� ���� ������ ������� ũ�� �ȵ�
			//if (header.len > mSession.recvRingBuffer.GetFreeSize())
			//{
			//	DisconnectSession();
			//	return false;
			//}

			break;
		}

		// packet alloc
		CPacket* packet = CPacket::Alloc();

		// payload ũ�⸸ŭ ������ Dequeue
		mSession.recvRingBuffer.Dequeue(packet->GetLanBufferPtr(), header.len + CPacket::en_PACKET::LAN_HEADER_SIZE);

		// payload ũ�⸸ŭ packet write pos �̵�
		packet->MoveWritePos(header.len);

		// Total Recv Message Count
		InterlockedIncrement64((LONG64*)&recvMsgCount);

		// Recv Message TPS
		InterlockedIncrement64((LONG64*)&recvMsgTPS);

		// Total Recv Bytes
		InterlockedAdd64((LONG64*)&recvBytes, header.len);

		// Recv Bytes TPS
		InterlockedAdd64((LONG64*)&recvBytesTPS, header.len);

		// ������ �� recv ó��
		OnRecv(packet);

		useSize = mSession.recvRingBuffer.GetUseSize();
	}

	// Recv ����
	RecvPost();


	return true;
}

bool LanClient::SendProc(long cbTransferred)
{
	// sendPost���� ������ 0�� ��츦 �ɷ��´µ��� �� ������ �߻��ϴ� ���� error
	if (mSession.sendPacketCount == 0)
		CRASH();

	int totalSendBytes = 0;
	int iSendCount;

	// send �Ϸ� ������ ��Ŷ ����
	for (iSendCount = 0; iSendCount < mSession.sendPacketCount; iSendCount++)
	{
		totalSendBytes += mSession.SendPackets[iSendCount]->GetDataSize();
		CPacket::Free(mSession.SendPackets[iSendCount]);
	}

	// Total Send Bytes
	InterlockedAdd64((long long*)&sendBytes, totalSendBytes);

	// Send Bytes TPS
	InterlockedAdd64((long long*)&sendBytesTPS, totalSendBytes);

	// Total Send Message Count
	InterlockedAdd64((long long*)&sendMsgCount, mSession.sendPacketCount);

	// Send Message TPS
	InterlockedAdd64((long long*)&sendMsgTPS, mSession.sendPacketCount);

	mSession.sendPacketCount = 0;

	// ���� �� flag�� �ٽ� ������ ���·� �ǵ�����
	InterlockedExchange8((char*)&mSession.sendFlag, false);

	// 1ȸ send ��, sendQ�� �׿��ִ� ������ ������ ��� send
	if (mSession.sendQ.GetSize() > 0)
	{
		// sendFlag�� false�ΰ� �ѹ� Ȯ���� ������ ���Ͷ� �� (������� �� ���̿� true�� ��찡 �ɷ����� ���Ͷ� call ����)
		if (mSession.sendFlag == false)
		{
			SendPost();
			//if (false == InterlockedExchange8((char*)&sendFlag, true))
			//{
			//	InterlockedIncrement64(&ioRefCount);
			//	PostQueuedCompletionStatus(IOCPHandle, 0, (ULONG_PTR)&mServerSock, (LPOVERLAPPED)PQCSTYPE::SENDPOST);
			//}
		}
	}

	return true;
}


bool LanClient::RecvPost()
{
	// recv �ɱ� ���� �ܺο��� disconnect ȣ��� �� ����
	// -> recv �� �ɷ��� �� io ����ص� �ǹ� �����ϱ� ������ recvpost ���ƹ���
	if (mSession.isDisconnected)
		return false;

	if (mSession.recvRingBuffer.GetFreeSize() <= 0)
	{
		DisconnectSession();

		return false;
	}

	// ������ ���
	WSABUF wsa[2] = { 0 };
	int wsaCnt = 1;
	DWORD flags = 0;

	int freeSize = mSession.recvRingBuffer.GetFreeSize();
	int directEequeueSize = mSession.recvRingBuffer.DirectEnqueueSize();

	if (freeSize == 0)
		return false;

	wsa[0].buf = mSession.recvRingBuffer.GetWriteBufferPtr();
	wsa[0].len = directEequeueSize;

	// ������ ���ο��� �� ������ �� �������� ���� ���
	if (freeSize > directEequeueSize)
	{
		wsa[1].buf = mSession.recvRingBuffer.GetBufferPtr();
		wsa[1].len = freeSize - directEequeueSize;
		++wsaCnt;
	}

	// recv overlapped I/O ����ü reset
	ZeroMemory(&mSession.m_stRecvOverlapped, sizeof(OVERLAPPED));

	// recv
	// ioCount : WSARecv �Ϸ� ������ ���Ϻ��� ���� ������ �� �����Ƿ� WSARecv ȣ�� ���� �������Ѿ� ��
	InterlockedIncrement64(&mSession.ioRefCount);
	int recvRet = WSARecv(mSession.m_socketClient, wsa, wsaCnt, NULL, &flags, &mSession.m_stRecvOverlapped, NULL);
	InterlockedIncrement64(&recvCallCount);
	InterlockedIncrement64(&recvCallTPS);

	// ����ó��
	if (recvRet == SOCKET_ERROR)
	{
		int recvError = WSAGetLastError();

		if (recvError != WSA_IO_PENDING)
		{
			if (recvError != ERROR_10054 && recvError != ERROR_10058 && recvError != ERROR_10060)
			{
				// ����				
				OnError(recvError, L"RecvPost # WSARecv Error\n");
			}

			// Pending�� �ƴ� ���, �Ϸ� ���� ����
			if (0 == InterlockedDecrement64(&mSession.ioRefCount))
			{
				ReleaseSession();
			}
			return false;
		}
		// Pending�� ���
		else
		{
			InterlockedIncrement64(&recvPendingTPS);

			// Pending �ɷȴµ�, �� ������ disconnect�Ǹ� �� �� �����ִ� �񵿱� io �����������
			if (mSession.isDisconnected)
			{
				CancelIoEx((HANDLE)mSession.m_socketClient, &mSession.m_stRecvOverlapped);
			}

		}
	}

	return true;
}

bool LanClient::SendPost()
{
	// 1ȸ �۽� ������ ���� flag Ȯ�� (send call Ƚ�� ���̷��� -> send call ��ü�� ����
	// true�� ���� ��� �ƴ�
	// false -> true �� ���� ���
	// true -> true �� ���� ����� �ƴ�
	if ((mSession.sendFlag == true) || true == InterlockedExchange8((char*)&mSession.sendFlag, true))
		return false;

	// SendQ�� ������� �� ����
	// -> �ٸ� �����忡�� Dequeue �������� ���
	if (mSession.sendQ.GetSize() <= 0)
	{
		// * �Ͼ �� �ִ� ��Ȳ
		// �ٸ� �����忡�� dequeue�� ���� �ؼ� size�� 0�� �ż� �� ���ǹ��� �����Ѱǵ�
		// �� ��ġ���� �Ǵٸ� �����忡�� ��Ŷ�� enqueue�ǰ� sendpost�� �Ͼ�� �Ǹ�
		// ���� sendFlag�� false�� ������� ���� �����̱� ������ sendpost �Լ� ��� ���ǿ� �ɷ� ���������� ��
		// �� ��, �� ������� �ٽ� ���ƿ��� �� ���, 
		// sendQ�� ��Ŷ�� �ִ� �����̹Ƿ� sendFlas�� false�� �ٲ��ֱ⸸ �ϰ� �����ϴ°� �ƴ϶�
		// �ѹ� �� sendQ�� size Ȯ�� �� sendpost PQCS ���� �� ����

		InterlockedExchange8((char*)&mSession.sendFlag, false);

		// �� ���̿� SendQ�� Enqueue �ƴٸ� �ٽ� SendPost Call 
		if (mSession.sendQ.GetSize() > 0)
		{
			// sendpost �Լ� ������ send call�� 1ȸ ������
			// sendpost �Լ��� ȣ���ϱ� ���� PQCS�� 1ȸ ������ �־� ���� ������
			// -> �׷��� ���� ���, sendpacket ���´�� ��� PQCS ȣ���ϰ� �Ǿ� ������ �����Ѵ�� �ȳ��� �� ���� 
			if (mSession.sendFlag == false)
			{
				SendPost();
				//if (false == InterlockedExchange8((char*)&sendFlag, true))
				//{
				//	InterlockedIncrement64(&ioRefCount);
				//	PostQueuedCompletionStatus(IOCPHandle, 0, (ULONG_PTR)&mServerSock, (LPOVERLAPPED)PQCSTYPE::SENDPOST);
				//}
			}
		}
		return false;
	}

	int deqIdx = 0;

	// ������ ���
	WSABUF wsa[MAXWSABUF] = { 0 };

	int totalSendSize = 0;

	while (mSession.sendQ.Dequeue(mSession.SendPackets[deqIdx]))
	{
		// ��Ŷ ���� ������ (����� ������)
		wsa[deqIdx].buf = mSession.SendPackets[deqIdx]->GetLanBufferPtr();

		// ��Ŷ ũ�� (��� ����)
		wsa[deqIdx].len = mSession.SendPackets[deqIdx]->GetLanDataSize();

		totalSendSize += wsa[deqIdx].len;

		deqIdx++;

		if (deqIdx >= MAXWSABUF)
			break;
	}

 	mSession.sendPacketCount = deqIdx;

	// send overlapped I/O ����ü reset
	ZeroMemory(&mSession.m_stSendOverlapped, sizeof(OVERLAPPED));

	// send
	// ioCount : WSASend �Ϸ� ������ ���Ϻ��� ���� ������ �� �����Ƿ� WSASend ȣ�� ���� �������Ѿ� ��
	InterlockedIncrement64(&mSession.ioRefCount);
	int sendRet = WSASend(mSession.m_socketClient, wsa, deqIdx, NULL, 0, &mSession.m_stSendOverlapped, NULL);
	InterlockedIncrement64(&sendCallCount);
	InterlockedIncrement64(&sendCallTPS);
	
	// ����ó��
	if (sendRet == SOCKET_ERROR)
	{
		int sendError = WSAGetLastError();

		// default error�� ����
		if (sendError != WSA_IO_PENDING)
		{
			if (sendError != ERROR_10054 && sendError != ERROR_10058 && sendError != ERROR_10060)
			{
				OnError(sendError, L"SendPost # WSASend Error\n");
			}

			// Pending�� �ƴ� ���, �Ϸ� ���� ���� -> IOCount�� ����
			if (0 == InterlockedDecrement64(&mSession.ioRefCount))
			{
				ReleaseSession();
			}

			return false;
		}
		else
			InterlockedIncrement64(&sendPendingTPS);
	}

	return true;
}


bool LanClient::SendPacket(CPacket* packet)
{
	// ���� ��� ����ī��Ʈ ���� & Release ������ ���� Ȯ��
	// Release ��Ʈ���� 1�̸� ReleaseSession �Լ����� ioCount = 0, releaseFlag = 1 �� ����
	// ��ó�� �ٽ� release���� ������ �����̹Ƿ� ioRefCount ���ҽ�Ű�� �ʾƵ� ��
	if (InterlockedIncrement64(&mSession.ioRefCount) & RELEASEMASKING)
	{
		return false;
	}

	// ------------------------------------------------------------------------------------
	// Release ���� ���� �̰������� ���� ����Ϸ��� ����

	// �ܺο��� disconnect �ϴ� ����
	if (mSession.isDisconnected)
	{
		if (0 == InterlockedDecrement64(&mSession.ioRefCount))
		{
			//ReleasePQCS();
			ReleaseSession();
		}

		return false;
	}

	// lan ��� ����
	packet->SetLanHeader();

	// Enqueue�� ��Ŷ�� �ٸ� ������ ����ϹǷ� ��Ŷ ����ī��Ʈ ���� -> Dequeue�� �� ����
	packet->addRefCnt();

	// packet ������ enqueue
	mSession.sendQ.Enqueue(packet);

	// sendpost �Լ� ������ send call�� 1ȸ ������
	// sendpost �Լ��� ȣ���ϱ� ���� PQCS�� 1ȸ ������ �־� ���� ������
	// -> �׷��� ���� ���, sendpacket ���´�� ��� PQCS ȣ���ϰ� �Ǿ� ������ �����Ѵ�� �ȳ��� �� ���� 
	if (mSession.sendFlag == false)
	{
		SendPost();
		//if (false == InterlockedExchange8((char*)&sendFlag, true))
		//{
		//	InterlockedIncrement64(&ioRefCount);
		//	PostQueuedCompletionStatus(IOCPHandle, 0, (ULONG_PTR)&mServerSock, (LPOVERLAPPED)PQCSTYPE::SENDPOST);
		//}
	}

	// sendPacket �Լ����� ������Ų ���� ���� ī��Ʈ ����
	if (0 == InterlockedDecrement64(&mSession.ioRefCount))
	{
		//ReleasePQCS();
		ReleaseSession();

		return false;
	}
}

void LanClient::ReleaseSession()
{
	// ���� �۽� �� ��ġ�� �����ؾ��� 
	// ���� �޸� ����
	// ���� ����
	// ���� ����
	// ioCount == 0 && releaseFlag == 0 => release = 1 (���Ͷ� �Լ��� �ذ�)
	// �ٸ� ������ �ش� ������ ���(sendpacket or disconnect)�ϴ��� Ȯ��
	if (InterlockedCompareExchange64(&mSession.ioRefCount, RELEASEMASKING, 0) != 0)
	{
		return;
	}

	//-----------------------------------------------------------------------------------
	// Release ���� ���Ժ�
	//-----------------------------------------------------------------------------------
	//ioCount = 0, releaseFlag = 1 �� ����

	uint64_t _sessionID = mSession.sessionID;

	mSession.sessionID = -1;

	SOCKET sock = mSession.m_socketClient;

	// ���� Invalid ó���Ͽ� ���̻� �ش� �������� I/O ���ް� ��
	mSession.m_socketClient = INVALID_SOCKET;

	InterlockedExchange8((char*)&mSession.sendFlag, false);

	// recv�� ���̻� ������ �ȵǹǷ� ���� close
	closesocket(sock);

	// Send Packet ���� ���ҽ� ����
	// SendQ���� Dqeueue�Ͽ� SendPacket �迭�� �־����� ���� WSASend ���ؼ� �����ִ� ��Ŷ ����
	for (int iSendCount = 0; iSendCount < mSession.sendPacketCount; iSendCount++)
	{
		CPacket::Free(mSession.SendPackets[iSendCount]);
	}

	mSession.sendPacketCount = 0;

	// SendQ�� �����ִٴ� �� WSABUF�� �ȾƳ����� ���� ���� 
	if (mSession.sendQ.GetSize() > 0)
	{
		CPacket* packet = nullptr;
		while (mSession.sendQ.Dequeue(packet))
		{
			CPacket::Free(packet);
		}
	}

	ZeroMemory(mSession.IP_str, sizeof(mSession.IP_str));
	mSession.IP_num = 0;
	mSession.PORT = 0;
	//LastRecvTime = 0;

	ZeroMemory(&mSession.m_stRecvOverlapped, sizeof(OVERLAPPED));
	ZeroMemory(&mSession.m_stSendOverlapped, sizeof(OVERLAPPED));
	mSession.recvRingBuffer.ClearBuffer();

	mSession.ioRefCount = 0;			// accept ���� �ٷ� recv �ɾ������ ������ �׻� default�� 1
	
	InterlockedExchange64(&mSession.ioRefCount, 0);
	InterlockedExchange8((char*)&mSession.isDisconnected, false);
	InterlockedExchange8((char*)&mSession.isUsed, false);

	// �����(Player) ���� ���ҽ� ���� (ȣ�� �Ŀ� �ش� ������ ���Ǹ� �ȵ�)
	OnClientLeave();
}

bool LanClient::DisconnectSession()
{
	// ���� ��� ����ī��Ʈ ���� & Release ������ ���� Ȯ��
	// Release ��Ʈ���� 1�̸� ReleaseSession �Լ����� ioCount = 0, releaseFlag = 1 �� ����
	// ��ó�� �ٽ� release���� ������ �����̹Ƿ� ioRefCount ���ҽ�Ű�� �ʾƵ� ��
	if (InterlockedIncrement64(&mSession.ioRefCount) & RELEASEMASKING)
	{
		return false;
	}

	// Release ���� ���� �̰������� ���� ����Ϸ��� ����

	// �ܺο��� disconnect �ϴ� ����
	if (mSession.isDisconnected)
	{
		if (0 == InterlockedDecrement64(&mSession.ioRefCount))
		{
			ReleaseSession();
			// ReleasePQCS();
		}

		return false;
	}

	// ------------------------ Disconnect Ȯ�� ------------------------
	// �׳� closesocket�� �ϰ� �Ǹ� closesocket �Լ��� CancelIoEx �Լ� ���̿��� ������ ������ 
	// ���Ҵ�Ǿ� �ٸ� ������ �� �� ����
	// �׶� ���Ҵ�� ������ IO �۾����� CancelIoEx�� ���� ���ŵǴ� ���� �߻�
	// disconnected flag�� true�� �����ϸ� sendPacket �� recvPost �Լ� ������ ����
	InterlockedExchange8((char*)&mSession.isDisconnected, true);

	// ���� IO �۾� ��� ���
	CancelIoEx((HANDLE)mSession.m_socketClient, NULL);

	// Disconnect �Լ����� ������Ų ���� ���� ī��Ʈ ����
	if (0 == InterlockedDecrement64(&mSession.ioRefCount))
	{
		ReleaseSession();
		//ReleasePQCS();

		return false;
	}

	return true;
}

void LanClient::Stop()
{
	// stop �Լ� ���� ���� �Ϸ�

	// worker thread�� ���� PQCS ����
	for (int i = 0; i < s_workerThreadCount; i++)
	{
		PostQueuedCompletionStatus(IOCPHandle, 0, 0, 0);
	}


	WaitForMultipleObjects(s_workerThreadCount, &mWorkerThreads[0], TRUE, INFINITE);

	closesocket(mSession.m_socketClient);

	CloseHandle(IOCPHandle);

	for (int i = 0; i < s_workerThreadCount; i++)
		CloseHandle(mWorkerThreads[i]);

	WSACleanup();
}