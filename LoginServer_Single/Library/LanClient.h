#ifndef __LanClient_CLASS__
#define __LanClient_CLASS__

#include "PCH.h"

// ���� ������ ��� ��� Ŭ����
class LanClient
{
public:
	LanClient();

	~LanClient();

	// ���� -> �翬�� �Լ� ���� �ʿ� 
	// (Ư�� Ű ������ �翬�� -> ����͸� ������ ���� �� �� ä�ü����� �����ϴ� ������ �ؼ�)
	bool Connect();

	// ���� ���� ����
	bool DisconnectSession();

	// ��Ŷ ����
	bool SendPacket(CPacket* packet);

	// Server Start
	bool Start(const wchar_t* IP, unsigned short PORT, int createWorkerThreadCnt, int runningWorkerThreadCnt, bool nagelOff);

	// Server Stop
	void Stop();

protected:
	// ==========================================================
	// ����ó�� �Ϸ� �� ȣ�� 
	// [PARAM] __int64 sessionID
	// [RETURN] X
	// ==========================================================
	virtual void OnClientJoin() = 0;

	// ==========================================================
	// �������� �� ȣ��, Player ���� ���ҽ� ����
	// [PARAM] __int64 sessionID
	// [RETURN] X 
	// ==========================================================
	virtual void OnClientLeave() = 0;

	// ==========================================================
	// ��Ŷ ���� �Ϸ� ��
	// [PARAM] __int64 sessionID, CPacket* packet
	// [RETURN] X 
	// ==========================================================
	virtual void OnRecv(CPacket* packet) = 0;

	// ==========================================================
	// Error Check
	// [PARAM] int errorCode, wchar_t* msg
	// [RETURN] X 
	// ==========================================================
	virtual void OnError(int errorCode, const wchar_t* msg) = 0;

private:
	friend unsigned __stdcall LanWorkerThread(void* param);

	bool LanWorkerThread_serv();

	// �ۼ��� ���� ��� ��, �ۼ��� �Լ� ȣ��
	bool RecvPost();
	bool SendPost();

	bool RecvProc(long cbTransferred);
	bool SendProc(long cbTransferred);

	// ���� ���ҽ� ���� �� ����
	void ReleaseSession();

	inline void ReleasePQCS()
	{
		PostQueuedCompletionStatus(IOCPHandle, 0, (ULONG_PTR)&mSession, (LPOVERLAPPED)PQCSTYPE::RELEASE);
	}


	// Ŭ���̾�Ʈ�� ����
private:
	stLanSESSION mSession;

	wchar_t mIP[16];											// Server IP
	unsigned short mPORT;										// Server Port

	bool mOk;

private:
	bool mNagleOff;

	HANDLE IOCPHandle;										// IOCP Handle

	std::vector<HANDLE> mWorkerThreads;							// Worker Threads Count

	long s_workerThreadCount;								// Worker Thread Count (Server)
	long s_runningThreadCount;								// Running Thread Count (Server)

	enum PQCSTYPE
	{
		SENDPOST = 100,
		SENDPOSTDICONN,
		RELEASE,
		STOP,
	};

protected:
	// logging
	Log* logger;

	// ����͸��� ���� (1�� ����)
	// ������ ���Ǹ� ���� TPS�� �� ������ 1�ʴ� �߻��ϴ� �Ǽ��� ���, �������� �� ���� �հ踦 ��Ÿ��
	__int64 connectTryTPS;
	__int64 connectSuccessTPS;
	__int64 connectCnt;
	__int64 connectFailCnt;
	__int64 recvMsgTPS;								// Recv Packet TPS
	__int64 sendMsgTPS;								// Send Packet TPS
	__int64 recvMsgCount;							// Total Recv Packet Count
	__int64 sendMsgCount;							// Total Send Packet Count
	__int64 recvCallTPS;							// Recv Call TPS
	__int64 sendCallTPS;							// Send Call TPS
	__int64 recvCallCount;							// Total Recv Call Count
	__int64 sendCallCount;							// Total Send Call Count
	__int64 recvPendingTPS;							// Recv Pending TPS
	__int64 sendPendingTPS;							// Send Pending TPS
	__int64 recvBytesTPS;							// Recv Bytes TPS
	__int64 sendBytesTPS;							// Send Bytes TPS
	__int64 recvBytes;								// Total Recv Bytes
	__int64 sendBytes;								// Total Send Bytes
	__int64 workerThreadCount;						// Worker Thread Count (Monitering)
	__int64 runningThreadCount;						// Running Thread Count (Monitering)
	bool startMonitering;
};

#endif // !__LanClient_CLASS__


