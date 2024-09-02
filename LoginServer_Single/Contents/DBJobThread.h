#ifndef __DB_WORKER_CLASS__
#define __DB_WORKER_CLASS__

#include "../Library/ThreadWorker.h"
#include "../Utils/DBConnection.h"
#include "../Library/SerializingBuffer.h"
#include "../Library/TLSFreeList.h"
#include "../Library/LockFreeQueue.h"

class LoginServer;

class DBWorkerThread : public ThreadWorker
{
public:
	enum DBTYPE
	{
		SELECT,  // select ��û
	};

private:
	// Job ����ü
	struct Job
	{
		WORD type;
		uint64_t sessionID;		// Session ���� ID
		std::wstring query;		// db ����
		CPacket* packet;
	};

	TLSObjectPool<Job> mJobPool = TLSObjectPool<Job>(200);
	LockFreeQueue<Job*> mJobQ = LockFreeQueue<Job*>(200);

	DBConnector* mDBConn;		// DB Connector

	LoginServer* mLogServer;

	Log* mLog;

	friend class LoginServer;

public:
	DBWorkerThread(LoginServer* _logServer, const wchar_t* host, const wchar_t* user, const wchar_t* password, const wchar_t* db, unsigned short port, bool sslOff)
	: mLogServer(_logServer),
		mDBPort(port),
		mSSLEnabled(!sslOff)  // sslOff�� false�� SSL Ȱ��ȭ, true�� ��Ȱ��ȭ
	{
		// wchar_t �迭 �ʱ�ȭ
		wcscpy_s(mDBHost, host);
		wcscpy_s(mDBUser, user);
		wcscpy_s(mDBPassword, password);
		wcscpy_s(mDBName, db);

		mDBConn = new DBConnector(mDBHost, mDBUser, mDBPassword, mDBName, mDBPort, mSSLEnabled);

		mLog = new Log(L"DBThread.txt");
	}

	~DBWorkerThread()
	{
		if (mDBConn)
			delete mDBConn;

		if (mLog)
			delete mLog;
	}

	void EnqueueJob(WORD type, uint64_t sessionID, const std::wstring query, CPacket* packet)
	{
		Job* job = mJobPool.Alloc();
		job->type = type;
		job->sessionID = sessionID;
		job->query = query;
		job->packet = packet;

		mJobQ.Enqueue(job);
		SignalEvent();
	}

	void Run() override;

public:
	void SelectProc(Job* job);
	void NetPacketProc_AccountSelect(Job* job);

	void MPResAccountSelect(CPacket* packet, INT64 accountNo, const char* SessionKey, const wchar_t* ID, const wchar_t* Nicnname);

// ����͸� ������
public:
	__int64 m_dbQueryTotal;
	__int64 m_dbQueryTPS;

private:
	wchar_t mDBHost[DBLENSIZE::SHORT_LEN];
	wchar_t mDBUser[DBLENSIZE::MIDDLE_LEN];
	wchar_t mDBPassword[DBLENSIZE::MIDDLE_LEN];
	wchar_t mDBName[DBLENSIZE::MIDDLE_LEN];
	unsigned short mDBPort;
	bool mSSLEnabled;
};


#endif 