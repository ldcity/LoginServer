#include "DBJobThread.h"
#include "../Utils/Profiling.h"
#include "LoginServer.h"
#include "../Utils/Protocol.h"
#include "Packet.h"

void DBWorkerThread::Run()
{
	mDBConn->Open();

	while (mRunFlag)
	{
		WaitForSingleObject(mEventHandle, INFINITE);

		Job* job = nullptr;

		// Queue�� Job�� ���� ������ update ����
		while (mJobQ.GetSize() > 0)
		{
			if (mJobQ.Dequeue(job))
			{
				switch (job->type)
				{
					// Select ���� ��û
				case DBTYPE::SELECT:
					SelectProc(job);
					break;

				default:
					break;
				}

				if (job->packet != nullptr)
					CPacket::Free(job->packet);

				mJobPool.Free(job);

				InterlockedIncrement64(&mJobThreadUpdateTPS);
				InterlockedIncrement64(&mJobThreadUpdateCnt);
			}
		}
	}
}

void DBWorkerThread::SelectProc(Job* job)
{
	WORD type;

	(*job->packet) >> type;

	switch (type)
	{
	case en_PACKET_SS_REQ_SELECT_ACCOUNT:
		NetPacketProc_AccountSelect(job);
		break;

	default:
		break;
	}
}

void DBWorkerThread::NetPacketProc_AccountSelect(Job* job)
{
	INT64 _accountNo;

	*(job->packet) >> _accountNo;

	char SessionKey[MSGMAXLEN + 1] = { 0 };

	uint64_t sessionID = job->sessionID;
	job->packet->GetData((char*)SessionKey, MSGMAXLEN);

	SessionKey[MSGMAXLEN] = '\0';
	wchar_t nonID[IDMAXLEN] = { 0 };
	wchar_t nonNickname[NICKNAMEMAXLEN] = { 0 };
	wchar_t chatIP[16] = { 0 };
	unsigned short chatPort = 0;
	wchar_t gameServerIp[16] = { 0 };
	USHORT gameServerPort = 0;

	// select ���� �ش� ���� �÷� �� ���� (��� ����)
	char id[IDMAXLEN] = { 0 };
	char nickname[NICKNAMEMAXLEN] = { 0 };

	// �Ű����� ���ε� & ���� ��û
	bool isDBSuccess = mDBConn->ExecuteQuery(job->query, [&, this](MYSQL_STMT* stmt, Log* dblog) -> bool {
		int fetchResult = mDBConn->FetchResult(stmt, id, nickname);

		// ����
		if (fetchResult == -1)
		{
			mLog->logger(dfLOG_LEVEL_ERROR, __LINE__, L"Result binding failed : %s", mysql_stmt_error(stmt));
			return false;
		}
		// ���̺� ���ڵ� ����
		else if (fetchResult == MYSQL_NO_DATA)
		{
			// account ���̺� �ش� ���� ������ ����
			BYTE status = en_PACKET_CS_LOGIN_RES_LOGIN::dfLOGIN_STATUS_ACCOUNT_MISS;

			CPacket* resLoginPacket = CPacket::Alloc();

			MPResLogin(resLoginPacket, _accountNo, status, nonID, nonNickname, gameServerIp, gameServerPort, chatIP, chatPort);
			mLogServer->SendJob(job->sessionID, LoginServer::JobType::LOGIN_RES, resLoginPacket);

			return false;
		}
		// ���̺� ���ڵ� ����
		else if (fetchResult == 0)
		{
			// ���� ���� - ���� ����
			wchar_t ID[IDMAXLEN] = { 0 };
			wchar_t Nickname[NICKNAMEMAXLEN] = { 0 };

			int length = MultiByteToWideChar(CP_UTF8, 0, id, strlen(id), NULL, NULL);
			MultiByteToWideChar(CP_UTF8, 0, id, strlen(id), ID, length);

			length = MultiByteToWideChar(CP_UTF8, 0, nickname, strlen(nickname), NULL, NULL);
			MultiByteToWideChar(CP_UTF8, 0, nickname, strlen(nickname), Nickname, length);

			CPacket* resLoginPacket = CPacket::Alloc();
			MPResAccountSelect(resLoginPacket, _accountNo, SessionKey, ID, Nickname);

			// ���� ������Ʈ �����忡 ������ ������ �۾� ����
			mLogServer->SendJob(job->sessionID, LoginServer::JobType::DB_RES, resLoginPacket);

			return true;
		}
		else
		{
			mLog->logger(dfLOG_LEVEL_ERROR, __LINE__, L"Error fetching result: : %s", mysql_stmt_error(stmt));
			return false;
		}
		return true;
	}, _accountNo, id, nickname);

	InterlockedIncrement64(&m_dbQueryTotal);
	InterlockedIncrement64(&m_dbQueryTPS);
}

void DBWorkerThread::MPResAccountSelect(CPacket* packet, INT64 accountNo, const char* SessionKey, const wchar_t* ID, const wchar_t* Nickname)
{
	WORD type = en_PACKET_SS_RES_SELECT_ACCOUNT;

	*packet << type << accountNo;

	packet->PutData((char*)SessionKey, MSGMAXLEN);
	packet->PutData((char*)ID, IDMAXLEN * sizeof(wchar_t));
	packet->PutData((char*)Nickname, NICKNAMEMAXLEN * sizeof(wchar_t));
}