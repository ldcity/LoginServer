#include "RedisJobThread.h"
#include "../Utils/Profiling.h"
#include "LoginServer.h"

void RedisWorkerThread::Run()
{
	mRedis->Connect(redisIP, redisPort);

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
					// Redis DB�� key-value ����
				case REDISTYPE::SET:
					RedisSet(job);
					break;

				default:
					break;
				}
				
				mJobPool.Free(job);

				InterlockedIncrement64(&mJobThreadUpdateTPS);
				InterlockedIncrement64(&mJobThreadUpdateCnt);
			}
		}
	}
}

void RedisWorkerThread::RedisSet(Job* job)
{
	// �񵿱� redis set��û
	mRedis->AsyncSet(job->accountNo, job->sessionKey, 30, [=](const cpp_redis::reply& reply)
		{
			// redis set �Ϸ� �ݹ�
			if (reply.is_string() && reply.as_string() == "OK")
			{
				logServer->SendJob(job->sessionID, LoginServer::JobType::LOGIN_RES, job->packet);
			}
			else
			{
				// ���� ó��
				logServer->OnError(LoginServer::ErrorCode::REDISSETERROR, L"Redis Set failed!");

				CPacket::Free(job->packet);
			}
		});
}
