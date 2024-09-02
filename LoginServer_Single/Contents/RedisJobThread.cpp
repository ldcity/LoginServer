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

		// Queue에 Job이 없을 때까지 update 수행
		while (mJobQ.GetSize() > 0)
		{
			if (mJobQ.Dequeue(job))
			{
				switch (job->type)
				{
					// Redis DB에 key-value 저장
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
	// 비동기 redis set요청
	mRedis->AsyncSet(job->accountNo, job->sessionKey, 30, [=](const cpp_redis::reply& reply)
		{
			// redis set 완료 콜백
			if (reply.is_string() && reply.as_string() == "OK")
			{
				logServer->SendJob(job->sessionID, LoginServer::JobType::LOGIN_RES, job->packet);
			}
			else
			{
				// 실패 처리
				logServer->OnError(LoginServer::ErrorCode::REDISSETERROR, L"Redis Set failed!");

				CPacket::Free(job->packet);
			}
		});
}
