#ifndef __LOGINSERVER__CLASS__
#define __LOGINSERVER__CLASS__

#include "PCH.h"

class LoginServer : public NetServer
{
public:
	LoginServer();
	~LoginServer();

	bool LoginServerStart();
	bool LoginServerStop();

	bool OnConnectionRequest(const wchar_t* IP, unsigned short PORT);
	void OnClientJoin(uint64_t sessionID);
	void OnClientLeave(uint64_t sessionID);
	void OnRecv(uint64_t sessionID, CPacket* packet);
	void OnError(int errorCode, const wchar_t* msg);
	void OnTimeout(uint64_t sessionID);

	//--------------------------------------------------------------------------------------
	// Packet Proc
	//--------------------------------------------------------------------------------------
	void PacketProc(uint64_t sessionID, CPacket* packet, WORD type);
	void netPacketProc_ReqLogin(uint64_t sessionID, CPacket* packet);

	friend unsigned __stdcall MoniteringThread(void* param);
	bool MoniterThread_serv();

private:
	Log* loginLog;

	int m_userMAXCnt;									// 최대 player 수
	int m_timeout;

	HANDLE m_moniteringThread;							// Monitering Thread
	HANDLE m_controlThread;

	HANDLE m_moniterEvent;								// Monitering Event
	HANDLE m_runEvent;									// Thread Start Event


private:
	wchar_t chatIP[16];
	unsigned short chatPort;

	// 모니터링 관련 변수들
private:
	__int64 m_loginCount;
	__int64 m_loginTPS;

	__int64 m_loginSuccessCount;
	__int64 m_loginSuccessTPS;

	__int64 m_loginFailCount;
	__int64 m_loginFailTPS;

	__int64 m_timeoutTotalCnt;
	__int64 m_timeoutCntTPS;

	__int64 m_dbQueryTotal;
	__int64 m_dbQueryTPS;

	__int64 m_updateTotal;
	__int64 m_updateTPS;

	__int64 m_redisSetCnt;
	__int64 m_redisSetTPS;

	bool startFlag;

private:
	PerformanceMonitor performMoniter;
	MonitoringLanClient lanClient;

	std::wstring m_tempIp;
	std::string m_ip;

	CRedis_TLS* mRedis;				// TLS용 Redis Connector
	DBConnector_TLS* dbConn_TLS;	// TLS용 DBConnector

	wchar_t mDBName[64];

};




#endif // !__LOGINSERVER__CLASS__
