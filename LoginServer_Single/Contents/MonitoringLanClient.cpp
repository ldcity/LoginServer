#include <process.h>

#include "MonitoringLanClient.h"
#include "../Utils/TextParser.h"
#include "../Utils/MonitorProtocol.h"
#include "../Utils/MonitoringDefine.h"

unsigned __stdcall ConnectThread(LPVOID param)
{
	MonitoringLanClient* lanServ = (MonitoringLanClient*)param;

	lanServ->ConnectThread_serv();

	return 0;
}

MonitoringLanClient::MonitoringLanClient()
{
	wprintf(L"Monitoring Lan Client Init...\n");

}

MonitoringLanClient::~MonitoringLanClient()
{
	MonitoringLanClientStop();
}

bool MonitoringLanClient::MonitoringLanClientStart()
{
	TextParser clientCntFile;
	const wchar_t* cnfName = L"LoginClient.txt";
	clientCntFile.LoadFile(cnfName);

	wchar_t IP[256];
	clientCntFile.GetValue(L"CLIENT.IP", IP);

	int port;
	clientCntFile.GetValue(L"CLIENT.PORT", &port);

	int workerThread;
	clientCntFile.GetValue(L"CLIENT.IOCP_WORKER_THREAD", &workerThread);

	int runningThread;
	clientCntFile.GetValue(L"CLIENT.IOCP_ACTIVE_THREAD", &runningThread);

	int nagleOff;
	clientCntFile.GetValue(L"CLIENT.NAGLE_OFF", &nagleOff);

	// Lan Client Start
	if (!Start(IP, port, workerThread, runningThread, nagleOff))
	{
		MonitoringLanClientStop();
		return false;
	}

	connectThread = (HANDLE)_beginthreadex(NULL, 0, ConnectThread, this, 0, NULL);
	if (connectThread == NULL)
	{
		int threadError = GetLastError();

		return false;
	}

	return true;

}

bool MonitoringLanClient::ConnectThread_serv()
{
	// ���� ���� -> 2�ʸ��� ���� �õ�
	while (!Connect())
	{
		Sleep(2000);
	}

	return true;
}

bool MonitoringLanClient::MonitoringLanClientStop()
{
	Stop();

	WaitForSingleObject(connectThread, INFINITE);

	return true;
}

void MonitoringLanClient::mpLoginToMonitorServer(BYTE serverNo, CPacket* packet)
{
	WORD type = en_PACKET_SS_MONITOR_LOGIN;
	*packet << type << serverNo;
}

void MonitoringLanClient::mpUpdateDataToMonitorServer(BYTE serverNo, BYTE dataType, int dataValue, int timeStamp, CPacket* packet)
{
	WORD type = en_PACKET_SS_MONITOR_DATA_UPDATE;
	*packet << type << serverNo << dataType << dataValue << timeStamp;
}

void MonitoringLanClient::SendDataToMonitorServer(BYTE serverNo, BYTE dataType, int dataValue, int timeStamp)
{
	CPacket* packet = CPacket::Alloc();
	
	mpUpdateDataToMonitorServer(serverNo, dataType, dataValue, timeStamp, packet);

	SendPacket(packet);

	CPacket::Free(packet);
}


void MonitoringLanClient::OnClientJoin()
{
	CPacket* packet = CPacket::Alloc();
	
	mpLoginToMonitorServer(SERVERTYPE::LOGIN_SERVER_TYPE, packet);

	SendPacket(packet);

	CPacket::Free(packet);
}

void MonitoringLanClient::OnClientLeave()
{
	while (!Connect())
	{
		Sleep(2000);
	}
}

void MonitoringLanClient::OnRecv(CPacket* packet)
{
	CPacket::Free(packet);
}

void MonitoringLanClient::OnError(int errorCode, const wchar_t* msg)
{

}