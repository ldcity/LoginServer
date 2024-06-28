#ifndef __PCH__
#define __PCH__

#include <WinSock2.h>
#include <WS2tcpip.h>
#include <windows.h>
#include <string>
#include <process.h>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <iostream>
#include <strsafe.h>

#include <cpp_redis/cpp_redis>

#pragma comment(lib, "mysql/libmysql.lib")
#pragma comment(lib, "cpp_redis.lib")
#pragma comment(lib, "tacopie.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "winmm.lib")

#include "mysql/include/mysql.h"
#include "mysql/include/errmsg.h"

#include "Utils/Exception.h"

#include "Utils/Define.h"
#include "Utils/MonitoringDefine.h"
#include "Utils/MonitorProtocol.h"
#include "Utils/Protocol.h"

#include "Library/TLSFreeList.h"
#include "Library/LockFreeQueue.h"
#include "Library/LockFreeStack.h"
#include "Library/SerializingBuffer.h"
#include "Library/RingBuffer.h"
#include "Library/Session.h"

#include "Utils/LOG.h"
#include "Utils/Profiling.h"
#include "Utils/CrashDump.h"
#include "Utils/TextParser.h"
#include "Utils/PerformanceMonitor.h"
#include "Utils/DBConnection.h"
#include "Utils/DBConnection_TLS.h"
#include "Utils/Redis.h"

#include "Contents/Packet.h""

#include "Library/LanClient.h"
#include "Contents/MonitoringLanClient.h"
#include "Library/NetServer.h"

#include "Contents/LoginServer.h"


#endif // __PCH__
