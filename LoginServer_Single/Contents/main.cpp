#include "../Utils/CrashDump.h"
#include "LoginServer.h"

lib::CrashDump crashDump;

LoginServer loginServer;

int main()
{
	loginServer.LoginServerStart();

	return 0;
}