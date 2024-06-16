#include "PCH.h"
#include "Contents/LoginServer.h"

lib::CrashDump crashDump;

LoginServer loginServer;

int main()
{
	loginServer.LoginServerStart();


	return 0;
}