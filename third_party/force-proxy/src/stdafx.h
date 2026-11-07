#pragma once


#include <WinSock2.h>
#include <WS2tcpip.h>
#include <MSWSock.h>
#include <Windows.h>

#include <cstdio>
#include <cstdint>

#include <vector>
#include <map>
#include <shared_mutex>

#include <detours/detours.h>

#include "proxy.h"
#include "hooks.h"