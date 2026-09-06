#pragma once
#include "skCrypt.h"

#ifndef pstra
#define pstra(val) (skCrypt(val).decrypt())
#endif

#ifndef pstrw
#define pstrw(val) (skCrypt(val).decrypt())
#endif

#ifndef pstra8
#define pstra8(val) (skCrypt(val).decrypt())
#endif
