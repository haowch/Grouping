
#define _SECURE_ATL 1
#define VC_EXTRALEAN
#define WINVER 0x0600
#define _WIN32_WINNT 0x0600 
#define _WIN32_WINDOWS 0x0410
#define _WIN32_IE 0x0700
#define _ATL_CSTRING_EXPLICIT_CONSTRUCTORS
#define _AFX_ALL_WARNINGS
#define D_SCL_SECURE_NO_WARNINGS

#include <tchar.h>
#include <afx.h>
#include <afxcmn.h>
#include <afxwin.h>
#include <afxext.h>
#include <afxmt.h>

#include <algorithm>
#include <vector>
#include <string>
#include <iostream>
#include <sstream>
#include <fstream>
#include <map>
#include <set>

#ifndef uint
	typedef unsigned int uint;
#endif
