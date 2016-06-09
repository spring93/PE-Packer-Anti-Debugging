// SWU.cpp : DLL 응용 프로그램을 위해 내보낸 함수를 정의합니다.
//

#include "stdafx.h"
#include "stdio.h"
#include "stdlib.h"
#include <Windows.h>
#include <Psapi.h>
#include <string.h>
#include <atlstr.h>

#pragma comment(lib,"psapi.lib")

extern "C" __declspec(dllexport) 
	void antidebugging (void)
{
	DWORD pList[1024],pCnt;
	WCHAR pName[1024];
	DWORD pID;
	char *ollydbg1="ollydbg.exe";
	char *ollydbg2="OLLYDBG.EXE";
	char *windbg="windbg.exe";
	char *ida="idaPlus.exe";
	CStringA str;
	
	EnumProcesses(pList,sizeof(pList),&pCnt);
	pCnt=pCnt/sizeof(DWORD);
	
	for(pID=0;pID<pCnt;pID++)
	{
		HANDLE pHwnd=OpenProcess(PROCESS_ALL_ACCESS,FALSE,pList[pID]);
		GetProcessImageFileName(pHwnd,(LPWSTR)pName,sizeof(pName));
		str=pName;

		//ollydbg,windbg,ida 실행 중인지 검사 후 종료
		if(strstr(str.GetBuffer(),ollydbg1) || strstr(str.GetBuffer(),windbg) || 
			strstr(str.GetBuffer(),ida) || strstr(str.GetBuffer(),ollydbg2))
		{
			wprintf(L"%s\n",pName);
			TerminateProcess(pHwnd,0);
			CloseHandle(pHwnd);
		}
	}

	//간단한 API 사용 예시
	//---- 윈도우 타이틀 창 검사 FindWindow ----

	HANDLE hWnd;

	if(hWnd = FindWindow(NULL,TEXT("OllyDbg")))
	{
		MessageBoxA(NULL,"OllyDbg is detected","FindWindow",NULL);
		TerminateProcess(hWnd,0);
		CloseHandle(hWnd);
	}
	
	//---- 디버깅 되고 있는지 탐지 IsdebuggerPresent ----
	if(IsDebuggerPresent())
	{
		TerminateProcess(hWnd,0);
		CloseHandle(hWnd);
	}

		//---- INT 3 ----
	BOOL flag=TRUE;
	
	__try
    {
     __asm { int 3 }
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
		flag=FALSE;
    }

	if(flag)
	{
		MessageBoxA(NULL,"Debugging","SEH",NULL);
	}
}