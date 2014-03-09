// Meterpreter is available for use under the following license, commonly known as the
// 3-clause (or "modified") BSD license:
//
//=========================================================================================
//
// Meterpreter
// -----------
//
// Copyright (c) 2006-2013, Rapid7 Inc
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// * Redistributions of source code must retain the above copyright notice, this list of
//   conditions and the following disclaimer.
//
// * Redistributions in binary form must reproduce the above copyright notice, this list of
//   conditions and the following disclaimer in the documentation and/or other materials
//   provided with the distribution.
//
// * Neither the name of Rapid7 nor the names of its contributors may be used to endorse or
//   promote products derived from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
// OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
// TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
//=========================================================================================

#ifndef INJECT64_H
#define INJECT64_H

#include <stdlib.h>
#include <Windows.h>

// Definitions used for running native x64 code from a wow64 process (see executex64.asm)
typedef BOOL (WINAPI * X64FUNCTION)( DWORD dwParameter );
typedef DWORD (WINAPI * EXECUTEX64)( X64FUNCTION pFunction, DWORD dwParameter );

// The context used for injection via migrate_via_remotethread_wow64
typedef struct _WOW64CONTEXT
{
	union
	{
 		HANDLE hProcess;
		BYTE bPadding2[8];
	} h;

 	union
	{
		LPVOID lpStartAddress;
		BYTE bPadding1[8]; 
	} s;

	union
	{
 		LPVOID lpParameter;
		BYTE bPadding2[8];
	} p;
	union
	{
		HANDLE hThread;
		BYTE bPadding2[8];
	} t;
} WOW64CONTEXT, * LPWOW64CONTEXT;

DWORD inject_via_remotethread_wow64( HANDLE hProcess, LPVOID lpStartAddress, LPVOID lpParameter, HANDLE * pThread );

#endif // INJECT64_H