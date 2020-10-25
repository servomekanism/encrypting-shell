#include <Windows.h>
#include <stdio.h>

_declspec(dllexport)   void start()
{
	__asm
	{
		xor eax, eax;
		xor ebx, ebx;
		mov eax, 0x12344321;
	}
}