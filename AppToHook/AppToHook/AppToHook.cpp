#include <Windows.h>
#include <iostream>
int sum(int a, int b) {
	return a + b;
}
int main()
{
	SetConsoleTitle(T("T"));
	system("title apptohook");
	while (true) {
		std::cout << "test:" << sum(3,5) << std::endl;
		Sleep(2000);
	}
}
