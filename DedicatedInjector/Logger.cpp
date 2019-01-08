#include "Logger.h"



Logger::Logger(wstring filename)
	:logText(NULL), DoLog(false), filename(filename)
{
}


Logger::~Logger()
{
	if (logText)
		CloseHandle(logText);
}

void Logger::startLog()
{
	if (!logText) {
		wstring filepathBase = L"C:\\Users\\Hunter\\Desktop\\Logfiles\\" + filename + L".txt";
		logText = CreateFileW(filepathBase.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	}

	DoLog = true;
}

void Logger::stopLog()
{
	DoLog = false;
}

string Logger::LogString(string explaination, const string str)
{
	if (DoLog && logText) {
		string logme = "Log_string : " + explaination + " ! " + str + "\r\n" ;
		WriteFile(logText, logme.c_str(), logme.size(), NULL, NULL);
	}
	return str;
}

float Logger::LogFloat(string explaination, const float value)
{
	if (DoLog && logText) {
		string logme = "Log_Float : " + explaination + " ! " + tostr<float>(value) + "\r\n";
		WriteFile(logText, logme.c_str(), logme.size(), NULL, NULL);
	}
	return value;
}

int Logger::LogInt(string explaination, const int value)
{
	if (DoLog && logText) {
		string logme = "Log_Int : " + explaination + " ! " + tostr<int>(value) + "\r\n" ;
		WriteFile(logText, logme.c_str(), logme.size(), NULL, NULL);
	}
	return value;
}
BYTE Logger::LogBYTE(string explaination, const BYTE value)
{
	if (DoLog && logText) {
		string logme = "Log_BYTE : " + explaination + " ! " + tostr<BYTE>(value) + "\r\n";
		WriteFile(logText, logme.c_str(), logme.size(), NULL, NULL);
	}
	return value;
}

DWORD64 Logger::LogAddress(string explaination, const DWORD64 value)
{
	if (DoLog && logText) {
		ostringstream os;
		os << hex << value;
		string logme = "Log_Address : " + explaination + " ! "  + "0x" + os.str() + "\r\n";
		WriteFile(logText, logme.c_str(), logme.size(), NULL, NULL);
	}
	return value;
}
