#pragma once
#include <Windows.h>
#include <string>
#include <sstream>

using namespace std;
class Logger
{
public:
	Logger(wstring filename);
	~Logger();

	void startLog();
	void stopLog();

	string LogString(string explaination, const string str = string());
	float LogFloat(string explaination, const float value);
	int LogInt(string explaination, const int value);
	BYTE LogBYTE(string explaination, const BYTE value);
	DWORD64 LogAddress(string explaination, const DWORD64 value);

	template<typename T>

	T LogGeneral(string explaination, const typename T value);

private:
	HANDLE logText;
	bool DoLog;
	wstring filename;
	template <typename T> string tostr(const T& t) {
		ostringstream os;
		os << t;
		return os.str();
	}
};

template<typename T>
T Logger::LogGeneral(string explaination, const typename T value){
	if (DoLog && logText) {
		string logme = "LogGeneral : " + explaination + " ! " + tostr<T>(value) + "\r\n";
		WriteFile(logText, logme.c_str(), logme.size(), NULL, NULL);
	}
	return value;
}

