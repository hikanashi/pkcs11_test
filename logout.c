#include <stdio.h>
#include <time.h>
#include <string.h>
#include <pthread.h>

#ifndef _WIN32
#include <unistd.h>
#else
#include <windows.h>
#include <direct.h>
#include <stdint.h>
#define getcwd _getcwd
#define localtime_r(timet, tm)	localtime_s(tm, timet)


static int gettimeofday(struct timeval * tp, struct timezone * tzp)
{
	// Note: some broken versions only have 8 trailing zero's, the correct epoch has 9 trailing zero's
	// This magic number is the number of 100 nanosecond intervals since January 1, 1601 (UTC)
	// until 00:00:00 January 1, 1970 
	static const uint64_t EPOCH = ((uint64_t)116444736000000000ULL);

	SYSTEMTIME  system_time;
	FILETIME    file_time;
	uint64_t    time;

	GetSystemTime(&system_time);
	SystemTimeToFileTime(&system_time, &file_time);
	time = ((uint64_t)file_time.dwLowDateTime);
	time += ((uint64_t)file_time.dwHighDateTime) << 32;

	tp->tv_sec = (long)((time - EPOCH) / 10000000L);
	tp->tv_usec = (long)(system_time.wMilliseconds * 1000);
	return 0;
}
#endif


static char logfilepath[2048] = { 0 };
static pthread_mutex_t logoutLock = PTHREAD_ERRORCHECK_MUTEX_INITIALIZER_NP;


static void time_to_str(char* str, size_t strlen)
{
	time_t nowtime_t;
	struct tm nowtime;

	nowtime_t = time(NULL);
	localtime_r(&nowtime_t, &nowtime);

	nowtime.tm_year += 1900;

	snprintf(str, strlen - 1,
		"%04d%02d%02d_%02d%02d%02d",
		nowtime.tm_year, nowtime.tm_mon, nowtime.tm_mday,
		nowtime.tm_hour, nowtime.tm_min, nowtime.tm_sec);
}

static void set_logfile(char filepath[], size_t pathlen)
{
	size_t buflen = 0;

	getcwd(filepath, pathlen - 1);
	buflen = strlen(filepath);
	
	strncat(filepath, "/", pathlen - buflen - 1);
	buflen = strlen(filepath);

	time_to_str(&filepath[buflen], pathlen - buflen);
	buflen = strlen(filepath);
	strncat(filepath, "_sim.log", pathlen - buflen -1 );

	return;
}

void logout(const char* logstr)
{

	size_t loglen = strlen(logstr);
	FILE*	logfile = NULL;

	pthread_mutex_lock(&logoutLock);

	if (logfilepath[0] == 0)
	{
		set_logfile(logfilepath, sizeof(logfilepath));
	}


	logfile = fopen(logfilepath, "a");

	if (logfile != NULL)
	{
		size_t writelen = 0;

		struct timeval nowtime_t;
		struct tm nowtime;

		gettimeofday(&nowtime_t, NULL);
		
		
		time_t temp_tvsec = nowtime_t.tv_sec;
		localtime_r(&temp_tvsec, &nowtime);

		nowtime.tm_year += 1900;

		char nowstr[128] = { 0 };
		snprintf(nowstr, nowstr - 1,
			"%04d/%02d/%02d %02d:%02d:%02d.%03d ",
			nowtime.tm_year, nowtime.tm_mon, nowtime.tm_mday,
			nowtime.tm_hour, nowtime.tm_min, nowtime.tm_sec,
			nowtime_t.tv_usec / 1000 );
		writelen = fwrite(nowstr, strlen(nowstr), 1, logfile);

		writelen = fwrite(logstr, loglen, 1, logfile);
		fflush(logfile);
		fclose(logfile);
		logfile = NULL;
	}

	printf("%s", logstr);

	pthread_mutex_unlock(&logoutLock);
}
