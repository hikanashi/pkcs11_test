#pragma once

#define LOGOUT(...)								\
	do {										\
		char logbuf[1024] = {0};				\
		snprintf(logbuf, sizeof(logbuf), __VA_ARGS__);	\
		logout(logbuf);							\
	} while (0);

#define FUNC_TO_STR2(x) #x
#define FUNC_TO_STR(x) FUNC_TO_STR2(x)

#define LOGOUT_APIIN(...)	LOGOUT("[curl_test][API_IN]"  FUNC_TO_STR(__func__)  __VA_ARGS__)
#define LOGOUT_APIOUT(...)	LOGOUT("[curl_test][API_OUT]"  FUNC_TO_STR(__func__)  __VA_ARGS__)


#ifdef __cplusplus
extern "C" {
#endif

void logout(const char* logstr);

#ifdef __cplusplus
}
#endif
