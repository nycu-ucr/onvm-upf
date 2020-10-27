#include "utlt_debug.h"

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdarg.h>

#include "utlt_lib.h"

int configured_level = 0;

// TODO : Need to use buffer written by ourself
#define MAX_SIZE_OF_BUFFER 32768

void SetLogLevel(int level) {
  configured_level = level;
}

Status UTLT_SetLogLevel(const char *level) {
#ifdef FREE5GC
    if (UpfUtilLog_SetLogLevel(UTLT_CStr2GoStr(level)))
        return STATUS_OK;
    else
        return STATUS_ERROR;
#else
    return STATUS_OK;
#endif
}

int UTLT_LogPrint(int level, const char *filename, const int line, 
                  const char *funcname, const char *fmt, ...) {
  if (level >= configured_level) {
    return 0;
  }
    static char buffer[MAX_SIZE_OF_BUFFER];

    unsigned int cnt, vspCnt;
    cnt = sprintf(buffer, "%s:%d %s() ", filename, line, funcname);
    if (cnt < 0) {
        fprintf(stderr, "sprintf in UTLT_LogPrint error : %s\n", strerror(errno));
        return STATUS_ERROR;
    }

    va_list vl;
    va_start(vl, fmt);
    vspCnt = vsnprintf(buffer + cnt, sizeof(buffer) - cnt, fmt, vl);
    if (vspCnt < 0) {
        fprintf(stderr, "vsnprintf in UTLT_LogPrint error : %s\n", strerror(errno));
        va_end(vl);
        return STATUS_ERROR;
    } else if (vspCnt == 0) {
        return STATUS_OK;
    }
    va_end(vl);

    printf("%s \n", buffer);

#ifdef FREE5GC
    switch(level) {
        case 0 :
            UpfUtilLog_Panicln(UTLT_CStr2GoStr(buffer));
            break;
        case 1 :
            UpfUtilLog_Fatalln(UTLT_CStr2GoStr(buffer));
            break;
        case 2 :
            UpfUtilLog_Errorln(UTLT_CStr2GoStr(buffer));
            break;
        case 3 :
            UpfUtilLog_Warningln(UTLT_CStr2GoStr(buffer));
            break;
        case 4 :
            UpfUtilLog_Infoln(UTLT_CStr2GoStr(buffer));
            break;
        case 5 :
            UpfUtilLog_Debugln(UTLT_CStr2GoStr(buffer));
            break;
        case 6 :
            UpfUtilLog_Traceln(UTLT_CStr2GoStr(buffer));
            break;
        default :
            fprintf(stderr, "The log level %d is out of range.\n", level);
            return STATUS_ERROR;
    }
#endif
    return STATUS_OK;
}

const char *UTLT_StrStatus(Status status) {
    switch(status) {
        case STATUS_OK :
            return "status OK";
        case STATUS_ERROR :
            return "status error";
        case STATUS_EAGAIN :
            return "status eagain";
        default :
            return "status unknown";
    }
}
