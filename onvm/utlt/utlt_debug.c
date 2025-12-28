#include "utlt_debug.h"

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <strings.h>
#include <stdarg.h>

#include "logger.h"
#include "utlt_lib.h"

// TODO : Need to use buffer written by ourself
#define MAX_SIZE_OF_BUFFER 32768

unsigned int reportCaller = 0;
/* Fast-path log filter (avoids formatting when message would be dropped).
 * Default = most verbose to preserve historical behavior until UTLT_SetLogLevel is called. */
static int g_utlt_min_level = LOG_TRACE;

static inline int
utlt_parse_level(const char *level) {
    if (level == NULL) return -1;
    if (strcasecmp(level, "panic") == 0)   return LOG_PANIC;
    if (strcasecmp(level, "fatal") == 0)   return LOG_FATAL;
    if (strcasecmp(level, "error") == 0)   return LOG_ERROR;
    if (strcasecmp(level, "warning") == 0) return LOG_WARNING;
    if (strcasecmp(level, "warn") == 0)    return LOG_WARNING;
    if (strcasecmp(level, "info") == 0)    return LOG_INFO;
    if (strcasecmp(level, "debug") == 0)   return LOG_DEBUG;
    if (strcasecmp(level, "trace") == 0)   return LOG_TRACE;
    return -1;
}

Status UTLT_SetLogLevel(const char *level) {
    int parsed = utlt_parse_level(level);
    if (parsed >= 0) {
        __atomic_store_n(&g_utlt_min_level, parsed, __ATOMIC_RELEASE);
    }
    if (UpfUtilLog_SetLogLevel(UTLT_CStr2GoStr(level)))
        return STATUS_OK;
    else
        return STATUS_ERROR;
}

Status UTLT_SetReportCaller(unsigned int flag) {
    if (reportCaller >= REPORTCALLER_MAX) {
        reportCaller = 0;
        return STATUS_ERROR;
    }

    reportCaller = flag;
    return STATUS_OK;
}

int UTLT_LogPrint(int level, const char *filename, const int line, 
                  const char *funcname, const char *fmt, ...) {
    static char buffer[MAX_SIZE_OF_BUFFER];

    const int min_level = __atomic_load_n(&g_utlt_min_level, __ATOMIC_ACQUIRE);
    if (level > min_level) {
        return STATUS_OK;
    }

    unsigned int cnt = 0, vspCnt = 0;
    if (reportCaller == REPORTCALLER_TRUE) {
        cnt = snprintf(buffer, sizeof(buffer), " (%s:%d %s) ", filename, line, funcname);
        if (cnt < 0) {
            fprintf(stderr, "sprintf in UTLT_LogPrint error : %s\n", strerror(errno));
            return STATUS_ERROR;
        }
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
