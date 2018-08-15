/*
* Copyright (C) 2014 MediaTek Inc.
* Modification based on code covered by the mentioned copyright
* and/or permission notice(s).
*/
/*
 * Copyright (C) 2012 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <stdarg.h>
#include "utils.h"
#define LOG_TAG "ipsec_policy_mont"
#include <log/log.h>
#include <string>
#include <list>
#include "netutils_wrapper_interface.h"
#include "../../../../system/netdagent/include/forkexecwrap/fork_exec_wrap.h"

const char * const IPTABLES_PATH = "/system/bin/iptables-wrapper-1.0";
const char * const IP6TABLES_PATH = "/system/bin/ip6tables-wrapper-1.0";
const char * const IP_PATH = "/system/bin/ip-wrapper-1.0";
const char * const NDC_PATH = "/system/bin/ndc-wrapper-1.0";

extern "C" char* strchr(const char* p, int ch);

static void logExecError(const char* argv[], int res, int status) {
    const char** argp = argv;
    std::string args = "";
    while (*argp) {
        args += *argp;
        args += ' ';
        argp++;
    }
    ALOGE("exec() res=%d, status=%d for %s", res, status, args.c_str());
}

static int execCommand(int argc, const char *argv[], bool silent) {
    int res;
    int status;

    res = android_fork_execvp_ext(argc, (char **)argv, &status, false, LOG_ALOG,!silent,NULL,NULL,0);
    if (res || !WIFEXITED(status) || WEXITSTATUS(status)) {
        if (!silent) {
            logExecError(argv, res, status);
        }
        if (res)
            return res;
        if (!WIFEXITED(status))
            return ECHILD;
    }
    return res;
}

static int execIptables(IptablesTarget target, bool silent, va_list args) {
    /* Read arguments from incoming va_list; we expect the list to be NULL terminated. */
    std::list<const char*> argsList;
    argsList.push_back(NULL);
    const char* arg;

    // Wait to avoid failure due to another process holding the lock
    argsList.push_back("-w");

    do {
        arg = va_arg(args, const char *);
        argsList.push_back(arg);
    } while (arg);

    int i = 0;
    const char* argv[argsList.size()];
    std::list<const char*>::iterator it;
    for (it = argsList.begin(); it != argsList.end(); it++, i++) {
        argv[i] = *it;
    }

    const char** temp = argv + 1; //skip argv[0]
    std::string debug = "";
    while (*temp) {
        debug += *temp;
        debug += " ";
        temp++;
    }
    ALOGI("execIptables %s\n", debug.c_str());

    int res = 0;
    if (target == V4 || target == V4V6) {
        argv[0] = IPTABLES_PATH;
        res |= execCommand(argsList.size(), argv, silent);
    }
    if (target == V6 || target == V4V6) {
        argv[0] = IP6TABLES_PATH;
        res |= execCommand(argsList.size(), argv, silent);
    }
    return res;
}

int execIptables(IptablesTarget target, ...) {
    va_list args;
    va_start(args, target);
    int res = execIptables(target, false, args);
    va_end(args);
    return res;
}

int execIptablesSilently(IptablesTarget target, ...) {
    va_list args;
    va_start(args, target);
    int res = execIptables(target, true, args);
    va_end(args);
    return res;
}

static int execNdcCmd(const char *command, bool silent, va_list args) {
    /* Read arguments from incoming va_list; we expect the list to be NULL terminated. */
    std::list<const char*> argsList;
    argsList.push_back(NULL);
    const char* arg;
    argsList.push_back(command);
    do {
        arg = va_arg(args, const char *);
        argsList.push_back(arg);
    } while (arg);

    int i = 0;
    const char* argv[argsList.size()];
    std::list<const char*>::iterator it;
    for (it = argsList.begin(); it != argsList.end(); it++, i++) {
        argv[i] = *it;
    }

    const char** temp = argv + 1; //skip argv[0]
    std::string debug = "";
    while (*temp) {
        debug += *temp;
        debug += " ";
        temp++;
    }
    ALOGI("execNdcCmd %s\n", debug.c_str());

    int res = 0;
    argv[0] = NDC_PATH;
    res = execCommand(argsList.size(), argv, silent);
    return res;
  
}

int execNdcCmd(const char *command, ...) {
    va_list args;
    va_start(args, command);
    int res = execNdcCmd(command, false, args);
    va_end(args);
    return res;
}

static int execIpCmd(int family, bool silent, va_list args) {
    /* Read arguments from incoming va_list; we expect the list to be NULL terminated. */
    std::list<const char*> argsList;
    argsList.push_back(NULL);
    argsList.push_back(NULL);
    const char* arg;

    do {
        arg = va_arg(args, const char *);
        argsList.push_back(arg);
    } while (arg);

    int i = 0;
    const char* argv[argsList.size()];
    std::list<const char*>::iterator it;
    for (it = argsList.begin(); it != argsList.end(); it++, i++) {
        argv[i] = *it;
    }


    const char** temp = argv + 2; //skip argv[0] and argv[1]
    std::string debug = "";
    while (*temp) {
        debug += *temp;
        debug += " ";
        temp++;
    }
    ALOGI("execIpCmd %s\n", debug.c_str());

    int res = 0;
    argv[0] = IP_PATH;
    if (family == AF_INET) {
        argv[1] = "-4";
        res |= execCommand(argsList.size(), argv, silent);
    }
    if (family == AF_INET6) {
        argv[1] = "-6";
        res |= execCommand(argsList.size(), argv, silent);
    }
    return res;
  
}

int execIpCmd(int family, ...) {
    va_list args;
    va_start(args, family);
    int res = execIpCmd(family, false, args);
    va_end(args);
    return res;
}

const char* IptablesInterface::LOCAL_FILTER_INPUT = "fw_INPUT";  //AOSP chain
const char* IptablesInterface::LOCAL_FILTER_OUT = "fw_OUTPUT";  //AOSP chain
const char* IptablesInterface::LOCAL_MANGLE_PREROUTING = "PREROUTING";  //AOSP chain
const char* IptablesInterface::LOCAL_FILTER_FORWARD = "oem_fwd";  //AOSP chain
const char* IptablesInterface::LOCAL_HAPPY_BOX = "bw_happy_box";  //AOSP chain

int IptablesInterface::start()
{
	pthread_t thread;
	if(pthread_create(&thread, NULL, IptablesInterface::threadStart, this)) {
		ALOGE("pthread create failed(%s)", strerror(errno));
		return -1;
	}
	pthread_detach(thread);
	return 0;
}

IptablesInterface::IptablesInterface(const char* inIface, const char* outIface, const char* nxthop, const char* tableId, 
	const char* IMSinterfaceIP, const char* epdgTunnel, int family, int refCnt, IptablesAction action)
		: mInIface(inIface), mOutIface(outIface), mNxthop(nxthop), mTableId(tableId), mIMSinterfaceIP(IMSinterfaceIP), mEpdgTunnel(epdgTunnel), mFamily(family), mRefCnt(refCnt), mAction(action) {
}

IptablesInterface::~IptablesInterface() {
}

void* IptablesInterface::threadStart(void* obj)
{
	IptablesInterface* handler = reinterpret_cast<IptablesInterface*>(obj);
	handler->run();
	delete handler;
	pthread_exit(NULL);
	return NULL;
}

void IptablesInterface::run()
{
	switch (mAction) {
		case IptablesAction::IPTABLES_ON:
			if(enableIptables())
				ALOGE("enable iptables failed from %s to %s\n", mInIface.c_str(), mOutIface.c_str());
			else
				ALOGI("enable iptables successfully from %s to %s\n", mInIface.c_str(), mOutIface.c_str());
			break;
		case IptablesAction::IPTABLES_OFF:
			if(disableIptables())
				ALOGE("disable iptables failed from %s to %s\n", mInIface.c_str(), mOutIface.c_str());
			else
				ALOGE("disable iptables successfully from %s to %s\n", mInIface.c_str(), mOutIface.c_str());
			break;
		case IptablesAction::IPTABLES_RESET:
			if(disableIptables() || enableIptables())
				ALOGE("reset iptables failed from %s to %s\n", mInIface.c_str(), mOutIface.c_str());
			else
				ALOGE("reset iptables successfully from %s to %s\n", mInIface.c_str(), mOutIface.c_str());
		default:
			break;
	}
}

int IptablesInterface::enableIptables()
{
	int res = 0;
	const char *FORWARD_MARK = "0x10000";

	//enable forwarding
	res |= execNdcCmd("ipfwd", "enable", mInIface.c_str(), NULL);
	//add forward rule
	res |= execIpCmd(mFamily, "rule", "add", "from", "all", "iif",  mInIface.c_str(), "fwmark", "0x0/0xffff", "lookup", mTableId.c_str(), "prio", "25000", NULL);
        //add forward route
        res |= execIpCmd(mFamily, "route", "add", mNxthop.c_str(), "dev", mOutIface.c_str(), "table", mTableId.c_str(), NULL);

	//add rorward mark
	res |= execIptables(V4V6, "-t", "mangle", "-I", LOCAL_MANGLE_PREROUTING, "-i", mInIface.c_str(), "-j", "MARK", "--set-mark", FORWARD_MARK, NULL);
	//add forward exception iptables
	res |= execIptables(V4V6, "-t", "filter", "-I", LOCAL_FILTER_FORWARD, "-i", mInIface.c_str(), "-o", mOutIface.c_str(), "-j", "ACCEPT", NULL);
	//add powersave or dozable output exception iptables
	res |= execIptables(V4V6, "-t", "filter", "-I", LOCAL_FILTER_OUT, "-o", mOutIface.c_str(), "-d", mEpdgTunnel.c_str(), "-j", "RETURN", NULL);
	//add datasaver output exception iptables
	res |= execIptables(strchr(mIMSinterfaceIP.c_str(),':')?V6:V4, "-t", "filter", "-I", LOCAL_HAPPY_BOX, "-o", mOutIface.c_str(), "-s", mIMSinterfaceIP.c_str(), "-j", "RETURN", NULL);
	res |= execIptables(strchr(mEpdgTunnel.c_str(),':')?V6:V4, "-t", "filter", "-I", LOCAL_HAPPY_BOX, "-o", mOutIface.c_str(), "-d", mEpdgTunnel.c_str(), "-j", "RETURN", NULL);
	//add powersave or dozable input exception iptables
	res |= execIptables(V4V6, "-t", "filter", "-I", LOCAL_FILTER_INPUT, "-i", mOutIface.c_str(), "-j", "RETURN", NULL);
	//add datasaver input exception iptables
	res |= execIptables(strchr(mIMSinterfaceIP.c_str(),':')?V6:V4, "-t", "filter", "-I", LOCAL_HAPPY_BOX, "-i", mOutIface.c_str(), "-d", mIMSinterfaceIP.c_str(), "-j", "RETURN", NULL);
	res |= execIptables(strchr(mEpdgTunnel.c_str(),':')?V6:V4, "-t", "filter", "-I", LOCAL_HAPPY_BOX, "-i", mOutIface.c_str(), "-s", mEpdgTunnel.c_str(), "-j", "RETURN", NULL);

	return res;
}

int IptablesInterface::disableIptables()
{
	int res = 0;
	const char *FORWARD_MARK = "0x10000";

	//disable forwarding
	res |= execNdcCmd("ipfwd", "disable", mInIface.c_str(), NULL);
	//del forward mark
	res |= execIptables(V4V6, "-t", "mangle", "-D", LOCAL_MANGLE_PREROUTING, "-i", mInIface.c_str(), "-j", "MARK", "--set-mark", FORWARD_MARK, NULL);
	//del forward exception iptables
	res |= execIptables(V4V6, "-t", "filter", "-D", LOCAL_FILTER_FORWARD, "-i", mInIface.c_str(), "-o", mOutIface.c_str(), "-j", "ACCEPT", NULL);
	//del powersave or dozable output exception iptables
	res |= execIptables(V4V6, "-t", "filter", "-D", LOCAL_FILTER_OUT, "-o", mOutIface.c_str(), "-d", mEpdgTunnel.c_str(), "-j", "RETURN", NULL);
	//del datasaver output exception iptables
	res |= execIptables(strchr(mIMSinterfaceIP.c_str(),':')?V6:V4, "-t", "filter", "-D", LOCAL_HAPPY_BOX, "-o", mOutIface.c_str(), "-s", mIMSinterfaceIP.c_str(), "-j", "RETURN", NULL);
	res |= execIptables(strchr(mEpdgTunnel.c_str(),':')?V6:V4, "-t", "filter", "-D", LOCAL_HAPPY_BOX, "-o", mOutIface.c_str(), "-d", mEpdgTunnel.c_str(), "-j", "RETURN", NULL);
	//del powersave or dozable input exception iptables
	res |= execIptables(V4V6, "-t", "filter", "-D", LOCAL_FILTER_INPUT, "-i", mOutIface.c_str(), "-j", "RETURN", NULL);
	//del datasaver input exception iptables
	res |= execIptables(strchr(mIMSinterfaceIP.c_str(),':')?V6:V4, "-t", "filter", "-D", LOCAL_HAPPY_BOX, "-i", mOutIface.c_str(), "-d", mIMSinterfaceIP.c_str(), "-j", "RETURN", NULL);
	res |= execIptables(strchr(mEpdgTunnel.c_str(),':')?V6:V4, "-t", "filter", "-D", LOCAL_HAPPY_BOX, "-i", mOutIface.c_str(), "-s", mEpdgTunnel.c_str(), "-j", "RETURN", NULL);
	//del/forward rule
	res |= execIpCmd(mFamily, "rule", "del", "from", "all", "iif",  mInIface.c_str(), "fwmark", "0x0/0xffff", "lookup", mTableId.c_str(), "prio", "25000", NULL);
	//del forward route
	res |= mRefCnt ? 0 : execIpCmd(mFamily, "route", "del", mNxthop.c_str(), "dev", mOutIface.c_str(), "table", mTableId.c_str(), NULL);
    return res;
}


