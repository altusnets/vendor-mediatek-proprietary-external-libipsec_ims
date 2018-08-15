#ifndef __NETUTILS_WRAPPER_INTERFACE_H__
#define __NETUTILS_WRAPPER_INTERFACE_H__

#include <pthread.h>
#include <string>

enum IptablesTarget { V4, V6, V4V6 };
enum IptablesAction {IPTABLES_OFF = 0, IPTABLES_ON, IPTABLES_RESET};
int execIptables(IptablesTarget target, ...);
int execIptablesSilently(IptablesTarget target, ...);
int execNdcCmd(const char *command, ...);
int execIpCmd(int family, ...);


class IptablesInterface {
public:
	IptablesInterface(const char* inIface, const char* outIface, const char* nxthop, const char* tableId, const char* IMSinterfaceIP, const char* epdgTunnel,  int family, int refCnt, IptablesAction action);
	virtual ~IptablesInterface();
	int start();
	static void* threadStart(void* handler);

private:
	void run();
	int enableIptables();
	int disableIptables();

	std::string mInIface;
	std::string mOutIface;
	std::string mNxthop;
	std::string mTableId;
	std::string mIMSinterfaceIP;
	std::string mEpdgTunnel;
	int mFamily;
	int mRefCnt;
	int mAction;

	static const char* LOCAL_FILTER_INPUT;
	static const char* LOCAL_FILTER_OUT;
	static const char* LOCAL_MANGLE_PREROUTING;
	static const char* LOCAL_FILTER_FORWARD;
	static const char* LOCAL_HAPPY_BOX;
};

#endif
