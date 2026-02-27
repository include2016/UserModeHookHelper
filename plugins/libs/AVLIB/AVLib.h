#pragma once

#include <string>
#include <winsock2.h>
#include "../../../Shared/HookServices.h"
#include "../../../Shared/LogMacros.h"

namespace AVLIB {
	void SetHookServices(IHookServices* services);
	IHookServices* GetHookServices();
class AV {
public:
	AV(const std::string& host, int port);
	void sendData(const std::string& data);
	std::string receiveData();
	~AV();

private:
	SOCKET sockfd;
	bool winsockInitialized;
};

} // namespace AVLIB
