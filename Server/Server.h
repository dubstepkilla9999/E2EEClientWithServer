#include <unordered_map>
#include <mutex>
#include <winsock2.h>
#include <thread>
#include <iostream>
#include <string>


class ClientSession final
{
	SOCKET Socket;
	std::string UserID;
	std::thread UserThread;
	std::mutex SocketMutex;

public:
	ClientSession(SOCKET ClientSocket, std::string ID);

	~ClientSession();

	void SendToClient(std::string Message);
	void SendToClient(std::vector<unsigned char> Message);//send binary data that could contain '\0'

private:
	void Run();
};
std::unordered_map<std::string, std::shared_ptr<ClientSession>> UMClientSessions;
