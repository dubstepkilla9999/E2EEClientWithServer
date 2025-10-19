#include "Server.h"

#pragma comment(lib, "Ws2_32.lib")
int main()
{
	int Result;
	WSADATA wsadata;

	//Initialize winsock
	Result = WSAStartup(MAKEWORD(2, 2), &wsadata);
	if (Result != NO_ERROR)
	{
		std::cout << "WSAStartup failed with error: " << std::to_string(Result) << std::endl;
		return 1;
	}
	else
	{
		std::cout << "Winsock initialized" << std::endl;
	}

	//Create a socket
	const SOCKET MainServerSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (MainServerSocket == INVALID_SOCKET)
	{
		std::cout << "Socket failed with error: " << std::to_string(WSAGetLastError()) << std::endl;
		return 1;
	}
	else
	{
		std::cout << "Server socket created" << std::endl;
	}

	//socket address to bind
	sockaddr_in server_addr;
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(8080);
	server_addr.sin_addr.s_addr = INADDR_ANY;

	//Bind socket to address
	Result = bind(MainServerSocket, (SOCKADDR*)&server_addr, sizeof(server_addr));
	if (Result == SOCKET_ERROR) {
		std::cout << "Bind failed with error " << std::to_string(WSAGetLastError()) << std::endl;
		closesocket(MainServerSocket);
		WSACleanup();
		return 1;
	}
	else
	{
		std::cout << "Bound socket to port" << std::endl;
	}

	if (listen(MainServerSocket, 5) == SOCKET_ERROR)
	{
		std::cout << "Listen function failed with error: " << std::to_string(WSAGetLastError()) << std::endl;
		return 1;
	}
	else
	{
		std::cout << "Listening..." << std::endl;
	}

	//main server loop
	for (;;)
	{
		SOCKET AcceptSocket;
		std::cout << "Waiting for client to connect..." << std::endl;
		AcceptSocket = accept(MainServerSocket, NULL, NULL);
		if (AcceptSocket == INVALID_SOCKET) {
			std::cout << "Accept failed with error: " << std::to_string(WSAGetLastError()) << std::endl;
			closesocket(AcceptSocket);
			WSACleanup();
			continue;
		}
		std::cout << "Client is trying to connect..." << std::endl;

		char buffer[32];
		Result = recv(AcceptSocket, buffer, 32, 0);
		if (Result > 0)
		{
			std::cout << "Trying to register client: " << buffer << std::endl;
		}
		else
		{
			closesocket(AcceptSocket);
			if (Result == 0)
			{
				std::cout << "Recv name failed: " << std::to_string(WSAGetLastError()) << std::endl;
				continue;
			}
			std::cout << "Connection closed" << std::endl;
			continue;
		}
		std::string ClientID(buffer);
		std::shared_ptr<ClientSession> NewSession = std::make_shared<ClientSession>(AcceptSocket , ClientID);
		UMClientSessions[ClientID] = NewSession;
		std::cout << "Registered new client: " << ClientID << std::endl;
	}
}

ClientSession::ClientSession(SOCKET ClientSocket, std::string ID) : Socket(ClientSocket), UserID(ID)
{
	UserThread = std::thread([this]() {Run(); });
	UserThread.detach();
}

ClientSession::~ClientSession()
{
	
}

void ClientSession::SendToClient(std::string Message)
{
	std::lock_guard<std::mutex> lock(SocketMutex);
	send(Socket, Message.data(), Message.size(), 0);
}

void ClientSession::SendToClient(std::vector<unsigned char> Message)
{
	std::lock_guard<std::mutex> lock(SocketMutex);
	send(Socket, (char*)Message.data(), Message.size(), 0);
}

void ClientSession::Run()
{
	for (;;)
	{
		char buffer[2048];
		int Result = recv(Socket, buffer, 2048, 0);
		if (Result > 0)
		{
			std::cout << "Received bytes from " << UserID << "\n";
			std::string RawMessage(buffer);
			RawMessage.resize(Result);
			int Delimiter = RawMessage.find(':');
			if (Delimiter <= 0) {
				std::cout << "Target of " << UserID << "'s bytes was unclear.\n";
				continue;
			}
			auto Message = RawMessage.substr(Delimiter + 1);
			auto Target = RawMessage.substr(0, Delimiter);
			if (UMClientSessions.find(Target) != UMClientSessions.end())
			{
				std::vector<unsigned char> BinaryData(buffer+Target.size()+1, buffer+Result);
				std::string TargetHeader = UserID + ':';
				BinaryData.insert(BinaryData.begin(), TargetHeader.begin(), TargetHeader.end());
				UMClientSessions[Target]->SendToClient(BinaryData);
				std::cout << "Sent message from " << UserID << " to " << Target << "\n";
				std::cout << "Compromised server is peeking into sent data:\n" << std::string(BinaryData.begin(), BinaryData.end()) << std::endl;//imitating someone intercepting and reading packets on the way
			}
			else
			{
				std::cout << "Unable to find the target of " << UserID << "'s bytes.\n";
				continue;
			}
		}
		else if (Result == 0)
		{
			std::cout << "Client " << UserID << " disconnected." << std::endl;
			break;
		}
		else
		{
			int Error = errno;
			if (Error == EAGAIN || Error == EWOULDBLOCK || Error == EINTR)
			{
				std::cout << "Encountered problems receiving bytes from " << UserID << std::endl;
				continue;
			}
			std::cout << "Fatal error on client " << UserID << std::endl;
			break;
		}
	}
	closesocket(Socket);
	if (UserThread.joinable())
	{
		UserThread.join();
	}
	UMClientSessions.erase(UserID);
}

