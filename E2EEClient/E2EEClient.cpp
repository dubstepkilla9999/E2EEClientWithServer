#pragma once
#include "E2EEClient.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include "KeyManager.h"
#include <openssl/applink.c>
#include <mutex>

SOCKET ServerSocket;
std::mutex SendMutex;
std::string Username;
std::unordered_map<std::string, std::vector<std::string>> PendingMessages;
std::shared_ptr<KeyManager> KM;

void HandleIncomingMessages()
{
	for (;;)
	{
		char buffer[2048];
		int Result = recv(ServerSocket, buffer, 2048, 0);
		if (Result > 0)
		{
			std::cout << "Received bytes. " << std::to_string(Result) << std::endl;
			std::string FullMessage(buffer);
			FullMessage.resize(Result);
			int Delimiter = FullMessage.find(':');
			if (Delimiter <= 0)
			{
				std::cout << "Unknown bytes:\n" << FullMessage << std::endl;
				continue;
			}
			std::string InnerMessage = FullMessage.substr(Delimiter + 1);
			std::string Author = FullMessage.substr(0, Delimiter);
			if (InnerMessage == std::string("WANTKEY"))
			{
				const auto PublicKey = KM->GetPublicKey();
				std::string KeyPayload = Author + ":KEY:" + PublicKey;
				SendBytesBlocking(KeyPayload.c_str(), KeyPayload.size());
				std::cout << "Sent public key to " << Author << std::endl;
			}
			else
			{
				Delimiter = InnerMessage.find(':');
				if (InnerMessage.substr(0, Delimiter).c_str() == std::string("KEY"))
				{
					const auto NewContactKey = InnerMessage.substr(Delimiter + 1);
					KM->RegisterNewContact(Author, NewContactKey);
					if (PendingMessages.find(Author) != PendingMessages.end())
					{
						for (std::string PMessage : PendingMessages[Author])
						{
							EncryptAndSend(Author, PMessage);
						}
						PendingMessages.erase(Author);
					}
					std::cout << "Got a public key from " << Author << ". Sent all pending messages." << std::endl;
				}
				else
				{
					std::cout << "Got encrypted message from: " << Author << std::endl;
					std::vector<unsigned char> EncryptedMessage(buffer+Author.size()+1, buffer+Result);
					std::cout << KM->Decrypt(EncryptedMessage) << std::endl;
				}
			}
		}
		else
		{
			if (Result == 0)
			{
				std::cout << "Connection closed." << std::endl;
				return;
			}
			std::cout << "Failure" << std::endl;
			return;
		}
	}
}

int SendBytesBlocking(const char* buffer, int length)
{
	std::lock_guard<std::mutex> lock(SendMutex);
	int Result = send(ServerSocket, buffer, length, 0);
	return Result;
}

void EncryptAndSend(const std::string& Target, const std::string& Message)
{
	auto EncryptedMessage = KM->EncryptForContact(Target, Message);
	std::string FullMessagePayload(EncryptedMessage.begin(), EncryptedMessage.end());
	FullMessagePayload = Target + ":" + FullMessagePayload;
	int Result = SendBytesBlocking(FullMessagePayload.c_str(), FullMessagePayload.size());
	if (Result > 0)
	{
		std::cout << "Sent encrypted message to " << Target << std::endl;
	}
	else
	{
		std::cout << "Failed sending encrypted message to " << Target << std::endl;
	}
}

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
		std::cout << "Winsock initialized." << std::endl;
	}

	//Create a socket
	ServerSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (ServerSocket == INVALID_SOCKET)
	{
		std::cout << "Socket failed with error: " << std::to_string(WSAGetLastError()) << std::endl;
		return 1;
	}
	else
	{
		std::cout << "Socket created" << std::endl;
	}
	sockaddr_in addr;
	//convert string IP into binary
	InetPton(AF_INET, "192.168.1.6", &addr.sin_addr.s_addr);//local IP address found in ipconfig of the server machine

	addr.sin_family = AF_INET;
	addr.sin_port = htons(8080);
	Result = connect(ServerSocket, (SOCKADDR*)&addr, sizeof(addr));
	if (Result != SOCKET_ERROR)
	{
		std::cout << "Connected to server!" << std::endl;
	}
	else
	{
		return 1;
	}
	std::cout << "Type in your nickname:" << std::endl;
	char buffer[32];
	std::cin >> buffer;
	KM = std::make_shared<KeyManager>(buffer);
	Result = send(ServerSocket, buffer, 32, 0);
	if (Result > 0)
	{
		std::cout << "Logged on to server successfully. " << std::to_string(Result) << std::endl;
	}
	else
	{
		std::cout << "Failed to log in." << std::endl;
		if (Result == 0)
		{
			std::cout << "Connection closed." << std::endl;
			return 0;
		}
		return 0;
	}

	std::thread NewThread(HandleIncomingMessages);
	NewThread.detach();

	for (;;)
	{
		std::string TargetNickname = "";
		std::string FullMessage = "";
		std::cout << "Enter Target's nickname." << std::endl;
		std::cin >> TargetNickname;
		std::cout << "Enter your message to " << TargetNickname << std::endl;
		std::cin.ignore();
		std:getline(std::cin, FullMessage);
		if (KM->AttempLoadContactPKey(TargetNickname) != nullptr)
		{
			std::cout << "Found target's public keys locally, sending encrypted data..." << std::endl;
			EncryptAndSend(TargetNickname, FullMessage);
		}
		else
		{
			if (PendingMessages.find(TargetNickname) != PendingMessages.end())
			{
				PendingMessages[TargetNickname].push_back(FullMessage);
			}
			else
			{
				std::vector<std::string> TempMessages;
				TempMessages.push_back(FullMessage);
				PendingMessages.insert(make_pair(TargetNickname, TempMessages));
			}
			std::string AskForKeyPayload = TargetNickname + ":WANTKEY";
			Result = SendBytesBlocking(AskForKeyPayload.c_str(), AskForKeyPayload.size());
			if (Result > 0)
			{
				std::cout << "Asked " << TargetNickname << " for public key, message pending." << std::endl;
			}
			else
			{
				if (Result == 0)
				{
					std::cout << "Connection closed." << std::endl;
					return 0;
				}
				int Error = errno;
				if (Error == EAGAIN || Error == EWOULDBLOCK || Error == EINTR)
				{
					std::cout << "Encountered problems sending bytes." << std::endl;
					continue;
				}
				std::cout << "Fatal error." << std::endl;
				return 0;
			}
		}
	}
}

