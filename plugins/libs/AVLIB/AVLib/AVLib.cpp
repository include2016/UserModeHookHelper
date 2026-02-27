// AVLib.cpp : Defines the functions for the static library.
//

#include "pch.h"
#include "framework.h"
#include <iostream>
#include <string>
#include <winsock2.h>   // Include Winsock2 for socket programming
#include <ws2tcpip.h>   // Include for socket address structures

#pragma comment(lib, "ws2_32.lib")  // Link with the winsock library

namespace AVLIB {

	class AV {
	public:
		// Constructor to connect to a socket endpoint
		// ok, now let me figure out how ClamAV scanner connect to clamd.exe 
		// the connect code of clamav scanner is located at C:\Users\x\clamav-main\common\clamdcom.c line 268, function "dconnect"
		// the default port is 3310, target addr is localhost, because out app will run at the same machine as where clamd running
		AV(const std::string& host, int port) {
			sockfd = INVALID_SOCKET;
			winsockInitialized = false;

			// Initialize Winsock
			WSADATA wsaData;
			int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
			if (result != 0) {
				std::cerr << "WSAStartup failed with error: " << result << std::endl;
				return;
			}
			winsockInitialized = true;

			addrinfo hints = {};
			hints.ai_family = AF_UNSPEC;
			hints.ai_socktype = SOCK_STREAM;
			hints.ai_protocol = IPPROTO_TCP;

			addrinfo* resolved = nullptr;
			const std::string portStr = std::to_string(port);
			result = getaddrinfo(host.c_str(), portStr.c_str(), &hints, &resolved);
			if (result != 0) {
				std::cerr << "Address resolution failed for " << host << ":" << port
					<< " with error: " << result << std::endl;
				WSACleanup();
				winsockInitialized = false;
				return;
			}

			for (addrinfo* candidate = resolved; candidate != nullptr; candidate = candidate->ai_next) {
				sockfd = socket(candidate->ai_family, candidate->ai_socktype, candidate->ai_protocol);
				if (sockfd == INVALID_SOCKET) {
					continue;
				}

				if (connect(sockfd, candidate->ai_addr, static_cast<int>(candidate->ai_addrlen)) == 0) {
					break;
				}

				closesocket(sockfd);
				sockfd = INVALID_SOCKET;
			}

			freeaddrinfo(resolved);

			if (sockfd == INVALID_SOCKET) {
				std::cerr << "Connection failed for " << host << ":" << port
					<< " with last socket error: " << WSAGetLastError() << std::endl;
				WSACleanup();
				winsockInitialized = false;
				return;
			}

			std::cout << "Successfully connected to " << host << ":" << port << std::endl;
		}

		// Method to send data
		void sendData(const std::string& data) {
			if (sockfd == INVALID_SOCKET) {
				std::cerr << "Send failed: socket is not connected." << std::endl;
				return;
			}

			int result = send(sockfd, data.c_str(), data.size(), 0);
			if (result == SOCKET_ERROR) {
				std::cerr << "Send failed with error: " << WSAGetLastError() << std::endl;
			}
			else {
				std::cout << "Sent: " << data << std::endl;
			}
		}

		// Method to receive data
		std::string receiveData() {
			if (sockfd == INVALID_SOCKET) {
				std::cerr << "Recv failed: socket is not connected." << std::endl;
				return "";
			}

			char buffer[1024] = { 0 };
			int bytesRead = recv(sockfd, buffer, sizeof(buffer), 0);
			if (bytesRead == SOCKET_ERROR) {
				std::cerr << "Recv failed with error: " << WSAGetLastError() << std::endl;
				return "";
			}
			return std::string(buffer, bytesRead);
		}

		// Destructor to close the socket and clean up
		~AV() {
			if (sockfd != INVALID_SOCKET) {
				closesocket(sockfd);
			}

			if (winsockInitialized) {
				WSACleanup();
			}

			std::cout << "Socket closed and Winsock cleaned up." << std::endl;
		}

	private:
		SOCKET sockfd; // Socket file descriptor
		bool winsockInitialized;
	};

} // namespace AVLIB
