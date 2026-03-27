// AVLib.cpp : Defines the functions for the static library.
//

#include "pch.h"
#include "framework.h"
#include "AVLib.h"
#include <iostream>
#include <ws2tcpip.h>   // Include for socket address structures

#pragma comment(lib, "ws2_32.lib")  // Link with the winsock library

namespace AVLIB {
	static IHookServices* g_hookServices = nullptr;
	IHookServices* GetHookServices() {
		return g_hookServices;
	}
	void SetHookServices(IHookServices* services) {
		g_hookServices = services;
	}

	AV::AV(const std::string& host, int port) {
		sockfd = INVALID_SOCKET;
		winsockInitialized = false;

		WSADATA wsaData;
		int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
		if (result != 0) {
			LOG_AV(g_hookServices, L"WSAStartup failed, Error=0x%X\n", result);
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
			LOG_AV(g_hookServices, L"Address resolution failed, Host=%s, Port=%u, Error=0x%X\n", host.c_str(), port, result);
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
			LOG_AV(g_hookServices, L"Connection failed, Host=%s, Port=%u, Error=0x%X\n", host.c_str(), port, WSAGetLastError);

			WSACleanup();
			winsockInitialized = false;
			return;
		}

		LOG_AV(g_hookServices, L"Successfully connected to Host=%hs, Port=%u\n", host.c_str(), port);
	}

	void AV::sendData(const std::string& data) {
		if (sockfd == INVALID_SOCKET) {
			std::cerr << "Send failed: socket is not connected." << std::endl;
			return;
		}

		int result = send(sockfd, data.c_str(), static_cast<int>(data.size()), 0);
		if (result == SOCKET_ERROR) {
			std::cerr << "Send failed with error: " << WSAGetLastError() << std::endl;
		}
		else {
			std::cout << "Sent: " << data << std::endl;
		}
	}

	std::string AV::receiveData() {
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

	AV::~AV() {
		if (sockfd != INVALID_SOCKET) {
			closesocket(sockfd);
		}

		if (winsockInitialized) {
			WSACleanup();
		}

		std::cout << "Socket closed and Winsock cleaned up." << std::endl;
	}

} // namespace AVLIB
