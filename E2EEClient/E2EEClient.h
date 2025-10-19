// CmakeProject.h : Include file for standard system include files,
// or project specific include files.

#pragma once

#include <iostream>

int SendBytesBlocking(const char* buffer, int length);
void EncryptAndSend(const std::string& Target, const std::string& Message);
void HandleIncomingMessages();