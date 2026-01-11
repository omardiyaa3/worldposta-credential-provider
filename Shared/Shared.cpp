/* * * * * * * * * * * * * * * * * * * * *
**
** Copyright 2020 NetKnights GmbH
**           2020-2026 SysCo systemes de communication sa
** Author: Nils Behlen
**         Yann Jeanrenaud, Andre Liechti
**
**    Licensed under the Apache License, Version 2.0 (the "License");
**    you may not use this file except in compliance with the License.
**    You may obtain a copy of the License at
**
**        http://www.apache.org/licenses/LICENSE-2.0
**
**    Unless required by applicable law or agreed to in writing, software
**    distributed under the License is distributed on an "AS IS" BASIS,
**    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
**    See the License for the specific language governing permissions and
**    limitations under the License.
**
** * * * * * * * * * * * * * * * * * * */

#include "Shared.h"
#include "Logger.h"
#include "RegistryReader.h"
#include <tchar.h>
#include "MultiOTPRegistryReader.h"

namespace Shared {
	bool IsRequiredForScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, int caller)
	{
		ReleaseDebugPrint(__FUNCTION__);
		if (caller != FILTER && caller != PROVIDER)
		{
			ReleaseDebugPrint("Invalid argument for caller: " + std::to_string(caller));
			return false;
		}

		ReleaseDebugPrint(std::string("Caller: ") + (caller == FILTER ? "FILTER" : "PROVIDER"));
		ReleaseDebugPrint("Checking registry for scenario: " + CPUStoString(cpus));

		MultiOTPRegistryReader rr(L"CLSID\\{11A4894C-0968-40D0-840E-FAA4B8984916}\\");
		std::wstring entry;
		const bool isRemote = Shared::IsCurrentSessionRemote();
		ReleaseDebugPrint(std::string("IsRemoteSession: ") + (isRemote ? "true" : "false"));

		switch (cpus)
		{
		case CPUS_LOGON:
		{
			entry = rr.getRegistry(L"cpus_logon");
			ReleaseDebugPrint(L"cpus_logon registry value: [" + entry + L"]");
			break;
		}
		case CPUS_UNLOCK_WORKSTATION:
		{
			entry = rr.getRegistry(L"cpus_unlock");
			ReleaseDebugPrint(L"cpus_unlock registry value: [" + entry + L"]");
			break;
		}
		case CPUS_CREDUI:
		{
			entry = rr.getRegistry(L"cpus_credui");
			ReleaseDebugPrint(L"cpus_credui registry value: [" + entry + L"]");
			break;
		}
		case CPUS_CHANGE_PASSWORD:
		case CPUS_PLAP:
		case CPUS_INVALID:
			ReleaseDebugPrint("Scenario not supported (CHANGE_PASSWORD/PLAP/INVALID) - returning false");
			return false;
		default:
			ReleaseDebugPrint("Unknown scenario - returning false");
			return false;
		}

		// default - no additional config found
		if (entry.empty()) {
			ReleaseDebugPrint("Registry entry empty - defaulting to ENABLED (return true)");
			return true;
		}

		bool result = false;
		if (caller == FILTER)
		{
			// Check that we don't filter if the CP is not enumerated
			result = (entry == L"0e" || (entry == L"1e" && isRemote) || (entry == L"2e" && (!isRemote || cpus==CPUS_LOGON || cpus == CPUS_UNLOCK_WORKSTATION)));
			ReleaseDebugPrint(std::string("FILTER result: ") + (result ? "true" : "false"));
		}
		else if (caller == PROVIDER)
		{
			// 0 means fully enabled, 1-only remote, 2-non-remote, 3-disabled
			result = ((entry.at(0) == L'1' && isRemote) || (entry.at(0) == L'2' && (!isRemote || cpus == CPUS_LOGON || cpus == CPUS_UNLOCK_WORKSTATION)) || (entry.at(0) == L'0'));
			ReleaseDebugPrint(std::string("PROVIDER check - entry[0]=") + std::string(1, (char)entry.at(0)) + ", isRemote=" + (isRemote ? "true" : "false"));
			ReleaseDebugPrint(std::string("PROVIDER result: ") + (result ? "ENABLED" : "DISABLED"));
		}

		return result;
	}

#define TERMINAL_SERVER_KEY _T("SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\")
#define GLASS_SESSION_ID    _T("GlassSessionId")
	bool IsCurrentSessionRemote()
	{
		bool fIsRemoteable = false;
		DebugPrint("check for remote session...");
		if (GetSystemMetrics(SM_REMOTESESSION))
		{
			fIsRemoteable = true;
		}
		else
		{
			HKEY hRegKey = nullptr;
			LONG lResult;

			lResult = RegOpenKeyEx(
				HKEY_LOCAL_MACHINE,
				TERMINAL_SERVER_KEY,
				0, // ulOptions
				KEY_READ,
				&hRegKey
			);

			if (lResult == ERROR_SUCCESS)
			{
				DWORD dwGlassSessionId = 0;
				DWORD cbGlassSessionId = sizeof(dwGlassSessionId);
				DWORD dwType = 0;

				lResult = RegQueryValueEx(
					hRegKey,
					GLASS_SESSION_ID,
					NULL, // lpReserved
					&dwType,
					(BYTE*)&dwGlassSessionId,
					&cbGlassSessionId
				);

				if (lResult == ERROR_SUCCESS)
				{
					DWORD dwCurrentSessionId;

					if (ProcessIdToSessionId(GetCurrentProcessId(), &dwCurrentSessionId))
					{
						fIsRemoteable = (dwCurrentSessionId != dwGlassSessionId);
					}
				}
			}

			if (hRegKey)
			{
				RegCloseKey(hRegKey);
			}
		}

		DebugPrint(fIsRemoteable ? "session is remote" : "session is not remote");

		return fIsRemoteable;
	}

	std::string CPUStoString(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus)
	{
		switch (cpus)
		{
		case CPUS_LOGON:
			return "CPUS_LOGON";
		case CPUS_UNLOCK_WORKSTATION:
			return "CPUS_UNLOCK_WORKSTATION";
		case CPUS_CREDUI:
			return "CPUS_CREDUI";
		case CPUS_CHANGE_PASSWORD:
			return "CPUS_CHANGE_PASSWORD";
		case CPUS_PLAP:
			return "CPUS_PLAP";
		case CPUS_INVALID:
			return "CPUS_INVALID";
		default:
			return ("Unknown CPUS: " + std::to_string(cpus));
		}
	}
}
