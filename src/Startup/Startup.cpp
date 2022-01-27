#include <iostream>

#include "../Include.h"
#include "../Tools/Tools.h"

bool Remove()
{
    std::locale::global(std::locale("en_US.UTF-8"));

    if (!g_tools->IsRunAsAdmin())
    {
        fmt::print(fg(fmt::color::crimson) | fmt::emphasis::bold, "[!] Trinity should be run as administrator!\n");
        return false;
    }

    if (g_tools->EnablePrivelege(L"SeDebugPrivilege"))
        fmt::print("[00] Priveleges was updated!\n");

    if (!g_tools->StartTrustedInstallerService())
    {
        fmt::print(fg(fmt::color::crimson) | fmt::emphasis::bold, "[!] Failed to create TrustedInstaller service!");
        return false;
    }
    fmt::print("[01] TrustedInstaller service was created!\n");

    fmt::print(L"[02] Current user is {}.\n", g_tools->GetUsername().c_str());

    try
    {
        const auto winlogon_pid = g_tools->GetProccessByName(L"winlogon.exe");
        if (winlogon_pid != NULL)
            fmt::print("[03] Winlogon process was found!\n");
        else
            throw std::runtime_error("Failed to find winlogon proccess!");

        g_tools->ImpersonateUserByProcessId(winlogon_pid);

        const auto trustedinstaller_pid = g_tools->GetProccessByName(L"TrustedInstaller.exe");
        if (trustedinstaller_pid != NULL)
            fmt::print("[04] TrustedInstaller process was found!\n");
        else
            throw std::runtime_error("Failed to find TrustedInstaller proccess!");

        g_tools->ImpersonateUserByProcessId(trustedinstaller_pid);
    }
    catch (std::exception& err)
    {
        fmt::print(fg(fmt::color::crimson) | fmt::emphasis::bold, err.what());
        return false;
    }

    fmt::print(L"[05] Impersonated user is {}.\n", g_tools->GetUsername().c_str());

    {
        auto&& msft_mp_computer_status = std::make_unique<WinWmi>(
            L"root\\Microsoft\\Windows\\Defender",
            L"MSFT_MpComputerStatus"
        );
        if (const auto error = msft_mp_computer_status->GetLastError(); error != WmiError::kNone)
        {
            fmt::print(fg(fmt::color::crimson) | fmt::emphasis::bold,
                       "[!] Failed to access the MSFT_MpComputerStatus WMI\n");
            return false;
        }

        auto&& msft_mp_preference = std::make_unique<WinWmi>(
            L"root\\Microsoft\\Windows\\Defender",
            L"MSFT_MpPreference",
            L"Set"
        );
        if (const auto error = msft_mp_preference->GetLastError(); error != WmiError::kNone)
        {
            fmt::print(fg(fmt::color::crimson) | fmt::emphasis::bold,
                       "[!] Failed to access the MSFT_MpPreference WMI\n");
            return false;
        }
        fmt::print("[06] Got access to Windows Defender WMI!\n");


        fmt::print(L"   [+] Windows Defender Computer ID: {}\n",
                   msft_mp_computer_status->get(L"ComputerID").value_or(L"Failed to retrieve ComputerID"));


        std::unordered_map<std::wstring_view, WmiType> defender_information = {
            {L"AMServiceEnabled", WmiType::kBool},
            {L"AntispywareEnabled", WmiType::kBool},
            {L"AntivirusEnabled", WmiType::kBool},
            {L"IsTamperProtected", WmiType::kBool},
            {L"NISEnabled", WmiType::kBool},
            {L"RealTimeProtectionEnabled", WmiType::kBool},
        };

        for (const auto& [name, type] : defender_information)
            if (bool result = true; msft_mp_computer_status->get<bool>(name.data(), type, result))
                fmt::print(L"   [+] Windows Defender {}: {}.\n", name, result);

        std::array<std::wstring_view, 21> defender_bool_names = {
            L"DisableRealtimeMonitoring",
            L"DisableBehaviorMonitoring",
            L"DisableBlockAtFirstSeen",
            L"DisableIOAVProtection",
            L"DisablePrivacyMode",
            L"SignatureDisableUpdateOnStartupWithoutEngine",
            L"DisableArchiveScanning",
            L"DisableIntrusionPreventionSystem",
            L"DisableScriptScanning",
            L"DisableEmailScanning",
            L"DisableScanningNetworkFiles",
            L"DisableRemovableDriveScanning",
            L"DisableAntiSpyware",
            L"DisableAntiVirus",
            L"DisableTlsParsing",
            L"DisableHttpParsing",
            L"DisableDnsParsing",
            L"DisableDnsOverTcpParsing",
            L"DisableSshParsing",
            L"DisableInboundConnectionFiltering",
            L"DisableRdpParsing"
        };

        for (const auto& name : defender_bool_names)
            if (msft_mp_preference->set<BOOL>(name.data(), WmiType::kBool, TRUE))
                fmt::print(L"    [?] Successfuly set {} to true!\n", name);

        std::unordered_map<std::wstring_view, uint8_t> defender_uint_values = {
            {L"PUAProtection", 0},
            {L"EnableControlledFolderAccess", 0},
            {L"SubmitSamplesConsent", 2},
            {L"MAPSReporting", 0},
            {L"HighThreatDefaultAction", 6},
            {L"ModerateThreatDefaultAction", 6},
            {L"LowThreatDefaultAction", 6},
            {L"SevereThreatDefaultAction", 6},
            {L"ScanScheduleDay", 8},
        };

        for (const auto& [name, value] : defender_uint_values)
            if (msft_mp_preference->set<uint8_t>(name.data(), WmiType::kUint8, value))
                fmt::print(L"    [?] Successfuly set {} to {}!\n", name, value);
    }

    if (const auto result = g_tools->DisableElamDrivers(); result != S_OK)
    {
        fmt::print(fg(fmt::color::crimson) | fmt::emphasis::bold, "[!] Failed to disable elam drivers. Code: {0:X}\n",
                   result);

        if (g_tools->BcdEditDisableElamDrivers())
            fmt::print("[07] Succesfully disabled elam drivers!\n");
    }

    if (!g_tools->DeleteDefenderServices())
    {
        fmt::print(fg(fmt::color::crimson) | fmt::emphasis::bold, "[!] Failed to delete Windows Defender Services\n");
        return false;
    }
    fmt::print("[08] Successfuly deleted Windows Defender Services!\n");

    {
        winreg::RegKey windows_system{HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows\\System"};
        windows_system.SetDwordValue(L"EnableSmartScreen", 0);
        windows_system.SetExpandStringValue(L"ShellSmartScreenLevel", L"Warn");
        fmt::print("[09] SmartScreen was disabled!\n");
    }

    {
        winreg::RegKey defender_features{HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows Defender\\Features"};
        defender_features.SetDwordValue(L"TamperProtection", 0);
        fmt::print("[10] Tamper protection was disabled!\n");
    }

    {
        winreg::RegKey defender{HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows Defender"};
        defender.SetDwordValue(L"DisableRealtimeMonitoring", 1);
        fmt::print("[11] Real-time monitoring was disabled!\n");
    }

    {
        winreg::RegKey defender{HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\SecurityHealthService"};
        defender.SetDwordValue(L"Start", 4);
        fmt::print("[12] Security Health Service was disabled!\n");
    }

    return true;
}
