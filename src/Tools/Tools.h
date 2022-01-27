#ifndef TOOLS_H__
#define TOOLS_H

#include <Include.h>

using Handle = std::unique_ptr<void, decltype(&CloseHandle)>;
using SetRestorePointtW = BOOL(__stdcall*)(PRESTOREPOINTINFOW, PSTATEMGRSTATUS);

class Tools
{
public:
    Tools() = default;
    ~Tools() = default;
    void print_error(std::string_view text, int error_number) const;

    uint32_t GetProccessByName(const std::wstring_view name);
    bool EnablePrivelege(const std::wstring_view name);
    BOOL IsRunAsAdmin();

    std::wstring GetUsername();

    [[nodiscard]] SC_HANDLE StopService(const std::wstring_view name) const;
    [[nodiscard]] BOOL StartTrustedInstallerService() const;
    [[nodiscard]] BOOL DeleteDefenderServices() const;

    [[nodiscard]] HRESULT DisableElamDrivers(void) const;
    [[nodiscard]] bool BcdEditDisableElamDrivers(void) const;

    void ImpersonateUserByProcessId(const uint32_t pid) const;


    bool InitializeRestorePoint(void);
    bool FinishRestorePoint(bool status);

private:
    bool InitializeComSecurity();

private:
    RESTOREPOINTINFOW restore_pt_info_ = {};
    STATEMGRSTATUS s_mgr_status_ = {};
    HMODULE h_sr_client_ = nullptr;
    SetRestorePointtW sr_set_restore_point_w_ = nullptr;
};

extern Tools* g_tools;
#endif
