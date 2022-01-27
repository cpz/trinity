#include "Tools.h"

#include <TlHelp32.h>
#include <filesystem>
#include <accctrl.h>
#include <aclapi.h>
#include <objbase.h>
#include <strsafe.h>

Tools* g_tools = new Tools();

void Tools::print_error(std::string_view text, int error_number) const
{
    fmt::memory_buffer message;
    fmt::detail::format_windows_error(message, error_number, text.data());
    message.push_back('\n');
    fmt::print(fg(fmt::color::crimson) | fmt::emphasis::bold, to_string(message));
}

uint32_t Tools::GetProccessByName(const std::wstring_view name)
{
    const Handle snap_shot{CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0), &CloseHandle};

    if (snap_shot.get() == INVALID_HANDLE_VALUE)
        return NULL;

    PROCESSENTRY32W process_entry{sizeof(PROCESSENTRY32W)};

    for (Process32FirstW(snap_shot.get(), &process_entry); Process32NextW(snap_shot.get(), &process_entry);)
        if (std::wcscmp(name.data(), process_entry.szExeFile) == NULL)
            return process_entry.th32ProcessID;

    return NULL;
}

bool Tools::EnablePrivelege(const std::wstring_view name)
{
    HANDLE token_handle = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token_handle))
        return false;

    LUID luid{};
    if (!LookupPrivilegeValueW(nullptr, name.data(), &luid))
        return false;

    TOKEN_PRIVILEGES token_state{};
    token_state.PrivilegeCount = 1;
    token_state.Privileges[0].Luid = luid;
    token_state.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(token_handle, FALSE, &token_state, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr))
        return false;

    CloseHandle(token_handle);
    return true;
}

std::wstring Tools::GetUsername()
{
    std::wstring username;

    if (static auto p_getusername = LI_FN(GetUserNameW).get(); p_getusername)
    {
        DWORD size = 0;
        auto ret = p_getusername(nullptr, &size);
        if (const auto error_code = GetLastError(); !ret &&
            ERROR_INSUFFICIENT_BUFFER == error_code || ERROR_BUFFER_OVERFLOW == error_code &&
            size > 0)
        {
            username.resize(size);
            ret = p_getusername(&username[0], &size);
        }
    }

    return username;
}

BOOL Tools::IsRunAsAdmin()
{
    BOOL is_run_as_admin{FALSE};
    DWORD dw_error{ERROR_SUCCESS};
    PSID administrators_group{};

    SID_IDENTIFIER_AUTHORITY nt_authority = SECURITY_NT_AUTHORITY;
    if (!AllocateAndInitializeSid(
        &nt_authority,
        2,
        SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0,
        &administrators_group))
        return is_run_as_admin;

    if (!CheckTokenMembership(nullptr, administrators_group, &is_run_as_admin))
        return is_run_as_admin;

    if (administrators_group)
    {
        FreeSid(administrators_group);
        administrators_group = {};
    }

    return is_run_as_admin;
}

BOOL Tools::StartTrustedInstallerService() const
{
    const SC_HANDLE sch_sc_manager = OpenSCManager(
        nullptr,
        nullptr,
        SC_MANAGER_ALL_ACCESS);

    if (sch_sc_manager == nullptr)
    {
        print_error("[!] OpenSCManager failed", GetLastError());
        return FALSE;
    }

    const SC_HANDLE sch_service = OpenService(
        sch_sc_manager,
        L"TrustedInstaller",
        SERVICE_START);

    if (sch_service == nullptr)
    {
        print_error("[!] OpenService failed", GetLastError());
        CloseServiceHandle(sch_sc_manager);
        return FALSE;
    }

    if (!StartService(
        sch_service,
        0,
        nullptr) && GetLastError() != ERROR_SERVICE_ALREADY_RUNNING)
    {
        print_error("[!] OStartService failed", GetLastError());
        CloseServiceHandle(sch_service);
        CloseServiceHandle(sch_sc_manager);
        return FALSE;
    }

    sleep_for(2s);
    CloseServiceHandle(sch_service);
    CloseServiceHandle(sch_sc_manager);

    return TRUE;
}

void Tools::ImpersonateUserByProcessId(const uint32_t pid) const
{
    const Handle process_handle{OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid), &CloseHandle};
    if (process_handle.get() != nullptr)
        fmt::print("   [+] Got access to process!\n");
    else
        throw fmt::windows_error(GetLastError(), "[!] Failed to obtain access to process! Code");

    HANDLE token = nullptr;
    BOOL process_token = OpenProcessToken(process_handle.get(), TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY,
                                          &token);
    if (token != nullptr && process_token != FALSE)
        fmt::printf("   [+] Got access to process token!\n");
    else
        throw fmt::windows_error(GetLastError(), "[!] Failed to obtain access to process token! Code");

    const BOOL impersonate_user = ImpersonateLoggedOnUser(token);
    if (!impersonate_user)
        throw fmt::windows_error(GetLastError(), "[!] Failed to imperonate user! Code");

    CloseHandle(token);
}

SC_HANDLE Tools::StopService(const std::wstring_view name) const
{
    SERVICE_STATUS_PROCESS ssp;

    const SC_HANDLE sch_sc_manager = OpenSCManagerW(
        nullptr,
        nullptr,
        SC_MANAGER_ALL_ACCESS);

    if (sch_sc_manager == nullptr)
    {
        fmt::print(fg(fmt::color::crimson) | fmt::emphasis::bold, "[!] OpenSCManager failed {}\n", GetLastError());
        return nullptr;
    }

    const SC_HANDLE sch_service = OpenServiceW(
        sch_sc_manager,
        name.data(),
        SERVICE_STOP |
        SERVICE_QUERY_STATUS |
        SERVICE_ENUMERATE_DEPENDENTS |
        DELETE);

    if (sch_service == nullptr)
    {
        if (const auto error = GetLastError(); error != ERROR_SERVICE_DOES_NOT_EXIST)
            print_error("[!] OpenService failed", GetLastError());

        CloseServiceHandle(sch_sc_manager);
        return nullptr;
    }

    if (!ControlService(
            sch_service,
            SERVICE_CONTROL_STOP,
            reinterpret_cast<LPSERVICE_STATUS>(&ssp)) &&
        GetLastError() != ERROR_SERVICE_NOT_ACTIVE)
    {
        print_error("[!] ControlService failed", GetLastError());
        CloseServiceHandle(sch_service);
        CloseServiceHandle(sch_sc_manager);
        return nullptr;
    }

    return sch_service;
}

BOOL Tools::DeleteDefenderServices() const
{
    std::array<std::wstring, 3> services = {
        L"WinDefend",
        L"WdFilter",
        L"WdBoot"
    };

    auto status = true;
    for (auto& service : services)
    {
        const auto service_handle = StopService(service.data());
        if (service_handle == nullptr)
            continue;

        if (!DeleteService(service_handle))
        {
            print_error("[!] DeleteService failed", GetLastError());
            status = false;
        }

        CloseServiceHandle(service_handle);
    }

    return status;
}

HRESULT Tools::DisableElamDrivers(void) const
{
    IWbemServices* p_svc = nullptr;
    IWbemLocator* p_bem_location = nullptr;
    CIMTYPE cim_type;
    long flavor;
    HRESULT hres = S_OK;
    auto bcd_os_loader_boolean_disable_elam_drivers = 0x260000E1;

    hres = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (FAILED(hres))
    {
        return hres;
    }
    hres = CoInitializeSecurity(
        nullptr,
        -1,
        nullptr,
        nullptr,
        RPC_C_AUTHN_LEVEL_DEFAULT,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        nullptr,
        EOAC_NONE,
        nullptr
    );

    if (FAILED(hres) && hres != RPC_E_TOO_LATE)
    {
        CoUninitialize();
        return hres;
    }

    hres = CoCreateInstance(
        CLSID_WbemLocator,
        nullptr,
        CLSCTX_INPROC_SERVER,
        IID_IWbemLocator, reinterpret_cast<LPVOID*>(&p_bem_location));

    if (FAILED(hres))
    {
        CoUninitialize();
        return hres;
    }

    hres = p_bem_location->ConnectServer(
        _bstr_t(L"root\\wmi"),
        nullptr,
        nullptr,
        nullptr,
        NULL,
        nullptr,
        nullptr,
        &p_svc
    );

    if (FAILED(hres))
        return hres;

    hres = CoSetProxyBlanket(
        p_svc,
        RPC_C_AUTHN_WINNT,
        RPC_C_AUTHZ_NONE,
        nullptr,
        RPC_C_AUTHN_LEVEL_CALL,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        nullptr,
        EOAC_NONE
    );

    if (FAILED(hres))
        return hres;

    IWbemClassObject* p_bcd_store_class = nullptr;
    BSTR bcd_store_class_name = SysAllocString(L"BCDStore");
    hres = p_svc->GetObject(bcd_store_class_name, 0, nullptr, &p_bcd_store_class, nullptr);
    if (FAILED(hres))
        return hres;

    VARIANT bcd_store_path;
    hres = p_bcd_store_class->Get(L"__RELPATH", 0, &bcd_store_path, &cim_type, &flavor);
    if (FAILED(hres))
        return hres;

    IWbemClassObject* p_bcd_store_in_params_definition = nullptr;
    hres = p_bcd_store_class->GetMethod(L"OpenStore", 0, &p_bcd_store_in_params_definition, nullptr);
    if (FAILED(hres))
        return hres;

    IWbemClassObject* p_bcd_store_class_instance = nullptr;
    hres = p_bcd_store_in_params_definition->SpawnInstance(0, &p_bcd_store_class_instance);
    if (FAILED(hres))
        return hres;

    VARIANT param_file;
    param_file.vt = VT_BSTR;
    param_file.bstrVal = _bstr_t(L"");
    hres = p_bcd_store_class_instance->Put(L"File", 0, &param_file, 0);
    if (FAILED(hres))
        return hres;

    IWbemClassObject* p_bcd_store_out_params_definition = nullptr;
    hres = p_svc->ExecMethod(bcd_store_path.bstrVal, bstr_t(L"OpenStore"), 0, nullptr,
                             p_bcd_store_class_instance, &p_bcd_store_out_params_definition, nullptr);
    if (FAILED(hres))
        return hres;

    VARIANT bcd_store_variant;
    hres = p_bcd_store_out_params_definition->Get(L"Store", 0, &bcd_store_variant, &cim_type, &flavor);
    if (FAILED(hres))
        return hres;

    VARIANT bcd_open_store_path;
    auto p_bcd_store = static_cast<IWbemClassObject*>(bcd_store_variant.byref);
    hres = p_bcd_store->Get(L"__RELPATH", 0, &bcd_open_store_path, &cim_type, &flavor);
    if (FAILED(hres))
        return hres;

    IWbemClassObject* p_in_open_object_params = nullptr;
    hres = p_bcd_store_class->GetMethod(L"OpenObject", 0, &p_in_open_object_params, nullptr);
    if (FAILED(hres))
        return hres;

    VARIANT param_id;
    param_id.vt = VT_BSTR;
    param_id.bstrVal = _bstr_t(L"{fa926493-6f1c-4193-a414-58f0b2456d1e}");
    hres = p_in_open_object_params->Put(L"Id", 0, &param_id, 0);
    if (FAILED(hres))
        return hres;

    IWbemClassObject* p_out_open_object_params_definition = nullptr;
    hres = p_svc->ExecMethod(bcd_open_store_path.bstrVal, bstr_t(L"OpenObject"), 0, nullptr,
                             p_in_open_object_params, &p_out_open_object_params_definition, nullptr);
    if (FAILED(hres))
        return hres;

    VARIANT bcd_object_variant;
    hres = p_out_open_object_params_definition->Get(L"Object", 0, &bcd_object_variant, &cim_type, &flavor);
    if (FAILED(hres))
        return hres;

    auto p_bcd_object = static_cast<IWbemClassObject*>(bcd_object_variant.byref);
    VARIANT bcd_object_path;
    hres = p_bcd_object->Get(L"__RELPATH", 0, &bcd_object_path, &cim_type, &flavor);
    if (FAILED(hres))
        return hres;

    IWbemClassObject* p_bcd_obj_class = nullptr;
    BSTR bcd_object_class_name = SysAllocString(L"BCDObject");
    hres = p_svc->GetObject(bcd_object_class_name, 0, nullptr, &p_bcd_obj_class, nullptr);
    if (FAILED(hres))
        return hres;

    IWbemClassObject* p_bcd_obj_in_params_definition = nullptr;
    hres = p_bcd_obj_class->GetMethod(L"GetElement", 0, &p_bcd_obj_in_params_definition, nullptr);
    if (FAILED(hres))
        return hres;

    IWbemClassObject* p_bcd_obj_class_instance = nullptr;
    hres = p_bcd_obj_in_params_definition->SpawnInstance(0, &p_bcd_obj_class_instance);
    if (FAILED(hres))
        return hres;

    IWbemClassObject* p_in_get_element_params = nullptr;
    hres = p_bcd_obj_class->GetMethod(L"GetElement", 0, &p_in_get_element_params, nullptr);
    if (FAILED(hres))
        return hres;

    VARIANT param_type;
    param_type.vt = VT_I4;
    param_type.lVal = bcd_os_loader_boolean_disable_elam_drivers;
    hres = p_in_get_element_params->Put(L"Type", 0, &param_type, 0);
    if (FAILED(hres))
        return hres;

    IWbemClassObject* p_out_get_element_definition = nullptr;
    hres = p_svc->ExecMethod(bcd_object_path.bstrVal, bstr_t(L"GetElement"), 0, nullptr, p_in_get_element_params,
                             &p_out_get_element_definition, nullptr);
    if (FAILED(hres))
        return hres;

    VARIANT bcd_element_definitionvariant;
    hres = p_out_get_element_definition->Get(L"Element", 0, &bcd_element_definitionvariant, &cim_type, &flavor);
    if (FAILED(hres))
        return hres;

    auto p_bcd_element = static_cast<IWbemClassObject*>(bcd_element_definitionvariant.byref);
    VARIANT bcd_elementvariant;
    hres = p_bcd_element->Get(L"Boolean", 0, &bcd_elementvariant, &cim_type, &flavor);
    if (FAILED(hres))
        return hres;

    fmt::print("[07] BcdStore: disableelamdrivers set to {}.\n", static_cast<bool>(bcd_elementvariant.boolVal));

    if (bcd_elementvariant.boolVal == 0)
    {
        IWbemClassObject* p_in_set_boolean_element_params = nullptr;
        hres = p_bcd_obj_class->GetMethod(L"SetBooleanElement", 0, &p_in_set_boolean_element_params, nullptr);
        if (FAILED(hres))
            return hres;

        hres = p_in_set_boolean_element_params->Put(L"Type", 0, &param_type, 0);
        if (FAILED(hres))
            return hres;

        bcd_elementvariant.boolVal = TRUE;
        hres = p_in_set_boolean_element_params->Put(L"Boolean", 0, &bcd_elementvariant, CIM_BOOLEAN);
        if (FAILED(hres))
            return hres;

        IWbemClassObject* p_out_set_boolean_element_definition = nullptr;
        hres = p_svc->ExecMethod(bcd_object_path.bstrVal, bstr_t(L"SetBooleanElement"), 0, NULL,
                                 p_in_set_boolean_element_params,
                                 &p_out_set_boolean_element_definition, nullptr);
        if (FAILED(hres))
            return hres;

        fmt::print("    [01] BcdStore: Changed disableelamdrivers to {}.\n",
                   static_cast<bool>(bcd_elementvariant.boolVal));
    }

    VariantClear(&bcd_store_path);
    VariantClear(&param_file);
    VariantClear(&bcd_store_variant);
    VariantClear(&bcd_open_store_path);
    VariantClear(&param_id);
    VariantClear(&bcd_object_variant);
    VariantClear(&bcd_object_path);
    VariantClear(&param_type);

    return S_OK;
}

bool Tools::BcdEditDisableElamDrivers() const
{
    STARTUPINFOW si = {0};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi = {0};
    DWORD exit_code;

    HANDLE token_handle = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY, &token_handle))
        return false;

    const std::unique_ptr<wchar_t[]> system_directory(new wchar_t[MAX_PATH]);
    GetSystemDirectoryW(system_directory.get(), MAX_PATH);

    std::wstring bcdedit_path(system_directory.get());
    bcdedit_path.append(L"\\bcdedit.exe");

    if (!std::filesystem::exists(bcdedit_path))
        return false;

    if (!CreateProcessAsUserW(token_handle,
                              bcdedit_path.c_str(),
                              L"bcdedit /set disableelamdrivers true",
                              nullptr,
                              nullptr,
                              FALSE,
                              0,
                              nullptr,
                              nullptr,
                              &si,
                              &pi))
    {
        print_error("[!] CreateProccessAsUser failed", GetLastError());
        return false;
    }

    WaitForSingleObject(pi.hProcess, INFINITE);
    GetExitCodeProcess(pi.hProcess, &exit_code);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    if (exit_code != EXIT_SUCCESS)
        return false;

    return true;
}

bool Tools::InitializeComSecurity()
{
    SECURITY_DESCRIPTOR security_desc = {0};
    EXPLICIT_ACCESS ea[5] = {0};

    PACL acl = {};
    std::unique_ptr<std::remove_pointer<PACL>::type,
                    decltype(&LocalFree)> acl_guard(acl, &LocalFree);

    std::vector<PSID> rg_sid = {};

    BOOL ret = InitializeSecurityDescriptor(&security_desc, SECURITY_DESCRIPTOR_REVISION);
    if (!ret)
        return false;

    std::array<WELL_KNOWN_SID_TYPE, 5> sids_id = {
        WinBuiltinAdministratorsSid,
        WinLocalServiceSid,
        WinNetworkServiceSid,
        WinSelfSid,
        WinLocalSystemSid
    };

    for (const auto& id : sids_id)
    {
        ULONGLONG sid[(SECURITY_MAX_SID_SIZE + sizeof(ULONGLONG) - 1) / sizeof(ULONGLONG)] = {0};
        DWORD cb_sid = sizeof(sid);
        ret = CreateWellKnownSid(id, nullptr, sid, &cb_sid);
        if (!ret)
            return false;

        rg_sid.emplace_back(sid);
    }

    for (auto i = 0; i < 5; i++)
    {
        ea[i].grfAccessPermissions = COM_RIGHTS_EXECUTE | COM_RIGHTS_EXECUTE_LOCAL;
        ea[i].grfAccessMode = SET_ACCESS;
        ea[i].grfInheritance = NO_INHERITANCE;
        ea[i].Trustee.pMultipleTrustee = nullptr;
        ea[i].Trustee.MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE;
        ea[i].Trustee.TrusteeForm = TRUSTEE_IS_SID;
        ea[i].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
        ea[i].Trustee.ptstrName = static_cast<LPTSTR>(rg_sid.at(i));
    }

    // Create an access control list (ACL) using this ACE list.
    const auto dw_ret = SetEntriesInAclW(ARRAYSIZE(ea), ea, nullptr, &acl);
    if (dw_ret != ERROR_SUCCESS || acl == nullptr)
        if (!ret)
            return false;

    ret = SetSecurityDescriptorOwner(&security_desc, rg_sid.at(0), FALSE);
    if (!ret)
        return false;

    ret = SetSecurityDescriptorGroup(&security_desc, rg_sid.at(0), FALSE);
    if (!ret)
        return false;

    ret = SetSecurityDescriptorDacl(&security_desc, TRUE, acl, FALSE);
    if (!ret)
        return false;

    const auto hr_ret = CoInitializeSecurity(&security_desc,
                                             -1,
                                             nullptr,
                                             nullptr,
                                             RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
                                             RPC_C_IMP_LEVEL_IDENTIFY,
                                             nullptr,
                                             EOAC_DISABLE_AAA | EOAC_NO_CUSTOM_MARSHAL,
                                             nullptr);
    if (FAILED(hr_ret))
        return false;

    return true;
}

bool Tools::InitializeRestorePoint(void)
{
    if (const auto hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED); FAILED(hr))
        return false;

    auto ret = InitializeComSecurity();
    if (!ret)
        return false;

    restore_pt_info_.dwEventType = BEGIN_SYSTEM_CHANGE;
    restore_pt_info_.dwRestorePtType = APPLICATION_INSTALL;
    restore_pt_info_.llSequenceNumber = 0;

    StringCbCopyW(restore_pt_info_.szDescription,
                  sizeof(restore_pt_info_.szDescription),
                  L"T R I N I T Y [WINDOWS DEFENDER REMOVER]");

    h_sr_client_ = LoadLibraryW(L"srclient.dll");
    if (h_sr_client_ == nullptr)
    {
        fmt::print(fg(fmt::color::crimson) | fmt::emphasis::bold, "[!] System Restore is not present!\n");
        return false;
    }

    sr_set_restore_point_w_ = reinterpret_cast<SetRestorePointtW>(
        GetProcAddress(h_sr_client_, "SRSetRestorePointW"));
    if (sr_set_restore_point_w_ == nullptr)
    {
        fmt::print(fg(fmt::color::crimson) | fmt::emphasis::bold, "[!] Failed to find SRSetRestorePointW.\n");
        return false;
    }

    ret = sr_set_restore_point_w_(&restore_pt_info_, &s_mgr_status_);
    if (!ret)
    {
        const auto status = s_mgr_status_.nStatus;
        if (status == ERROR_SERVICE_DISABLED)
        {
            fmt::print(fg(fmt::color::crimson) | fmt::emphasis::bold, "[!] Failed to find SRSetRestorePointW.\n");
            return false;
        }

        print_error("[!] Failure to create the restore point", status);
        return false;
    }

    return true;
}

bool Tools::FinishRestorePoint(bool status)
{
    if (status)
    {
        restore_pt_info_.dwEventType = END_SYSTEM_CHANGE;
        restore_pt_info_.llSequenceNumber = s_mgr_status_.llSequenceNumber;
        const auto ret = sr_set_restore_point_w_(&restore_pt_info_, &s_mgr_status_);
        if (!ret)
        {
            const auto n_status = s_mgr_status_.nStatus;
            print_error("[!] Failure to end the restore point", n_status);
            return false;
        }
    }
    else
    {
        restore_pt_info_.dwEventType = END_SYSTEM_CHANGE;
        restore_pt_info_.dwRestorePtType = CANCELLED_OPERATION;
        restore_pt_info_.llSequenceNumber = s_mgr_status_.llSequenceNumber;
        const auto ret = sr_set_restore_point_w_(&restore_pt_info_, &s_mgr_status_);
        if (!ret)
        {
            const auto n_status = s_mgr_status_.nStatus;
            print_error("[!] Failure to cancel the restore point", n_status);
            return false;
        }
    }

    FreeLibrary(h_sr_client_);
    return true;
}
