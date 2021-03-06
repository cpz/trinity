#include "../Include.h"
#include "Tools/Tools.h"

int main(int argc, char* argv[])
{
    SetConsoleTitleW(L"T R I N I T Y");

    const HANDLE handle = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    GetConsoleMode(handle, &mode);
    mode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    SetConsoleMode(handle, mode);

    args::ArgumentParser p("");
    args::HelpFlag help(p, "help", "Display this help menu", {'h', "help"});
    args::Flag system_restore(p, "restore-point", "Create system restore point before removing defender",
                              {'s', "system-restore"});

    fmt::print(fg(fmt::color::cornsilk) | fmt::emphasis::faint,
               R"(                                   
                                 .--.   _..._   .--.                               
                                  |__| .'     '. |__|      .-.          .-          
                      .|  .-,.--. .--..   .-.   ..--.     .|\ \        / /          
                    .' |_ |  .-. ||  ||  '   '  ||  |   .' |_\ \      / /           
                  .'     || |  | ||  ||  |   |  ||  | .'     |\ \    / /            
                 '--.  .-'| |  | ||  ||  |   |  ||  |'--.  .-' \ \  / /             
                    |  |  | |  '- |  ||  |   |  ||  |   |  |    \ `  /              
                    |  |  | |     |__||  |   |  ||__|   |  |     \  /               
                    |  '.'| |         |  |   |  |       |  '.'   / /                
                    |   / |_|         |  |   |  |       |   /|`-' /                 
                    `'-'              '--'   '--'       `'-'  '..'                  
                    is going to disable & delete Windows Defender from your system.

                    [x] Created by cpz / og
                    [!] https://github.com/cpz/trinity/
                    [!] https://git.tcp.direct/og/trinity  
    )");
    fmt::print(fg(fmt::color::cornsilk) | fmt::emphasis::faint,
               "                [?] Build at {} {}\n",
               __DATE__,
               __TIME__);
    fmt::print("\n");

    try
    {
        p.ParseCLI(argc, argv);
    }
    catch (args::Help)
    {
        fmt::print("{}\n", p.Help());
        return 0;
    }
    catch (args::ParseError e)
    {
        fmt::print(fg(fmt::color::crimson) | fmt::emphasis::bold,
                   "[!] {}\n\n", e.what());
        fmt::print("{}\n", p.Help());
        return 1;
    }

    auto should_system_store = system_restore.Get();
    if (should_system_store)
    {
        if (!g_tools->InitializeRestorePoint())
        {
            fmt::print("[#] Failed to initialize system restore point!\n");
            fmt::print("[#] Do you want to continue? Y(es) or N(o): \n");
            if (auto response = getchar(); response == 'N' || response == 'n')
                return EXIT_FAILURE;
        }
        else fmt::print("[#] Creating system restore point!\n");
    }

    const auto status = Remove();
    if (status)
        fmt::print(fg(fmt::color::cornsilk) | fmt::emphasis::faint,
                   "[V] Windows Defender was successfuly removed.\n    [V] We are recommend you to reboot after closing this app.\n");

    if (should_system_store)
    {
        if (g_tools->FinishRestorePoint(status))
        {
            fmt::print("[#] Succesfully finished system restore point!\n");
        }
        else
        {
            fmt::print("[#] System restore point was cancelled.\n");
        }

        fmt::print("{}\n", should_system_store);
    }

    fmt::print(fg(fmt::color::dark_cyan) | fmt::emphasis::conceal, "\n\nPress any key to close application.");
    getchar();

    return EXIT_SUCCESS;
}
