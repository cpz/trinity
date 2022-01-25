#ifndef INCLUDE_H__
#define INCLUDE_H

#include <windows.h>
#include <thread>
#include <array>
#include <unordered_map>

#pragma region LazyImporter
#include <include/lazy_importer.hpp>
#pragma endregion LazyImporter

#pragma region FMT
#include <fmt/core.h>
#include <fmt/printf.h>
#include <fmt/format.h>
#include <fmt/xchar.h>
#include <fmt/os.h>
#include <fmt/color.h>
#pragma endregion FMT

#pragma region WinReg
#include <WinReg.hpp>
#pragma endregion WinReg

#pragma region WinWMI
#include <winwmi.hpp>
#pragma endregion WinWMI

using namespace std::chrono_literals;
using namespace std::this_thread;

bool Remove();

#endif
