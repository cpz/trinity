workspace "trinity"
  architecture "x64"
  startproject "trinity"

  configurations
  {
    "Debug",
    "Release",
    "Dist"
  }

  outputdir = "%{cfg.buildcfg}"

  IncludeDir = {}
  IncludeDir["lazyImporter"] = "dependencies/lazy_importer"
  IncludeDir["fmt"] = "dependencies/fmt/include"
  IncludeDir["WinReg"] = "dependencies/WinReg/WinReg"
  IncludeDir["WinWMI"] = "dependencies/WinWMI/include"
  
  CppVersion = "C++17"
  MsvcToolset = "v142"
  WindowsSdkVersion = "10.0"
  
  function DeclareMSVCOptions()
    filter "system:windows"
    staticruntime "Off"
    systemversion (WindowsSdkVersion)
    toolset (MsvcToolset)
    cppdialect (CppVersion)

    defines
    {
      "_CRT_SECURE_NO_WARNINGS",
      "NOMINMAX",
      "WIN32_LEAN_AND_MEAN",
      "_WIN32_WINNT=0x601" -- Support Windows 7
    }
    
    disablewarnings
    {
      "4100", -- C4100: unreferenced formal parameter
    }
  end
   
  function DeclareDebugOptions()
    filter "configurations:Debug"
      defines { "_DEBUG" }
      symbols "On"
    filter "not configurations:Debug"
      defines { "NDEBUG" }
  end
	
  project "fmt"
    location "dependencies/%{prj.name}"
    kind "StaticLib"
    language "C++"
    buildoptions { "/utf-8" }

    targetdir ("bin/lib/" .. outputdir)
    objdir ("bin/lib/int/" .. outputdir .. "/%{prj.name}")

    files
    {
      "dependencies/%{prj.name}/include/**.h",
      "dependencies/%{prj.name}/src/**.cc"
    }
	removefiles 
	{ 
	  "dependencies/%{prj.name}/src/fmt.cc"
	}
	
    includedirs
    {
      "dependencies/%{prj.name}/include"
    }

    DeclareMSVCOptions()
    DeclareDebugOptions()
	
  project "trinity"
    location "trinity"
    kind "ConsoleApp"
    language "C++"
    buildoptions { "/utf-8" }
    
    targetdir ("bin/" .. outputdir)
    objdir ("bin/int/" .. outputdir .. "/%{prj.name}")
	
    files
    {
      "src/**.h",
      "src/**.cpp",
    }

    includedirs
    {
	    "%{IncludeDir.fmt}",
	    "%{IncludeDir.lazyImporter}",
      "%{IncludeDir.WinReg}",
      "%{IncludeDir.WinWMI}",
      "src"
    }

    libdirs
    {
      "bin/lib"
    }

    links
    {
	    "fmt",
    }

    DeclareMSVCOptions()
    DeclareDebugOptions()

    flags { "NoImportLib", "Maps", "MultiProcessorCompile" }

    filter "configurations:Release"
      defines { "trinity_RELEASE" }
      optimize "speed"
	  
    filter "configurations:Dist"
      flags { "LinkTimeOptimization", "FatalCompileWarnings" }
      defines { "trinity_DIST" }
      optimize "speed"