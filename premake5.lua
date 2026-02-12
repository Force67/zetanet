-- Copyright (C) 2025 Vincent Hengel.
-- For licensing information see LICENSE at the root of this distribution.
require("premake", ">=5.0-beta3")

-- Option to compile without equilibrium, using STL only
newoption {
  trigger = "use-stl",
  description = "Build without equilibrium submodule, using STL replacements"
}

architecture("x86_64")

filter("architecture:x86_64")
    targetsuffix("_64")

filter("configurations:Debug")
    defines("TK_DBG")
    optimize("Off")
    symbols("On")

filter("configurations:Release")
    runtime("Release")
    optimize("Speed")

filter("language:C or C++")
    vectorextensions("SSE4.1")
    staticruntime("on")

filter("language:C++")
    cppdialect("C++20")

filter({})

-- Platform-specific defines
if os.target() == "windows" then
  defines("OS_WIN")
  buildoptions({"/utf-8"})
  defines("NOMINMAX")
end

if os.target() == "linux" then
  defines("OS_LINUX")
end

defines("PROJECT_NAME=\"Zetanet\"")

-- STL mode define
if _OPTIONS["use-stl"] then
  defines("ZNET_USE_STL")
end

workspace("Zetanet")
    targetdir("bin")
    configurations({
      "Debug",
      "Release",
      "Shipping",
    })
    flags {
      "MultiProcessorCompile"
    }
    include("./vendor")
    include("./znet")
    include("./samples")
