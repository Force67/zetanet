include("equilibrium/build/platform_files.lua")
include("equilibrium/build/build_config.lua")

project("fmtlib")
  language("C++")
  kind("StaticLib")
  includedirs({
    "./fmtlib/include",
  })
  files({
    "fmtlib/src/format.cc",
    "fmtlib/src/os.cc",
  })
  pic("On")
  buildoptions({
    "/utf-8",
  })

project("lz4")
  language("C")
  kind("StaticLib")
  includedirs({
    "./lz4/lib",
  })
  files({
    "lz4/lib/*.c",
    "lz4/lib/*.h"
  })

project("mbedtls")
  kind("StaticLib")
  language("C")
  includedirs({
    "mbedtls/include",
    "mbedtls/library"
  })
  defines({
    "MBEDTLS_ALLOW_PRIVATE_ACCESS"
  })
  files({
    "mbedtls/library/*.c",
    "mbedtls/library/*.h",
  })

local function base_project()
  warnings("High")

  links({
    "fmtlib",
  })

  includedirs({
    "fmtlib/include",
  })

  defines({
    "BASE_IMPLEMENTATION",
    "TRACY_HAS_CALLSTACK"})
  includedirs({"equilibrium/base", "equilibrium"})
end

local function base_library()
  base_project()
  files({
    "equilibrium/base/**.cc",
    "equilibrium/base/**.h",
    "equilibrium/base/**.in",
    "equilibrium/base/**.inl"})
  removefiles({
    "**_test.cc",
    "allocator/memory_unittests_main.cc"})
end

project("base")
  kind("StaticLib")
  base_library()
  buildoptions({
    "/utf-8",
  })