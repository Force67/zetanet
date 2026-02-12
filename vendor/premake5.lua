-- Only include equilibrium build files if not using STL mode
if not _OPTIONS["use-stl"] then
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
    filter("system:windows")
      buildoptions({"/utf-8"})
    filter({})
end

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

if not _OPTIONS["use-stl"] then
  -- Some mbedtls revisions require generated headers that are not always
  -- present in this checkout. Build it only when those files exist.
  local has_mbedtls_generated_headers =
      os.isfile("mbedtls/library/common.h") and
      os.isfile("mbedtls/include/mbedtls/config_psa.h")

  if has_mbedtls_generated_headers then
    project("mbedtls")
      kind("StaticLib")
      language("C")
      includedirs({
        "mbedtls",
        "mbedtls/include",
        "mbedtls/library",
        "mbedtls/tf-psa-crypto/include",
        "mbedtls/tf-psa-crypto/core"
      })
      defines({
        "MBEDTLS_ALLOW_PRIVATE_ACCESS"
      })
      files({
        "mbedtls/library/*.c",
        "mbedtls/library/*.h",
      })
  else
    print("Warning: skipping mbedtls project; missing generated headers (library/common.h, include/mbedtls/config_psa.h).")
  end

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
    filter("system:windows")
      buildoptions({"/utf-8"})
    filter({})
end
