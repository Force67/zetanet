project("zetanet")
    language("C++")
    kind("StaticLib")
    files({
        "*.cc",
        "*.h"
    })

    -- Exclude Windows-specific socket file on non-Windows
    filter("system:not windows")
      removefiles({ "z_socket_win.cc" })
    filter("system:windows")
      removefiles({ "z_socket_posix.cc" })
    filter({})

    if _OPTIONS["use-stl"] then
      defines("COMPILE_DLL")
      includedirs({
          ".",
          "../",
          "../vendor/lz4/lib",
      })
      links({
          "lz4",
      })
    else
      defines("COMPILE_DLL")
      includedirs({
          ".",
          "../",
          "../vendor/equilibrium",
          "../vendor/fmtlib/include",
          "../vendor/lz4/lib",
      })
      links({
          "base",
          "fmtlib",
          "lz4",
      })
    end

    apply_znet_crypto_links()
