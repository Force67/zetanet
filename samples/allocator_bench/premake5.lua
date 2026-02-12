project "AllocatorBench"
    language "C++"
    kind "ConsoleApp"
    vpaths
    {
        ["*"] = "premake5.lua"
    }

    if _OPTIONS["use-stl"] then
      includedirs
      {
          ".",
          "../../",
          "../../vendor/lz4/lib",
      }

      links
      {
          "zetanet",
          "lz4",
      }

      filter("system:linux")
        links({ "pthread", "crypto", "ssl" })
      filter("system:macosx")
        links({ "crypto", "ssl" })
      filter({})
    else
      includedirs
      {
          ".",
          "../../",
          "../../vendor/equilibrium",
          "../../vendor/fmtlib/include",
          "../../vendor/lz4/lib",
      }

      links
      {
          "zetanet",
          "base",
          "fmtlib",
          "lz4",
      }
    end

    files
    {
        "premake5.lua",
        "**.h",
        "**.cc",
        "**.rc"
    }
