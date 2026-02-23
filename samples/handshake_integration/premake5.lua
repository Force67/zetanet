project "HandshakeIntegration"
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

    apply_znet_crypto_links()

    files
    {
        "premake5.lua",
        "**.h",
        "**.cc",
        "**.rc"
    }
