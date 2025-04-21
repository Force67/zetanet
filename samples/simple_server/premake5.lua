project "SimpleServer"
    language "C++"
    kind "ConsoleApp"
    vpaths
    {
        ["*"] = "premake5.lua"
    }

    includedirs
    {
        ".",
        "../../../",
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


    files
    {
        "premake5.lua",
        "**.h",
        "**.cc",
        "**.rc"
    }