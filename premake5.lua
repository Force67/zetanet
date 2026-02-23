-- Copyright (C) 2026 Vincent Hengel.
-- For licensing information see LICENSE at the root of this distribution.
require("premake", ">=5.0-beta3")

-- Option to compile without equilibrium, using STL only
newoption {
  trigger = "use-stl",
  description = "Build without equilibrium submodule, using STL replacements"
}

newoption {
  trigger = "crypto-backend",
  value = "BACKEND",
  description = "Select crypto backend: openssl (default) or mbedtls",
  allowed = {
    { "openssl", "Use OpenSSL" },
    { "mbedtls", "Use mbedTLS" },
  }
}

newoption {
  trigger = "use-system-openssl",
  description = "Use system OpenSSL (optionally via pkg-config) instead of default linker assumptions"
}

newoption {
  trigger = "openssl-include-dir",
  value = "PATH",
  description = "Override OpenSSL include directory when using --use-system-openssl"
}

newoption {
  trigger = "openssl-lib-dir",
  value = "PATH",
  description = "Override OpenSSL library directory when using --use-system-openssl"
}

newoption {
  trigger = "openssl-crypto-lib",
  value = "NAME",
  description = "Override crypto library name (default: crypto)"
}

newoption {
  trigger = "openssl-ssl-lib",
  value = "NAME",
  description = "Override ssl library name (default: ssl)"
}

newoption {
  trigger = "use-system-mbedtls",
  description = "Use system mbedTLS (optionally via pkg-config) instead of default linker assumptions"
}

newoption {
  trigger = "mbedtls-include-dir",
  value = "PATH",
  description = "Override mbedTLS include directory when using --use-system-mbedtls"
}

newoption {
  trigger = "mbedtls-lib-dir",
  value = "PATH",
  description = "Override mbedTLS library directory when using --use-system-mbedtls"
}

newoption {
  trigger = "mbedtls-lib",
  value = "NAME",
  description = "Override mbedTLS TLS library name (default: mbedtls)"
}

newoption {
  trigger = "mbedx509-lib",
  value = "NAME",
  description = "Override mbedTLS X509 library name (default: mbedx509)"
}

newoption {
  trigger = "mbedcrypto-lib",
  value = "NAME",
  description = "Override mbedTLS crypto library name (default: mbedcrypto)"
}

local function split_words(text)
  local out = {}
  if not text then
    return out
  end
  for word in text:gmatch("%S+") do
    table.insert(out, word)
  end
  return out
end

local function apply_pkg_config_flags(cflags, libs)
  local linked_any = false
  for _, flag in ipairs(split_words(cflags)) do
    if flag:sub(1, 2) == "-I" and #flag > 2 then
      includedirs({ flag:sub(3) })
    elseif flag:sub(1, 2) == "-D" and #flag > 2 then
      defines({ flag:sub(3) })
    elseif #flag > 0 then
      buildoptions({ flag })
    end
  end

  for _, flag in ipairs(split_words(libs)) do
    if flag:sub(1, 2) == "-L" and #flag > 2 then
      libdirs({ flag:sub(3) })
    elseif flag:sub(1, 2) == "-l" and #flag > 2 then
      links({ flag:sub(3) })
      linked_any = true
    elseif #flag > 0 then
      linkoptions({ flag })
    end
  end
  return linked_any
end

function apply_znet_crypto_links()
  local crypto_backend = _OPTIONS["crypto-backend"] or "openssl"
  local openssl_crypto_lib = _OPTIONS["openssl-crypto-lib"] or "crypto"
  local openssl_ssl_lib = _OPTIONS["openssl-ssl-lib"] or "ssl"
  local mbedtls_lib = _OPTIONS["mbedtls-lib"] or "mbedtls"
  local mbedx509_lib = _OPTIONS["mbedx509-lib"] or "mbedx509"
  local mbedcrypto_lib = _OPTIONS["mbedcrypto-lib"] or "mbedcrypto"
  local target = os.target()

  if crypto_backend ~= "openssl" and crypto_backend ~= "mbedtls" then
    print("Error: --crypto-backend must be one of: openssl, mbedtls")
    os.exit(1)
  end

  if crypto_backend == "mbedtls" then
    defines({ "ZNET_CRYPTO_BACKEND_MBEDTLS" })
  else
    defines({ "ZNET_CRYPTO_BACKEND_OPENSSL" })
  end

  if target == "windows" then
    if crypto_backend == "openssl" and _OPTIONS["use-system-openssl"] then
      if _OPTIONS["openssl-include-dir"] then
        includedirs({ _OPTIONS["openssl-include-dir"] })
      end
      if _OPTIONS["openssl-lib-dir"] then
        libdirs({ _OPTIONS["openssl-lib-dir"] })
      end
      links({ openssl_crypto_lib, openssl_ssl_lib, "Crypt32" })
    end
    if crypto_backend == "mbedtls" and _OPTIONS["use-system-mbedtls"] then
      if _OPTIONS["mbedtls-include-dir"] then
        includedirs({ _OPTIONS["mbedtls-include-dir"] })
      end
      if _OPTIONS["mbedtls-lib-dir"] then
        libdirs({ _OPTIONS["mbedtls-lib-dir"] })
      end
      links({ mbedtls_lib, mbedx509_lib, mbedcrypto_lib, "Crypt32" })
    end
    filter({})
    return
  end

  filter("system:linux")
    links({ "pthread" })
  filter({})

  if crypto_backend == "openssl" then
    if _OPTIONS["use-system-openssl"] then
      local openssl_cflags = os.outputof("pkg-config --cflags openssl 2>/dev/null")
      local openssl_libs = os.outputof("pkg-config --libs openssl 2>/dev/null")
      local used_pkg_config = false

      if openssl_libs and openssl_libs:match("%S") then
        used_pkg_config = apply_pkg_config_flags(openssl_cflags, openssl_libs)
      end

      if not used_pkg_config then
        if _OPTIONS["openssl-include-dir"] then
          includedirs({ _OPTIONS["openssl-include-dir"] })
        end
        if _OPTIONS["openssl-lib-dir"] then
          libdirs({ _OPTIONS["openssl-lib-dir"] })
        end
        links({ openssl_crypto_lib, openssl_ssl_lib })
      end
    else
      links({ openssl_crypto_lib, openssl_ssl_lib })
    end
  else
    if _OPTIONS["use-system-mbedtls"] then
      local mbedtls_cflags = os.outputof("pkg-config --cflags mbedtls 2>/dev/null")
      local mbedtls_libs = os.outputof("pkg-config --libs mbedtls 2>/dev/null")
      local used_pkg_config = false

      if mbedtls_libs and mbedtls_libs:match("%S") then
        used_pkg_config = apply_pkg_config_flags(mbedtls_cflags, mbedtls_libs)
      end

      if not used_pkg_config then
        if _OPTIONS["mbedtls-include-dir"] then
          includedirs({ _OPTIONS["mbedtls-include-dir"] })
        end
        if _OPTIONS["mbedtls-lib-dir"] then
          libdirs({ _OPTIONS["mbedtls-lib-dir"] })
        end
      end
    end
    links({ mbedtls_lib, mbedx509_lib, mbedcrypto_lib })
  end
  filter({})
end

local host_arch = (os.outputof("uname -m 2>/dev/null") or ""):lower()
if host_arch:find("aarch64", 1, true) or host_arch:find("arm64", 1, true) then
  architecture("ARM64")
else
  architecture("x86_64")
end

filter("architecture:x86_64")
    targetsuffix("_64")
filter("architecture:ARM64")
    targetsuffix("_64")

filter("configurations:Debug")
    defines("TK_DBG")
    optimize("Off")
    symbols("On")

filter("configurations:Release")
    runtime("Release")
    optimize("Speed")

filter({ "language:C or C++", "architecture:x86_64" })
    vectorextensions("SSE4.1")
    staticruntime("on")
filter({ "language:C or C++", "architecture:ARM64" })
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
