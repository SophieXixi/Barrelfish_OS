--------------------------------------------------------------------------
-- Copyright (c) 2007-2010, ETH Zurich.
-- All rights reserved.
--
-- This file is distributed under the terms in the attached LICENSE file.
-- If you do not find this file, copies can be found by writing to:
-- ETH Zurich D-INFK, Universitaetstasse 6, CH-8092 Zurich. Attn: Systems Group.
--
-- Default architecture-specific definitions for Barrelfish
--
--------------------------------------------------------------------------

module ArchDefaults where

import Data.List
import HakeTypes
import System.FilePath
import qualified Config

commonFlags = [ Str s | s <- [ "-fno-builtin",
                                "-nostdinc",
                                "-U__linux__",
                                "-Ulinux",
                                "-Wall",
                                "-Wextra",
                                "-Wshadow",
                                "-Wunused",
                                "-Wmissing-declarations",
                                "-Wmissing-field-initializers",
                                "-Wtype-limits",
                                "-Wredundant-decls",
                                "-Werror" ] ]

commonCFlags = [ Str s | s <- [ "-std=c99",
                                "-Wstrict-prototypes",
                                "-Wold-style-definition",
                                "-Wmissing-prototypes" ] ]
                 ++ [ Str (if Config.use_fp then "-fno-omit-frame-pointer" else "") ]

commonCxxFlags = [ Str s | s <- [ "-nostdinc++",
                                  "-fexceptions",
                                  "-nodefaultlibs",
                                  "-fasynchronous-unwind-tables",
                                  "-DLIBCXX_CXX_ABI=libcxxabi",
                                  "-I" ] ]
                 ++ [ NoDep SrcTree "src" "/include/cxx" ]
                 ++ [ Str (if Config.use_fp then "-fno-omit-frame-pointer" else "") ]

cFlags = [ Str s | s <- [ "-Wno-packed-bitfield-compat" ] ]
       ++ commonCFlags

cxxFlags = [ Str s | s <- [ "-Wno-packed-bitfield-compat" ] ]
       ++ commonCxxFlags

cDefines options = [ Str ("-D"++s) | s <- [ "BARRELFISH",
                                            "BF_BINARY_PREFIX=\\\"\\\""
                                          ]
                   ]
                   ++ Config.defines
                   ++ Config.arch_defines options

cStdIncs arch archFamily =
    [ NoDep BFSrcTree "src" "/include",
      NoDep BFSrcTree "src" ("/include/arch" </> archFamily),
      NoDep BFSrcTree "src" ("/include/target" </> archFamily),
      NoDep InstallTree arch "/include",
      NoDep BFSrcTree "src" ".",
      NoDep SrcTree "src" ".",
      NoDep BuildTree arch "." ]

ldFlags arch =
    map Str Config.cOptFlags ++
    [ In InstallTree arch "/lib/crt0.o",
      In InstallTree arch "/lib/crtbegin.o",
      Str "-fno-builtin",
      Str "-nostdlib" ]

ldCxxFlags arch =
    map Str Config.cOptFlags ++
    [ In InstallTree arch "/lib/crt0.o",
      In InstallTree arch "/lib/crtbegin.o",
      Str "-fno-builtin",
      Str "-nostdlib" ]

kernelLibs arch =
    [ In InstallTree arch "/lib/libcompiler-rt.a" ]

-- Libraries that are linked to all applications.
stdLibDeps =
  [
    "aos",
    "c",
    "compiler-rt",
    "errno",
    "collections"
  ]

stdCxxLibDeps = ["cxx"] ++ stdLibDeps

stdLibs arch =
    -- Library OS now added in appGetOptionsForArch based on options field 'libraryOs'.
    -- Archive files should be added to stdLibDeps.
    [ In InstallTree arch "/lib/crtend.o" ]

stdCxxLibs arch =
    [ ]
    ++ stdLibs arch

options arch archFamily = Options {
            optArch = arch,
            optArchFamily = archFamily,
            optFlags = cFlags,
            optCxxFlags = cxxFlags,
            optDefines = [ Str "-DBARRELFISH" ] ++ Config.defines,
            optIncludes = cStdIncs arch archFamily,
            optDependencies =
                [ Dep InstallTree arch "/include/errors/errno.h",
                  Dep InstallTree arch "/include/barrelfish_kpi/capbits.h",
                  Dep InstallTree arch "/include/asmoffsets.h",
                  Dep InstallTree arch "/include/trace_definitions/trace_defs.h" ],
            optLdFlags = ldFlags arch,
            optLdCxxFlags = ldCxxFlags arch,
            optLibDep = stdLibDeps,
            optLibs = stdLibs arch,
            optCxxLibDep = stdCxxLibDeps,
            optCxxLibs = stdCxxLibs arch,
            optInterconnectDrivers = ["lmp", "ump", "multihop", "local"],
            optFlounderBackends = ["lmp", "ump", "multihop", "local"],
            extraFlags = [],
            extraCxxFlags = [],
            extraDefines = [],
            extraIncludes = [],
            extraDependencies = [],
            extraLdFlags = [],
            optSuffix = [],
            optInstallPath = OptionsPath {
                optPathBin = "/sbin",
                optPathLib = "/lib"
            }
          }

------------------------------------------------------------------------
--
-- Now, commands to actually do something
--
------------------------------------------------------------------------

--
-- C compiler
--
cCompiler :: String -> String -> [String] -> Options -> String ->
             String -> String -> [RuleToken]
cCompiler arch compiler opt_flags opts phase src obj =
    let incls = (extraIncludes opts) ++ (optIncludes opts)
        flags = (optFlags opts)
                ++ (optDefines opts)
                ++ [ Str f | f <- extraFlags opts ]
                ++ [ Str f | f <- extraDefines opts ]
        deps = (optDependencies opts) ++ (extraDependencies opts)
    in
      [ Str compiler ] ++ flags ++ (map Str opt_flags)
      ++ concat [ [ NStr "-I", i ] | i <- incls ]
      ++ [ Str "-o", Out arch obj,
           Str "-c", In (if phase == "src" then SrcTree else BuildTree) phase src ]
      ++ deps

--
-- the C preprocessor, like C compiler but with -E
--
cPreprocessor :: String -> String -> [String] -> Options -> String ->
                 String -> String -> [RuleToken]
cPreprocessor arch compiler opt_flags opts phase src obj =
    let incls = (extraIncludes opts) ++ (optIncludes opts)
        flags = (optFlags opts)
                ++ (optDefines opts)
                ++ [ Str f | f <- extraFlags opts ]
                ++ [ Str f | f <- extraDefines opts ]
        deps = (optDependencies opts) ++ (extraDependencies opts)
        cOptFlags = opt_flags \\ ["-g"]
    in
      [ Str compiler ] ++ flags ++ (map Str cOptFlags)
      ++ concat [ [ NStr "-I", i ] | i <- incls ]
      ++ [ Str "-o", Out arch obj,
           Str "-E", In (if phase == "src" then SrcTree else BuildTree) phase src ]
      ++ deps

--
-- C++ compiler
--
cxxCompiler arch cxxcompiler opt_flags opts phase src obj =
    let incls = (extraIncludes opts) ++ (optIncludes opts)
        flags = (optCxxFlags opts)
                ++ (optDefines opts)
                ++ [ Str f | f <- extraCxxFlags opts ]
                ++ [ Str f | f <- extraDefines opts ]
        deps = (optDependencies opts) ++ (extraDependencies opts)
    in
      [ Str cxxcompiler ] ++ flags ++ (map Str opt_flags)
      ++ concat [ [ NStr "-I", i ] | i <- incls ]
      ++ [ Str "-o", Out arch obj,
           Str "-c", In (if phase == "src" then SrcTree else BuildTree) phase src ]
      ++ deps

--
-- Create C file dependencies
--
makeDepend arch compiler opts phase src obj depfile =
    let incls = (extraIncludes opts) ++ (optIncludes opts)
        flags = (optFlags opts)
                ++ (optDefines opts)
                ++ [ Str f | f <- extraFlags opts ]
                ++ [ Str f | f <- extraDefines opts ]
    in
      [ Str ('@':compiler) ] ++ flags
      ++ concat [ [ NStr "-I", i ] | i <- incls ]
      ++ (optDependencies opts) ++ (extraDependencies opts)
      ++ [ Str "-M -MF",
           Out arch depfile,
           Str "-MQ", NoDep BuildTree arch obj,
           Str "-MQ", NoDep BuildTree arch depfile,
           Str "-c", In (if phase == "src" then SrcTree else BuildTree) phase src
         ]

--
-- Create C++ file dependencies
--
makeCxxDepend arch cxxcompiler opts phase src obj depfile =
    let incls = (extraIncludes opts) ++ (optIncludes opts)
        flags = (optCxxFlags opts)
                ++ (optDefines opts)
                ++ [ Str f | f <- extraCxxFlags opts ]
                ++ [ Str f | f <- extraDefines opts ]
    in
      [ Str ('@':cxxcompiler) ] ++ flags
      ++ concat [ [ NStr "-I", i ] | i <- incls ]
      ++ (optDependencies opts) ++ (extraDependencies opts)
      ++ [ Str "-M -MF",
           Out arch depfile,
           Str "-MQ", NoDep BuildTree arch obj,
           Str "-MQ", NoDep BuildTree arch depfile,
           Str "-c", In (if phase == "src" then SrcTree else BuildTree) phase src
         ]

--
-- Compile a C program to assembler
--
cToAssembler :: String -> String -> [String] -> Options -> String -> String ->
                String -> String -> [ RuleToken ]
cToAssembler arch compiler opt_flags opts phase src afile objdepfile =
    let incls = (extraIncludes opts) ++ (optIncludes opts)
        flags = (optFlags opts)
                ++ (optDefines opts)
                ++ [ Str f | f <- extraFlags opts ]
                ++ [ Str f | f <- extraDefines opts ]
        deps = [ Dep BuildTree arch objdepfile ] ++
               (optDependencies opts) ++
               (extraDependencies opts)
    in
      [ Str compiler ] ++ flags ++ (map Str opt_flags)
      ++ concat [ [ NStr "-I", i ] | i <- incls ]
      ++ [ Str "-o ", Out arch afile,
           Str "-S ", In (if phase == "src" then SrcTree else BuildTree) phase src ]
      ++ deps

--
-- Assemble an assembly language file
--
assembler :: String -> String -> [ String ] -> Options -> String ->
             String -> [ RuleToken ]
assembler arch compiler opt_flags opts src obj =
    let incls = (extraIncludes opts) ++ (optIncludes opts)
        flags = (optFlags opts)
                ++ (optDefines opts)
                ++ [ Str f | f <- extraFlags opts ]
                ++ [ Str f | f <- extraDefines opts ]
        deps = (optDependencies opts) ++ (extraDependencies opts)
    in
      [ Str compiler ] ++ flags ++ (map Str opt_flags)
      ++ concat [ [ NStr "-I", i ] | i <- incls ]
      ++ [ Str "-o ", Out arch obj, Str "-c ", In SrcTree "src" src ]
      ++ deps

--
-- Create a library from a set of object files
--
archive :: String -> String -> Options -> [String] -> [String] -> String -> String -> [ RuleToken ]
archive arch ar opts objs libs name libname =
    [ Str "rm -f ", Out arch libname ]
    ++
    [ NL, Str ar, Str " crT ", Out arch libname ]
    ++
    [ In BuildTree arch o | o <- objs ]
    ++
    if libs == [] then []
                  else [ In BuildTree arch a | a <- libs ]
    ++
    [ NL, Str "ranlib ", Out arch libname ]

--
-- Link an executable, explicitly stating libraries and modules
--
linker :: String -> String -> Options -> [String] -> [String] -> [String] -> String -> [RuleToken]
linker arch compiler opts objs libs mods bin =
    [ Str compiler ]
    ++ (optLdFlags opts)
    ++
    (extraLdFlags opts)
    ++
    [ Str "-o", Out arch bin ]
    ++
    [ In BuildTree arch o | o <- objs ]
    ++
    [Str "-Wl,--start-group"]
    ++
    [ In BuildTree arch l | l <- libs ]
    ++
    [Str "-Wl,--whole-archive"] ++ [ In BuildTree arch l | l <- mods ] ++ [Str "-Wl,--no-whole-archive"]
    ++
    [ In BuildTree arch l | l <- libs ]
    ++
    (optLibs opts)
    ++
    [Str "-Wl,--end-group"]

--
-- Link an executable, libs and mods are not passed, but later resolved
-- using the application name "app" and the library dependency tree
--
ldtLinker :: String -> String -> Options -> [String] -> String -> String -> [RuleToken]
ldtLinker arch compiler opts objs app bin =
    [ Str compiler ]
    ++ (optLdFlags opts)
    ++
    (extraLdFlags opts)
    ++
    [ Str "-o", Out arch bin ]
    ++
    [ In BuildTree arch o | o <- objs ]
    ++
    [Str "-Wl,--start-group"]
    ++
    [ Ldt BuildTree arch app ]
    ++
    (optLibs opts)
    ++
    [Str "-Wl,--end-group"]


--
-- Link an executable
--
cxxlinker :: String -> String -> Options -> [String] -> [String] -> [String] -> String -> [RuleToken]
cxxlinker arch cxxcompiler opts objs libs mods bin =
    [ Str cxxcompiler ]
    ++ (optLdCxxFlags opts)
    ++
    (extraLdFlags opts)
    ++
    [ Str "-o", Out arch bin ]
    ++
    [ In BuildTree arch o | o <- objs ]
    ++
    [ In BuildTree arch l | l <- libs ]
    ++
    [Str "-Wl,--start-group -Wl,--whole-archive"] ++ [ In BuildTree arch l | l <- mods ] ++ [Str "-Wl,--no-whole-archive"]
    ++
    (optCxxLibs opts)
    ++
    [Str "-Wl,--end-group"]


--
-- Link an executable
--
ldtCxxlinker :: String -> String -> Options -> [String] -> String -> String -> [RuleToken]
ldtCxxlinker arch cxxcompiler opts objs app bin =
    [ Str cxxcompiler ]
    ++
    (optLdCxxFlags opts)
    ++
    (extraLdFlags opts)
    ++
    [ Str "-o", Out arch bin ]
    ++
    [ In BuildTree arch o | o <- objs ]
    ++
    [Str "-Wl,--start-group"]
    ++
    [ Ldt BuildTree arch app ]
    ++
    (optCxxLibs opts)
    ++
    [Str "-Wl,--end-group"]


--
-- Strip debug symbols from an executable
--
strip :: String -> String -> Options -> String -> String ->
         String -> [RuleToken]
strip arch objcopy opts src debuglink target =
    [ Str objcopy,
      Str "-g",
      NStr "--add-gnu-debuglink=", In BuildTree arch debuglink,
      In BuildTree arch src,
      Out arch target
    ]

--
-- Extract debug symbols from an executable
--
debug :: String -> String -> Options -> String -> String -> [RuleToken]
debug arch objcopy opts src target =
    [ Str objcopy,
      Str "--only-keep-debug",
      In BuildTree arch src,
      Out arch target
    ]
