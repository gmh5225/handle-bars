@echo off
:: Preparing the environment
if not defined DevEnvDir (
    call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
)
rd /s /q .\out\
cargo clean
mkdir .\out\
mkdir .\target
mkdir .\target\debug

echo [i] Compiling C Sources
cl.exe /c /DNDEBUG /I .\src\c\includes .\src\c\enumhandles.c
if %errorlevel% neq 0 exit /b %errorlevel%

echo [i] Creating Library
lib.exe enumhandles.obj /OUT:.\out\rustydump.lib
if %errorlevel% neq 0 exit /b %errorlevel%

echo [i] Copying library
copy .\out\rustydump.lib .\target\debug\

del enumhandles.obj
echo [i] Compiling Debug Version
cargo build