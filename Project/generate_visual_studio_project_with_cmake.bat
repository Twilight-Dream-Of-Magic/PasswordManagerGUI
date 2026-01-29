@echo off
rem ========================================================
rem Auto-detect Visual Studio 2022, set up environment, and run CMake
rem ========================================================
setlocal EnableExtensions EnableDelayedExpansion
set BUILD_DIR=build_vs2022_x64

rem Switch to OEM code page (437) to avoid Unicode issues.
chcp 437 >nul

echo Searching for Visual Studio 2022 installation using vswhere...
for /f "delims=" %%i in (
    '"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -all -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath'
) do (
    set "VS_CANDIDATE=%%i"
    if not "!VS_CANDIDATE:2022=!"=="!VS_CANDIDATE!" set "VSPATH=%%i"
)

if not defined VSPATH (
    echo Could not find a Visual Studio 2022 installation!
    pause
    exit /b 1
)

echo Found Visual Studio at: %VSPATH%

rem Construct the path to vcvarsall.bat (assumes standard layout)
set VCVARSALL=%VSPATH%\VC\Auxiliary\Build\vcvarsall.bat

if not exist "%VCVARSALL%" (
    echo vcvarsall.bat not found at: %VCVARSALL%
    echo Please verify that your Visual Studio installation has the C++ workload.
    pause
    exit /b 1
)

echo Using vcvarsall: %VCVARSALL%
rem Call vcvarsall.bat for the x64 environment
call "%VCVARSALL%" x64

rem Reassert the OEM code page in case it was changed by vcvarsall
chcp 437 >nul

rem Use the Visual Studio bundled CMake. A CMake installation under a path
rem containing square brackets can break CMake's own file(GLOB) module lookup.
set "CMAKE_EXE=%VSPATH%\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"
if not exist "%CMAKE_EXE%" (
    echo CMake not found at: %CMAKE_EXE%
    echo Please install the Visual Studio CMake tools component.
    pause
    exit /b 1
)
echo Using CMake: %CMAKE_EXE%

rem Auto-detect the full path of cl.exe from the current environment
for /f "delims=" %%A in ('where cl.exe') do (
    set CLPATH=%%A
    goto GotCL
)
:GotCL
if not defined CLPATH (
    echo cl.exe not found in the PATH.
    pause
    exit /b 1
)
echo Found cl.exe at: %CLPATH%

rem Check if the build directory exists; if not, create it.
if not exist "%BUILD_DIR%" (
    echo Creating build directory...
    mkdir "%BUILD_DIR%"
)

rem ========================================================
rem  Temporary Backup and replace CMakeLists.txt
rem ========================================================

::if exist "CMakeLists.txt" (
::    echo Temporary Backing up original CMakeLists.txt...
::    copy /Y CMakeLists.txt CMakeLists.txt.backup
::) else (
::    echo No existing CMakeLists.txt found.
::    exit /b 1
::)

rem Copy CMakeLists_MSVC.txt to CMakeLists.txt
::if exist "CMakeLists_MSVC.txt" (
::    echo Copying CMakeLists_MSVC.txt to CMakeLists.txt...
::    copy /Y CMakeLists_MSVC.txt CMakeLists.txt
::) else (
::    echo No existing CMakeLists_MSVC.txt found.
::    exit /b 1
::)

rem ========================================================
rem Run CMake with the auto-detected compiler path
rem ========================================================
echo Running CMake...
"%CMAKE_EXE%" -U CMAKE_C_COMPILER -U CMAKE_CXX_COMPILER -U CMAKE_C_FLAGS -U CMAKE_CXX_FLAGS -G "Visual Studio 17 2022" -A x64 -S ./ -B ./%BUILD_DIR%

if errorlevel 1 (
    echo CMake configuration failed. Please review the error messages above.
    pause
    exit /b 1
)

echo Project generated successfully. The solution is in the "%BUILD_DIR%" directory.

:::Restore
rem ========================================================
rem Restore Original CMakeLists.txt if a backup exists, else remove the temporary backup file.
rem ========================================================
::echo Restoring original CMakeLists.txt...
::move /Y CMakeLists.txt.backup CMakeLists.txt
::echo Removing temporary backup  CMakeLists.txt...
::del /q CMakeLists.txt.backup

pause
