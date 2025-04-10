@echo off
rem ========================================================
rem Auto-detect Visual Studio, set up environment, and run CMake
rem ========================================================

rem Switch to OEM code page (437) to avoid Unicode issues.
chcp 437 >nul

echo Searching for Visual Studio installation using vswhere...
for /f "delims=" %%i in (
    '"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath'
) do set VSPATH=%%i

if not defined VSPATH (
    echo Could not find a Visual Studio installation!
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

rem Convert backslashes to forward slashes in the cl.exe path
set "CLPATH=%CLPATH:\=/%"
echo Converted cl.exe path: %CLPATH%

rem Check if the "build" directory exists; if not, create it.
if not exist "build" (
    echo Creating build directory...
    mkdir build
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
cmake -G "Visual Studio 17 2022" -DCMAKE_CXX_COMPILER="%CLPATH%" -DCMAKE_CXX_FLAGS="/Zc:__cplusplus /utf-8 /bigobj /W4 /wd4146 /D_CRT_SECURE_NO_WARNINGS /Zc:preprocessor /std:c++20 /permissive- /EHsc" -S ./ -B ./build

::if errorlevel 1 (
::    echo CMake configuration failed. Please review the error messages above.
::)

echo Project generated successfully. The solution is in the "build" directory.

:::Restore
rem ========================================================
rem Restore Original CMakeLists.txt if a backup exists, else remove the temporary backup file.
rem ========================================================
::echo Restoring original CMakeLists.txt...
::move /Y CMakeLists.txt.backup CMakeLists.txt
::echo Removing temporary backup  CMakeLists.txt...
::del /q CMakeLists.txt.backup

pause