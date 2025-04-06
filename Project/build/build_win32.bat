@REM Build for Visual Studio compiler. Run your copy of vcvars32.bat or vcvarsall.bat to setup command-line compiler.
@set OUT_DIR=Debug
@set OUT_EXE=PasswordManagerGUI
@set INCLUDES=/I..\.. /I..\..\ImGUI /I..\..\ImGUI\backends /I..\libs\glfw\include  /I..\..\json\include /I..\..\TDOM-EncryptOrDecryptFile-Reborn\include
@set SOURCES=source_code/main.cpp source_code/core/application_functional.cpp ..\..\ImGUI\backends\imgui_impl_glfw.cpp ..\..\ImGUI\backends\imgui_impl_opengl3.cpp ..\..\ImGUI\imgui*.cpp ..\..\ImGuiFileDialog\ImGuiFileDialog.cpp
@set LIBS=/LIBPATH:..\libs\glfw\lib-vc2010-64 glfw3.lib opengl32.lib gdi32.lib shell32.lib
mkdir %OUT_DIR%
cl /nologo /Zi /MD /utf-8 /std:c++20 /Zc:__cplusplus /experimental:preprocessor /permissive- /EHsc %INCLUDES% %SOURCES% /Fe%OUT_DIR%/%OUT_EXE%.exe /Fo%OUT_DIR%/ /link %LIBS%
