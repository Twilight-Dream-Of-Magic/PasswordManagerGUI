# CMake minimum version required
cmake_minimum_required(VERSION 3.26)

# Project name and settings
project(PasswordManagerGUI)

# Set C++ standard to C++20
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Define source files
set(SOURCES
    source_code/application_functional.cpp
    source_code/main.cpp
    ../../ImGUI/imgui.cpp
    ../../ImGUI/imgui_demo.cpp
    ../../ImGUI/imgui_draw.cpp
    ../../ImGUI/imgui_tables.cpp
    ../../ImGUI/imgui_widgets.cpp
    ../../ImGUI/backends/imgui_impl_glfw.cpp
    ../../ImGUI/backends/imgui_impl_opengl3.cpp
    ../../ImGuiFileDialog/ImGuiFileDialog.cpp
)

# Define the executable output name
add_executable(PasswordManagerGUI ${SOURCES})

# Include directories
target_include_directories(PasswordManagerGUI PRIVATE
    ../../json/include
    ../../TDOM-EncryptOrDecryptFile-Reborn/include
    ../../ImGUI
    ../../ImGUI/backends
    ../../libs/glfw/include
)

# Define libraries to link with (for Windows and other platforms)
if(MSVC)
    # For Visual Studio (Windows)
    target_link_libraries(PasswordManagerGUI PRIVATE
        glfw3
        opengl32
        gdi32
        shell32
        imm32
    )
else()
    # For other platforms
    if(APPLE)
        # For macOS
        target_link_libraries(PasswordManagerGUI PRIVATE
            OpenGL
            Cocoa
            IOKit
            CoreVideo
            glfw
        )
    elseif(UNIX)
        # For Linux
        find_package(PkgConfig REQUIRED)
        pkg_check_modules(GLFW3 REQUIRED glfw3)
        target_include_directories(PasswordManagerGUI PRIVATE ${GLFW3_INCLUDE_DIRS})
        target_link_libraries(PasswordManagerGUI PRIVATE
            ${GLFW3_LIBRARIES}
            ${GLFW3_STATIC_LIBRARIES}
            OpenGL
        )
    endif()
endif()

# Additional flags for all platforms
target_compile_options(PasswordManagerGUI PRIVATE
    -g
    -Wall
    -Wformat
)

# Ensure that CMake can find GLFW and OpenGL
find_package(OpenGL REQUIRED)

# Set up clean command
add_custom_target(clean COMMAND ${CMAKE_COMMAND} -P ${CMAKE_BINARY_DIR}/cmake_clean.cmake)