# Minimum required version of CMake
cmake_minimum_required(VERSION 3.26)

# Project name and settings
project(PasswordManagerGUI LANGUAGES CXX)

# Set C standard to C17
set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# Set C++ standard to C++20
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Recursively collect all source and header files under source_code/
file(GLOB_RECURSE PROJECT_SOURCE_FILES CONFIGURE_DEPENDS
    ${CMAKE_CURRENT_SOURCE_DIR}/source_code/*.h
    ${CMAKE_CURRENT_SOURCE_DIR}/source_code/*.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/source_code/*.inl
    ${CMAKE_CURRENT_SOURCE_DIR}/source_code/*.cpp
)

# Manually list external source files (libraries, 3rd-party dependencies)
set(IMGUI_PATH ${CMAKE_CURRENT_SOURCE_DIR}/../ImGUI)
set(EXTERNAL_SOURCES
    ${IMGUI_PATH}/imgui.cpp
    ${IMGUI_PATH}/imgui_demo.cpp
    ${IMGUI_PATH}/imgui_draw.cpp
    ${IMGUI_PATH}/imgui_tables.cpp
    ${IMGUI_PATH}/imgui_widgets.cpp
    ${IMGUI_PATH}/backends/imgui_impl_glfw.cpp
    ${IMGUI_PATH}/backends/imgui_impl_opengl3.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../ImGuiFileDialog/ImGuiFileDialog.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../ImGuiFileDialog/ImGuiFileDialogConfig.h
)

# Combine all sources
set(SOURCES ${PROJECT_SOURCE_FILES} ${EXTERNAL_SOURCES})

# Define the executable
add_executable(PasswordManagerGUI ${SOURCES})

# Include directories (headers from libraries)
target_include_directories(PasswordManagerGUI PRIVATE
    ${IMGUI_PATH}
    ${IMGUI_PATH}/backends
    ${CMAKE_CURRENT_SOURCE_DIR}/../json/include
    ${CMAKE_CURRENT_SOURCE_DIR}/libs/glfw/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../ImGuiFileDialog
    ${CMAKE_CURRENT_SOURCE_DIR}/../TDOM-EncryptOrDecryptFile-Reborn/include
)

# Platform-specific settings
if(MSVC)
    # Set PasswordManagerGUI as the startup project in Visual Studio
    set_property(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} PROPERTY VS_STARTUP_PROJECT PasswordManagerGUI)
    
    # Add other MSVC-specific options
    target_compile_options(PasswordManagerGUI PRIVATE
        /utf-8
        /Zc:__cplusplus
        /Zc:preprocessor
        /permissive-
        /EHsc
    )

    # Set GLFW static library path
    set(GLFW_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/libs/glfw)
    set(GLFW_LIBRARY ${GLFW_ROOT}/lib-vc2010-64/glfw3.lib)

    # Link Windows-specific libraries
    target_link_libraries(PasswordManagerGUI PRIVATE
        ${GLFW_LIBRARY}
        opengl32
        gdi32
        shell32
        imm32
    )

    # Set up Visual Studio source filters (folders in Visual Studio)
    foreach(file IN LISTS PROJECT_SOURCE_FILES)
        get_filename_component(dir "${file}" DIRECTORY)
        file(RELATIVE_PATH rel_dir "${CMAKE_CURRENT_SOURCE_DIR}" "${dir}")
        string(REPLACE "/" "\\" filter "${rel_dir}")
        source_group("${filter}" FILES "${file}")
    endforeach()

    foreach(file IN LISTS EXTERNAL_SOURCES)
        get_filename_component(dir "${file}" DIRECTORY)
        file(RELATIVE_PATH rel_dir "${CMAKE_CURRENT_SOURCE_DIR}/../.." "${dir}")
        string(REPLACE "/" "\\" filter "ThirdParty\\${rel_dir}")
        source_group("${filter}" FILES "${file}")
    endforeach()

else()
    find_package(OpenGL REQUIRED)
    
    # Basic compile options
    target_compile_options(PasswordManagerGUI PRIVATE
        -g
        -Wall
        -Wformat
    )

    # macOS or Linux-specific linking
    if(APPLE)
        find_package(glfw3 REQUIRED)
        target_link_libraries(PasswordManagerGUI PRIVATE
            OpenGL
            glfw
            "-framework Cocoa"
            "-framework IOKit"
            "-framework CoreVideo"
        )
    elseif(UNIX)
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
