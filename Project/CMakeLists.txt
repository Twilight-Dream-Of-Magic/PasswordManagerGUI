# Minimum required version of CMake
cmake_minimum_required(VERSION 3.26)

# Project name and languages
project(PasswordManagerGUI LANGUAGES CXX)

# -----------------------------------------
# Specify the main entry point separately
# -----------------------------------------
set(MAIN_SOURCE "${CMAKE_CURRENT_SOURCE_DIR}/source_code/main.cpp")

# -----------------------------------------
# Recursively collect other source files
# -----------------------------------------
file(GLOB_RECURSE PROJECT_SOURCE_FILES CONFIGURE_DEPENDS
	"${CMAKE_CURRENT_SOURCE_DIR}/source_code/*.h"
	"${CMAKE_CURRENT_SOURCE_DIR}/source_code/*.hpp"
	"${CMAKE_CURRENT_SOURCE_DIR}/source_code/*.inl"
	"${CMAKE_CURRENT_SOURCE_DIR}/source_code/*.cpp"
)

# Remove main.cpp if it was also collected in the glob
list(REMOVE_ITEM PROJECT_SOURCE_FILES "${MAIN_SOURCE}")

# -----------------------------------------
# Add external third-party dependency source files
# -----------------------------------------
set(IMGUI_PATH "${CMAKE_CURRENT_SOURCE_DIR}/../ImGUI")
set(EXTERNAL_SOURCES
	"${IMGUI_PATH}/imgui.cpp"
	"${IMGUI_PATH}/imgui_demo.cpp"
	"${IMGUI_PATH}/imgui_draw.cpp"
	"${IMGUI_PATH}/imgui_tables.cpp"
	"${IMGUI_PATH}/imgui_widgets.cpp"
	"${IMGUI_PATH}/backends/imgui_impl_glfw.cpp"
	"${IMGUI_PATH}/backends/imgui_impl_opengl3.cpp"
	"${CMAKE_CURRENT_SOURCE_DIR}/../ImGuiFileDialog/ImGuiFileDialog.cpp"
	"${CMAKE_CURRENT_SOURCE_DIR}/../ImGuiFileDialog/ImGuiFileDialogConfig.h"
)

# Merge all source files and include the main.cpp explicitly
set(SOURCES ${MAIN_SOURCE} ${PROJECT_SOURCE_FILES} ${EXTERNAL_SOURCES})

# Define the executable target
add_executable(PasswordManagerGUI ${SOURCES})

# -----------------------------------------
# Add include directories for headers
# -----------------------------------------
target_include_directories(PasswordManagerGUI PRIVATE
	"${IMGUI_PATH}"
	"${IMGUI_PATH}/backends"
	"${CMAKE_CURRENT_SOURCE_DIR}/../json/include"
	"${CMAKE_CURRENT_SOURCE_DIR}/libs/glfw/include"
	"${CMAKE_CURRENT_SOURCE_DIR}/../ImGuiFileDialog"
	"${CMAKE_CURRENT_SOURCE_DIR}/../TDOM-EncryptOrDecryptFile-Reborn/include"
)

# Set C++20 standard and related options
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# -------------------------------
# Compiler options for GNU/Clang
# -------------------------------
if(CMAKE_COMPILER_IS_GNUCC OR CMAKE_COMPILER_IS_GNUCXX)
	target_compile_options(PasswordManagerGUI PRIVATE
		-g
		-Wall
		-Wformat
	)
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
	target_compile_options(PasswordManagerGUI PRIVATE
		-g
		-Wall
		-Wformat=2
	)
endif()

# -----------------------------------------
# Find OpenGL package (common for all platforms)
# -----------------------------------------
find_package(OpenGL REQUIRED)

# -----------------------------------------
# Platform-specific linking configuration
# -----------------------------------------
if(APPLE)
	find_package(glfw3 REQUIRED)
	target_link_libraries(PasswordManagerGUI PRIVATE
		OpenGL::GL
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
		OpenGL::GL
	)
endif()

# -----------------------------------------
# Windows-specific configuration for Mingw Makefiles (Mingw Only)
# -----------------------------------------
if(WIN32)
	# Ensure that we are using the Mingw compiler only.
	if(NOT CMAKE_C_COMPILER MATCHES "mingw")
		message(FATAL_ERROR "This project must be compiled with the Mingw compiler.")
	endif()

	# Set the root path for the GLFW library.
	set(GLFW_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/libs/glfw)

	# Choose the correct GLFW library based on the architecture.
	if(CMAKE_SIZEOF_VOID_P EQUAL 8)
		# 64-bit platform
		set(GLFW_LIBRARY ${GLFW_ROOT}/lib-vc2010-64/glfw3.lib)
	elseif(CMAKE_SIZEOF_VOID_P EQUAL 4)
		# 32-bit platform
		set(GLFW_LIBRARY ${GLFW_ROOT}/lib-vc2010-32/glfw3.lib)
	else()
		message(FATAL_ERROR "Unknown pointer size detected!")
	endif()

	message(STATUS "Using Mingw compiler on Windows. Pointer size: ${CMAKE_SIZEOF_VOID_P}")

	# Link Windows-specific libraries.
	target_link_libraries(PasswordManagerGUI PRIVATE
		${GLFW_LIBRARY}
		opengl32
	)
endif()
