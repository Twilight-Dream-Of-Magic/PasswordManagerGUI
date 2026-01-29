# Minimum required version of CMake
cmake_minimum_required(VERSION 3.26)

# Project name and languages
project(PasswordManagerGUI LANGUAGES CXX)

# -----------------------------------------
# Specify the main entry point separately
# -----------------------------------------
set(MAIN_SOURCE "${CMAKE_CURRENT_SOURCE_DIR}/source_code/main.cpp")

# -----------------------------------------
# Recursively collect project source files
# -----------------------------------------
function(escape_cmake_glob_path output_variable input_path)
	string(REPLACE "\\" "/" escaped_path "${input_path}")
	string(REPLACE "[" "[[]" escaped_path "${escaped_path}")
	set(${output_variable} "${escaped_path}" PARENT_SCOPE)
endfunction()

escape_cmake_glob_path(PROJECT_SOURCE_GLOB_ROOT "${CMAKE_CURRENT_SOURCE_DIR}")
file(GLOB_RECURSE PROJECT_SOURCE_FILES CONFIGURE_DEPENDS
	"${PROJECT_SOURCE_GLOB_ROOT}/source_code/*.h"
	"${PROJECT_SOURCE_GLOB_ROOT}/source_code/*.hpp"
	"${PROJECT_SOURCE_GLOB_ROOT}/source_code/*.inl"
	"${PROJECT_SOURCE_GLOB_ROOT}/source_code/*.cpp"
)

# Remove main.cpp if it was also collected in the glob.
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

# Require C++20 on the actual target. CMAKE_CXX_STANDARD only initializes
# targets created after it is set, so keep this target property explicit.
set_target_properties(PasswordManagerGUI PROPERTIES
	CXX_STANDARD 20
	CXX_STANDARD_REQUIRED ON
	CXX_EXTENSIONS OFF
)

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

# Set C++20 defaults for any future targets
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# -------------------------------
# Compiler options
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
elseif(MSVC)
	target_compile_options(PasswordManagerGUI PRIVATE
		/utf-8
		/bigobj
		/W4
		/wd4146
		/Zc:__cplusplus
		/Zc:preprocessor
		/permissive-
		/EHsc
	)
	target_compile_definitions(PasswordManagerGUI PRIVATE
		_CRT_SECURE_NO_WARNINGS
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
# Windows-specific linking configuration
# -----------------------------------------
if(WIN32)
	# Set the root path for the GLFW library.
	set(GLFW_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/libs/glfw)

	if(MSVC)
		# Choose the bundled MSVC GLFW library based on the target architecture.
		if(CMAKE_SIZEOF_VOID_P EQUAL 8)
			set(GLFW_LIBRARY ${GLFW_ROOT}/lib-vc2010-64/glfw3.lib)
		elseif(CMAKE_SIZEOF_VOID_P EQUAL 4)
			set(GLFW_LIBRARY ${GLFW_ROOT}/lib-vc2010-32/glfw3.lib)
		else()
			message(FATAL_ERROR "Unknown pointer size detected!")
		endif()

		if(NOT EXISTS "${GLFW_LIBRARY}")
			message(FATAL_ERROR "Bundled MSVC GLFW library not found: ${GLFW_LIBRARY}")
		endif()

		message(STATUS "Using MSVC compiler on Windows. Pointer size: ${CMAKE_SIZEOF_VOID_P}")

		target_link_libraries(PasswordManagerGUI PRIVATE
			${GLFW_LIBRARY}
			opengl32
			gdi32
			shell32
			user32
		)
	elseif(MINGW)
		find_library(GLFW_LIBRARY
			NAMES glfw3 libglfw3
			PATHS
				"${GLFW_ROOT}/lib-mingw-w64"
				"${GLFW_ROOT}/lib-mingw"
				"${GLFW_ROOT}/lib"
			NO_DEFAULT_PATH
		)

		if(NOT GLFW_LIBRARY)
			message(FATAL_ERROR "MinGW build requires a MinGW-compatible GLFW library under ${GLFW_ROOT}.")
		endif()

		message(STATUS "Using MinGW compiler on Windows. Pointer size: ${CMAKE_SIZEOF_VOID_P}")

		target_link_libraries(PasswordManagerGUI PRIVATE
			${GLFW_LIBRARY}
			opengl32
			gdi32
			shell32
			user32
		)
	else()
		message(FATAL_ERROR "Unsupported Windows compiler. Use MSVC or MinGW.")
	endif()
endif()
