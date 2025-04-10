#pragma once

#include "imgui.h"
#include "imgui_impl_glfw.h"
#include "imgui_impl_opengl3.h"
#define GL_SILENCE_DEPRECATION
#if defined(IMGUI_IMPL_OPENGL_ES2)
#include <GLES2/gl2.h>
#endif

#include "../ImGuiFileDialog/ImGuiFileDialog.h"
#include <GLFW/glfw3.h> // Will drag system OpenGL headers
// [Win32] Our example includes a copy of glfw3.lib pre-compiled with VS2010 to maximize ease of testing and
// compatibility with old VS compilers. To link with VS2010-era libraries, VS2015+ requires linking with
// legacy_stdio_definitions.lib, which we do using this pragma. Your own project should not be affected, as you are
// likely to link with a newer binary of GLFW that is adequate for your version of Visual Studio.
#if defined(_MSC_VER) && (_MSC_VER >= 1900) && !defined(IMGUI_DISABLE_WIN32_FUNCTIONS)
#pragma comment(lib, "legacy_stdio_definitions")
#endif

#include "../ui/PasswordManagerGUI.hpp"

// init
inline void ImGUI_Inital(ApplicationData &AppData)
{
	static auto glfw_error_callback = [](int error, const char *description) { fprintf(stderr, "GLFW Error %d: %s\n", error, description); };

	glfwSetErrorCallback(glfw_error_callback);

	if (!glfwInit())
	{
		throw std::runtime_error("glfwInit failed");
	}

	// Decide GL+GLSL versions
#if defined(IMGUI_IMPL_OPENGL_ES2)
	// GL ES 2.0 + GLSL 100
	const char *glsl_version = "#version 100";
	glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 2);
	glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 0);
	glfwWindowHint(GLFW_CLIENT_API, GLFW_OPENGL_ES_API);
#elif defined(__APPLE__)
	// GL 3.2 + GLSL 150
	const char *glsl_version = "#version 150";
	glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
	glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 2);
	glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE); // 3.2+ only
	glfwWindowHint(GLFW_OPENGL_FORWARD_COMPAT, GL_TRUE);           // Required on Mac
#else
	// GL 3.0 + GLSL 130
	const char *glsl_version = "#version 130";
	glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
	glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 0);
	// glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);  // 3.2+ only
	// glfwWindowHint(GLFW_OPENGL_FORWARD_COMPAT, GL_TRUE);            // 3.0+ only
#endif

	// Create window with graphics context
	AppData.window = glfwCreateWindow(1280, 720, "Twilight-Dream Password Manager", nullptr, nullptr);
	if (AppData.window == nullptr)
	{
		throw std::runtime_error("glfwCreateWindow failed");
	}

	glfwMakeContextCurrent(AppData.window);
	glfwSwapInterval(1); // Enable vsync
	
	// clang format off
	static const char *default_imgui_ini = (
		#include "../ui/imgui_layout.inl"
	);
	// clang format on
	
	// Setup Dear ImGui context
	IMGUI_CHECKVERSION();
	ImGui::CreateContext();
	ImGuiIO &io = ImGui::GetIO(); //(void)io;
	io.IniFilename = nullptr;
	io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard; // Enable Keyboard Controls
	io.ConfigFlags |= ImGuiConfigFlags_NavEnableGamepad;  // Enable Gamepad Controls
	io.ConfigFlags |= ImGuiConfigFlags_DockingEnable;     // Enable Docking
	io.ConfigFlags |= ImGuiConfigFlags_ViewportsEnable;   // Enable Multi-Viewport / Platform Windows
	// io.ConfigViewportsNoAutoMerge = true;
	// io.ConfigViewportsNoTaskBarIcon = true;

	// Setup Dear ImGui style
	ImGui::StyleColorsDark();
	// ImGui::StyleColorsLight();

	ImGui::StyleColorsLight();
	ImGuiStyle &style     = ImGui::GetStyle();
	style.FrameBorderSize = 1.0f;
	style.FrameRounding   = 4.0f;
	if (io.ConfigFlags & ImGuiConfigFlags_ViewportsEnable)
	{
		style.WindowRounding              = 0.0f;
		style.Colors[ImGuiCol_WindowBg].w = 1.0f;
	}

	if (!std::filesystem::exists("imgui.ini"))
	{
		ImGui::LoadIniSettingsFromMemory(default_imgui_ini);
	}
	else
	{
		ImGui::LoadIniSettingsFromDisk("imgui.ini");
	}

	// Setup Platform/Renderer backends
	ImGui_ImplGlfw_InitForOpenGL(AppData.window, true);
	ImGui_ImplOpenGL3_Init(glsl_version);
}

inline void APP_Inital(ApplicationData &AppData)
{
	using namespace std::chrono_literals;
	ImGUI_Inital(AppData);
	if (AppData.background_thread.has_value())
	{
		AppData.background_thread->request_stop();
		AppData.background_thread->join();
		AppData.background_thread.reset();
	}
	AppData.background_thread = std::jthread(
	    [](std::stop_token st, ApplicationData &AppData)
	    {
		    while (!st.stop_requested())
		    {
			    std::optional<std::function<void()>> task;
			    if (AppData.current_task.has_value())
			    {
				    {
					    std::scoped_lock lock(AppData.mutex_task);
					    task = std::move(AppData.current_task.value());
					    AppData.current_task.reset();
				    }
			    }
			    else
			    {
				    std::this_thread::sleep_for(33ms);
			    }

			    try
			    {
				    if (task.has_value())
					    task.value()();
			    }
			    catch (const std::exception &e)
			    {
				    Logger::Instance().Error().Log("Error in background task: {}. ", e.what());
				    throw;
			    }
			    catch (...)
			    {
				    Logger::Instance().Error().Log("Error in background task: Unknow Error. ");
				    throw;
			    }
		    }
	    },
	    std::ref(AppData));
}

inline void APP_Cleanup(ApplicationData &AppData)
{
	std::call_once(
	    AppData.cleanup_once,
	    [&AppData]()
	    {
		    // Cleanup
		    ImGui_ImplOpenGL3_Shutdown();
		    ImGui_ImplGlfw_Shutdown();
		    ImGui::DestroyContext();

		    glfwDestroyWindow(AppData.window);
		    glfwTerminate();

		    // Wipe application sensitive data.
		    memory_set_no_optimize_function<0x00>(AppData.BufferRegisterUsername.data(), AppData.BufferRegisterUsername.size() * sizeof(char));
		    memory_set_no_optimize_function<0x00>(AppData.BufferRegisterPassword.data(), AppData.BufferRegisterPassword.size() * sizeof(char));
		    memory_set_no_optimize_function<0x00>(AppData.BufferLoginUsername.data(), AppData.BufferLoginUsername.size() * sizeof(char));
		    memory_set_no_optimize_function<0x00>(AppData.BufferLoginPassword.data(), AppData.BufferLoginPassword.size() * sizeof(char));
		    memory_set_no_optimize_function<0x00>(AppData.ShowPPI_Password.data(), AppData.ShowPPI_Password.size() * sizeof(char));
		    memory_set_no_optimize_function<0x00>(AppData.ShowPPI_NewPassword.data(), AppData.ShowPPI_NewPassword.size() * sizeof(char));
		    memory_set_no_optimize_function<0x00>(AppData.ShowPPI_Description.data(), AppData.ShowPPI_Description.size() * sizeof(char));
		    memory_set_no_optimize_function<0x00>(
		        AppData.BUFFER_ShowGUI_PPI_FindPasswordInstanceByID.data(),
		        AppData.BUFFER_ShowGUI_PPI_FindPasswordInstanceByID.size() * sizeof(char));
		    memory_set_no_optimize_function<0x00>(
		        AppData.BUFFER_ShowGUI_PPI_FindPasswordInstanceByDescription.data(),
		        AppData.BUFFER_ShowGUI_PPI_FindPasswordInstanceByDescription.size() * sizeof(char));
	    });
}

inline void APP_Loop(ApplicationData &AppData)
{

	// Our state
	ImVec4   clear_color = ImVec4(0.45f, 0.55f, 0.60f, 1.00f);
	ImGuiIO &io          = ImGui::GetIO();

	// io.Fonts->AddFontFromFileTTF(
	//     "C:/Windows/Fonts/msyh.ttc", 16.0f, nullptr, io.Fonts->GetGlyphRangesChineseSimplifiedCommon());

	bool ShowRegistrationSuccessPopup = false;
	bool ShowRegistrationFailPopup    = false;

	bool ShowLoadUserFailedPopup               = false;
	bool ShowUsernameAuthenticationFailedPopup = false;
	bool ShowPasswordAuthenticationFailedPopup = false;
	bool ShowInvalidCurrentUUIDFilePopup       = false;

	// Variables for controlling frame rate
	const float target_frame_time   = 1.0f / 60.0f; // 60 FPS
	auto        previous_frame_time = std::chrono::high_resolution_clock::now();

	while (!glfwWindowShouldClose(AppData.window))
	{
		// Calculate the time passed since the last frame
		auto                         current_time = std::chrono::high_resolution_clock::now();
		std::chrono::duration<float> elapsed_time = current_time - previous_frame_time;
		previous_frame_time                       = current_time;

		// Calculate the remaining time to achieve 60 FPS
		float frame_time = elapsed_time.count();
		if (frame_time < target_frame_time)
		{
			std::this_thread::sleep_for(std::chrono::milliseconds(int((target_frame_time - frame_time) * 1000)));
		}

		// Poll and handle events (inputs, window resize, etc.)
		glfwPollEvents();

		// Start the Dear ImGui frame
		ImGui_ImplOpenGL3_NewFrame();
		ImGui_ImplGlfw_NewFrame();
		ImGui::NewFrame();

		ImGui::DockSpaceOverViewport(ImGui::GetMainViewport());

		Show_ProgressBar(AppData);

		ApplicationUserRegistration(AppData.BufferRegisterUsername, AppData.BufferRegisterPassword, ShowRegistrationSuccessPopup, ShowRegistrationFailPopup);

		ApplicationUserLogin(
		    AppData.BufferLoginUsername,
		    AppData.BufferLoginPassword,
		    ShowInvalidCurrentUUIDFilePopup,
		    ShowUsernameAuthenticationFailedPopup,
		    ShowPasswordAuthenticationFailedPopup,
		    ShowLoadUserFailedPopup);

		if (AppData.ShowGUI_PersonalPasswordInfo)
			ShowGUI_PersonalPasswordInfo(AppData.BufferLoginPassword, AppData);
		if (AppData.ShowPPI_CreatePasswordInstance)
			ShowGUI_PPI_CreatePasswordInstance(AppData.BufferLoginPassword, AppData);
		if (AppData.ShowPPI_ChangePasswordInstance)
			ShowGUI_PPI_ChangePasswordInstance(AppData.BufferLoginPassword, AppData);
		if (AppData.ShowPPI_ListAllPasswordInstance)
			ShowGUI_PPI_ListAllPasswordInstance(AppData.BufferLoginPassword, AppData);

		if (AppData.ShowPPI_DeletePasswordInstance)
			ShowGUI_PPI_DeletePasswordInstance(AppData.BufferLoginPassword, AppData);
		if (AppData.ShowPPI_ConfirmDeleteAllPasswordInstance)
			ShowGUI_PPI_DeleteAllPasswordInstance(AppData.BufferLoginPassword, AppData);

		if (AppData.ShowPPI_ChangeInstanceMasterKeyWithSystemPassword)
			ShowGUI_PPI_ChangeInstanceMasterKeyWithSystemPassword(AppData.BufferLoginPassword, AppData);

		ShowGUI_PPI_FindPasswordInstanceByID(AppData.BufferLoginPassword, AppData);
		ShowGUI_PPI_FindPasswordInstanceByDescription(AppData.BufferLoginPassword, AppData);

		if (AppData.ShowGUI_PersonalFileInfo)
			ShowGUI_PersonalFileInfo(AppData.BufferLoginPassword, AppData);
		if (AppData.ShowPFI_CreateFileInstance)
			ShowGUI_PFI_CreateFileInstance(AppData);
		if (AppData.ShowPFI_ListAllFileInstance)
			ShowGUI_PFI_ListAllFileInstance(AppData);
		if (AppData.ShowPFI_DeleteFileInstanceByID)
			ShowGUI_PFI_DeleteFileInstance(AppData);
		if (AppData.ShowPFI_EncryptFile)
			ShowGUI_PFI_EncryptFile(AppData.BufferLoginPassword, AppData);
		if (AppData.ShowPFI_DecryptFile)
			ShowGUI_PFI_DecryptFile(AppData.BufferLoginPassword, AppData);
		if (AppData.ShowPFI_ConfirmDeleteAllFileInstancesPopup)
			ShowGUI_PFI_ConfirmDeleteAllFileInstances(AppData);

		// Rendering
		ImGui::Render();
		int display_w, display_h;
		glfwGetFramebufferSize(AppData.window, &display_w, &display_h);
		glViewport(0, 0, display_w, display_h);
		glClearColor(clear_color.x * clear_color.w, clear_color.y * clear_color.w, clear_color.z * clear_color.w, clear_color.w);
		glClear(GL_COLOR_BUFFER_BIT);
		ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());

		// Update and Render additional Platform Windows
		if (io.ConfigFlags & ImGuiConfigFlags_ViewportsEnable)
		{
			GLFWwindow *backup_current_context = glfwGetCurrentContext();
			ImGui::UpdatePlatformWindows();
			ImGui::RenderPlatformWindowsDefault();
			glfwMakeContextCurrent(backup_current_context);
		}

		glfwSwapBuffers(AppData.window);
	}
}
