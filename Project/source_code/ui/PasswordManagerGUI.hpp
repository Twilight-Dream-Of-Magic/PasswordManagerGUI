#pragma once

// clang-format off
#include "../core/application_data.hpp"
#include "../core/application_functional.hpp"
#include "../utility/async_tool.hpp"
#include "CommonUIComponent.hpp"
#include "UIActions.inl"
#include "FileEncryptionUI.inl"
#include "PasswordEncryptionUI.inl"
// clang-format on

// ImGUI Custom Application Function In Loop

inline void ApplicationUserRegistration(
    std::vector<char> &BufferRegisterUsername,
    std::vector<char> &BufferRegisterPassword,
    bool              &ShowRegistrationSuccessPopup,
    bool              &ShowRegistrationFailPopup)
{
	// User registration window
	ImGui::Begin("User Registration");
	ImGui::Text("New Username:");
	ImGui::InputText("##Register Username", BufferRegisterUsername.data(), 2048, ImGuiInputTextFlags_None);
	ImGui::Text("New Password:");
	ImGui::InputText("##Register Password", BufferRegisterPassword.data(), 2048, ImGuiInputTextFlags_Password);

	ImGui::Dummy(ImVec2(0.f, 1.f));

	if (ImGui::Button("Register"))
	{

		PasswordManagerUserKey  NewUserKey;
		PasswordManagerUserData NewUserData;

		GenerateRandomSalt(NewUserKey.RandomSalt);
		GenerateRandomSalt(NewUserKey.RandomPasswordSalt);

		auto new_end = std::find_if(BufferRegisterUsername.rbegin(), BufferRegisterUsername.rend(), [](char character) { return character != '\x00'; });

		BufferRegisterUsername.erase(new_end.base(), BufferRegisterUsername.end());

		new_end = std::find_if(BufferRegisterPassword.rbegin(), BufferRegisterPassword.rend(), [](char character) { return character != '\x00'; });

		BufferRegisterPassword.erase(new_end.base(), BufferRegisterPassword.end());

		if (!BufferRegisterUsername.empty() && !BufferRegisterPassword.empty())
		{
			// Generate a unique user ID
			GenerateUUID(BufferRegisterUsername, NewUserKey.RandomSalt, NewUserKey.RegistrationTime, NewUserKey.RandomUUID);

			NewUserData.UserName       = std::string(BufferRegisterUsername.begin(), BufferRegisterUsername.end());
			NewUserData.HashedPassword = PasswordAndHash(BufferRegisterPassword, NewUserKey.RandomPasswordSalt);

			// Save new user data
			SavePasswordManagerUser(std::pair<PasswordManagerUserKey, PasswordManagerUserData>{NewUserKey, NewUserData});

			ShowRegistrationSuccessPopup = true;
		}
		else
		{
			ShowRegistrationFailPopup = true;
		}

		// Clear Application GUI State Data
		// BufferRegisterUsername = std::vector<char>(2048, 0x00);
		// BufferRegisterPassword = std::vector<char>(2048, 0x00);
		memory_set_no_optimize_function<0x00>(BufferRegisterUsername.data(), BufferRegisterUsername.size());
		memory_set_no_optimize_function<0x00>(BufferRegisterPassword.data(), BufferRegisterPassword.size());
	}

	ImGui::End();

	if (ShowRegistrationSuccessPopup)
	{
		ImGui::OpenPopup("Registration Success");
	}
	if (ImGui::BeginPopup("Registration Success"))
	{
		ImGui::Text("Registration successful! Please save your UUID - 'current_uuid.json' file. Never lose this file!");
		if (ImGui::Button("OK"))
		{
			ImGui::CloseCurrentPopup();
			ShowRegistrationSuccessPopup = false;
		}
		ImGui::EndPopup();
	}

	if (ShowRegistrationFailPopup)
	{
		ImGui::OpenPopup("Registration Fail");
	}
	if (ImGui::BeginPopup("Registration Fail"))
	{
		ImGui::Text("Registration failed! Please make sure your username and password are not empty!");
		if (ImGui::Button("OK"))
		{
			ImGui::CloseCurrentPopup();
			ShowRegistrationFailPopup = false;
		}
		ImGui::EndPopup();
	}
}

inline void ApplicationUserLogin(
    std::vector<char> &BufferLoginUsername,
    std::vector<char> &BufferLoginPassword,
    bool              &ShowInvalidCurrentUUIDFilePopup,
    bool              &ShowUsernameAuthenticationFailedPopup,
    bool              &ShowPasswordAuthenticationFailedPopup,
    bool              &ShowLoadUserFailedPopup)
{
	// User login window
	ImGui::Begin("User Login");
	ImGui::BeginDisabled(CurrentApplicationData.IsUserLogin);
	ImGui::Text("Username:");
	ImGui::InputText("##Username", BufferLoginUsername.data(), 2048, ImGuiInputTextFlags_None);
	ImGui::Text("System Password:");
	ImGui::InputText("##Password", BufferLoginPassword.data(), 2048, ImGuiInputTextFlags_Password);

	ImGui::Dummy(ImVec2(0.f, 1.f));

	if (ImGui::Button("Login"))
	{
		Do_Login(
		    BufferLoginUsername,
		    BufferLoginPassword,
		    ShowInvalidCurrentUUIDFilePopup,
		    ShowUsernameAuthenticationFailedPopup,
		    ShowPasswordAuthenticationFailedPopup,
		    ShowLoadUserFailedPopup);
	}
	ImGui::EndDisabled();

	ImGui::SameLine();

	ImGui::BeginDisabled(!CurrentApplicationData.IsUserLogin);
	if (ImGui::Button("Logout"))
	{
		Do_LogoutPersonalPasswordInfo(BufferLoginPassword, CurrentApplicationData);
		Logger::Instance().Notice().Log("Logout successful!");
		CurrentApplicationData.IsUserLogin = false;
	}
	ImGui::EndDisabled();

	ImGui::End();

	if (ShowLoadUserFailedPopup)
	{
		ImGui::OpenPopup("Load UUID File Failed");
	}
	if (ImGui::BeginPopup("Load UUID File Failed"))
	{
		ImGui::Text("Loading the UUID - 'current_uuid.json' file failed. Please make sure the file exists.");
		if (ImGui::Button("OK"))
		{
			ImGui::CloseCurrentPopup();
			ShowLoadUserFailedPopup = false;
		}
		ImGui::EndPopup();
	}

	if (ShowInvalidCurrentUUIDFilePopup)
	{
		ImGui::OpenPopup("Invalid UUID File Content");
	}
	if (ImGui::BeginPopup("Invalid UUID File Content"))
	{
		ImGui::Text(
		    "Your UUID - 'current_uuid.json' file is not valid. Please make sure the contents of the file are "
		    "correct.");
		if (ImGui::Button("OK"))
		{
			ImGui::CloseCurrentPopup();
			ShowInvalidCurrentUUIDFilePopup = false;
		}
		ImGui::EndPopup();
	}

	if (ShowUsernameAuthenticationFailedPopup)
	{
		ImGui::OpenPopup("Username Authentication Failed");
	}
	if (ImGui::BeginPopup("Username Authentication Failed"))
	{
		ImGui::Text("Username authentication has failed. Please check your username.");
		if (ImGui::Button("OK"))
		{
			ImGui::CloseCurrentPopup();
			ShowUsernameAuthenticationFailedPopup = false;
		}
		ImGui::EndPopup();
	}

	if (ShowPasswordAuthenticationFailedPopup)
	{
		ImGui::OpenPopup("Password Authentication Failed");
	}
	if (ImGui::BeginPopup("Password Authentication Failed"))
	{
		ImGui::Text("Password authentication has failed. Please check your password.");
		if (ImGui::Button("OK"))
		{
			ImGui::CloseCurrentPopup();
			ShowPasswordAuthenticationFailedPopup = false;
		}
		ImGui::EndPopup();
	}
}
