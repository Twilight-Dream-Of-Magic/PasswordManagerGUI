#pragma once

#include "application_core_functional.hpp"

struct ApplicationData
{
	bool ShowGUI_PersonalPasswordInfo = false;

	/* About PersonalPasswordInfo GUI Data */

	bool ShowPPI_CreatePasswordInstance;

	bool ShowPPI_ChangePasswordInstance;
	bool ShowPPI_ChangePasswordInstanceSuccessful;
	bool ShowPPI_ChangePasswordInstanceFailed;

	bool ShowPPI_ListAllPasswordInstance;
	bool ShowPPI_ListAllPasswordInstanceData;

	bool ShowPPI_DeletePasswordInstance;
	bool ShowPPI_ConfirmDeleteAllPasswordInstance;
	bool ShowPPI_FindPasswordInstanceByID;
	bool ShowPPI_FindPasswordInstanceByDescription;
	bool ShowPPI_ChangeInstanceMasterKeyWithSystemPassword;
	bool ShowPPI_SystemPasswordChangeSuccessful;
	bool ShowPPI_SystemPasswordNotChange;
	bool ShowPPI_SystemPasswordChangeFailed;

	bool ShowPPI_NeedAES = false;
	bool ShowPPI_NeedRC6 = false;
	bool ShowPPI_NeedSM4 = false;
	bool ShowPPI_NeedTwofish = false;
	bool ShowPPI_NeedSerpent = false;

	std::uint64_t ShowPPI_SelectedPasswordInstanceID = 0;
	std::string ShowPPI_Description = std::string(2048, 0x00);
	std::string ShowPPI_SelectedPasswordInstanceDescription = "";
	std::string ShowPPI_Password = std::string(2048, 0x00);
	std::string ShowPPI_NewPassword = std::string(2048, 0x00);

	std::vector<std::string> ShowPPI_EncryptionAlgorithms;
	std::vector<std::string> ShowPPI_DecryptionAlgorithms;

	bool ShowPPI_ChangeEncryptedPassword = false;

	PasswordManagerUserKey UserKey;
	PasswordManagerUserData UserData;

	PersonalPasswordInfo PersonalPasswordInfo;
	std::filesystem::path PersonalPasswordInfoFilePath;
};

//global object
ApplicationData CurrentApplicationData;

//ImGUI Custom Application Function In Loop

inline void ApplicationUserRegistration
(
	std::vector<char>& BufferRegisterUsername, std::vector<char>& BufferRegisterPassword,
	bool& ShowRegistrationSuccessPopup, bool& ShowRegistrationFailPopup
)
{
	// User registration window
	ImGui::Begin("User Registration");

	ImGui::InputText("New Username", BufferRegisterUsername.data(), 2048, ImGuiInputTextFlags_None);
	ImGui::InputText("New Password", BufferRegisterPassword.data(), 2048, ImGuiInputTextFlags_Password);

	if (ImGui::Button("Register")) {

		PasswordManagerUserKey NewUserKey;
		PasswordManagerUserData NewUserData;

		GenerateRandomSalt(NewUserKey.RandomSalt);
		GenerateRandomSalt(NewUserKey.RandomPasswordSalt);

		auto new_end = std::find_if
		(
			BufferRegisterUsername.rbegin(), BufferRegisterUsername.rend(), 
			[](char character)
			{
				return character != '\x00';
			}
		);

		BufferRegisterUsername.erase(new_end.base(), BufferRegisterUsername.end());

		new_end = std::find_if
		(
			BufferRegisterPassword.rbegin(), BufferRegisterPassword.rend(), 
			[](char character)
			{
				return character != '\x00';
			}
		);

		BufferRegisterPassword.erase(new_end.base(), BufferRegisterPassword.end());

		if(!BufferRegisterUsername.empty() && !BufferRegisterPassword.empty())
		{
			// Generate a unique user ID
			GenerateUUID(BufferRegisterUsername, NewUserKey.RandomSalt, NewUserKey.RegistrationTime, NewUserKey.RandomUUID);

			NewUserData.UserName = std::string(BufferRegisterUsername.begin(), BufferRegisterUsername.end());
			NewUserData.HashedPassword = PasswordAndHash(BufferRegisterPassword, NewUserKey.RandomPasswordSalt);

			// Save new user data
			SavePasswordManagerUser(std::pair<PasswordManagerUserKey, PasswordManagerUserData>{NewUserKey, NewUserData});

			ShowRegistrationSuccessPopup = true;
		}
		else
		{
			ShowRegistrationFailPopup = true;
		}

		//Clear Application GUI State Data
		BufferRegisterUsername = std::vector<char>(2048, 0x00);
		BufferRegisterPassword = std::vector<char>(2048, 0x00);
	}

	ImGui::End();

	if (ShowRegistrationSuccessPopup)
	{
		ImGui::OpenPopup("Registration Success");
	}
	if (ImGui::BeginPopup("Registration Success"))
	{
		ImGui::Text("Registration successful! Please save your UUID - 'current_uuid.json' file. Never lose this file!");
		if (ImGui::Button("OK")) {
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
		if (ImGui::Button("OK")) {
			ImGui::CloseCurrentPopup();
			ShowRegistrationFailPopup = false;
		}
		ImGui::EndPopup();
	}
}

inline void ApplicationUserLogin
(
	std::vector<char>& BufferLoginUsername, std::vector<char>& BufferLoginPassword,
	bool& ShowInvalidCurrentUUIDFilePopup, bool& ShowUsernameAuthenticationFailedPopup,
	bool& ShowPasswordAuthenticationFailedPopup, bool& ShowLoadUserFailedPopup
)
{
	// User login window
	ImGui::Begin("User Login");

	ImGui::InputText("Username", BufferLoginUsername.data(), 2048, ImGuiInputTextFlags_None);
	ImGui::InputText("Password", BufferLoginPassword.data(), 2048, ImGuiInputTextFlags_Password);

	if (ImGui::Button("Login"))
	{
		PasswordManagerUserKey CurrentUserKey;
		PasswordManagerUserData CurrentUserData;

		auto new_end = std::find_if
		(
			BufferLoginUsername.rbegin(), BufferLoginUsername.rend(), 
			[](char character)
			{
				return character != '\x00';
			}
		);

		BufferLoginUsername.erase(new_end.base(), BufferLoginUsername.end());

		new_end = std::find_if
		(
			BufferLoginPassword.rbegin(), BufferLoginPassword.rend(), 
			[](char character)
			{
				return character != '\x00';
			}
		);

		BufferLoginPassword.erase(new_end.base(), BufferLoginPassword.end());

		// Use the "current_uuid.json" file to load the UUID and RandomSalt for logins
		if (LoadPasswordManagerUUID(CurrentUserKey))
		{
			if (CurrentUserKey.RandomSalt.empty() && CurrentUserKey.RandomPasswordSalt.empty() && CurrentUserKey.RegistrationTime == 0)
			{
				std::cout << "Login failed because the UUID of the contents of the 'current_uuid.json' file is invalid!" << std::endl;

				ShowInvalidCurrentUUIDFilePopup = true;

				goto LoginButtonDone;
			}

			//Loading usernames and hashed passwords with UUID
			LoadPasswordManagerUser(CurrentUserKey, CurrentUserData);

			// Verify Username and Password
			const bool VaildUsername = VerifyUUID(BufferLoginUsername, CurrentUserKey.RandomSalt, CurrentUserKey.RegistrationTime, CurrentUserKey);
			const bool VaildPassword = VerifyPassword(BufferLoginPassword, CurrentUserKey, CurrentUserData);

			if (VaildUsername && VaildPassword)
			{
				// Login successful
				std::cout << "Login successful!" << std::endl;

				if (CurrentUserData.IsFirstLogin)
				{
					FirstLoginLogic(BufferLoginPassword, CurrentUserKey, CurrentUserData);
				}

				//Change Application Data
				CurrentApplicationData.UserKey = CurrentUserKey;
				CurrentApplicationData.UserData = CurrentUserData;

				CurrentApplicationData.PersonalPasswordInfoFilePath = std::filesystem::path(std::string("PersonalPasswordData") + "/" + CurrentApplicationData.UserData.PersonalPasswordInfoFileName + ".json");
				CurrentApplicationData.PersonalPasswordInfo.Deserialization(CurrentApplicationData.PersonalPasswordInfoFilePath);

				CurrentApplicationData.ShowGUI_PersonalPasswordInfo = true;
				CurrentApplicationData.ShowPPI_CreatePasswordInstance = true;
				CurrentApplicationData.ShowPPI_ChangePasswordInstance = true;
			}
			else
			{
				if (VaildUsername == false && VaildPassword == true)
				{
					std::cout << "Failed to login, incorrect username by UUID checking" << std::endl;

					// Username validation failed
					ShowUsernameAuthenticationFailedPopup = true;
				}
				else if (VaildUsername == true && VaildPassword == false)
				{
					std::cout << "Failed to login, incorrect password by security comparison" << std::endl;

					// Password validation failed
					ShowPasswordAuthenticationFailedPopup = true;
				}
			}
		}
		else
		{
			// Loading user data failed
			ShowLoadUserFailedPopup = true;
		}

		//Clear Application GUI State Data
		BufferLoginUsername = std::vector<char>(2048, 0x00);
		BufferLoginPassword = std::vector<char>(2048, 0x00);

	}
	LoginButtonDone:

	ImGui::End();

	if (ShowLoadUserFailedPopup)
	{
		ImGui::OpenPopup("Load UUID File Failed");
	}
	if (ImGui::BeginPopup("Load UUID File Failed"))
	{
		ImGui::Text("Loading the UUID - 'current_uuid.json' file failed. Please make sure the file exists.");
		if (ImGui::Button("OK")) {
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
		ImGui::Text("Your UUID - 'current_uuid.json' file is not valid. Please make sure the contents of the file are correct.");
		if (ImGui::Button("OK")) {
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
		if (ImGui::Button("OK")) {
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
		if (ImGui::Button("OK")) {
			ImGui::CloseCurrentPopup();
			ShowPasswordAuthenticationFailedPopup = false;
		}
		ImGui::EndPopup();
	}
}

inline void ShowGUI_PersonalPasswordInfo(std::vector<char>& BufferLoginPassword, ApplicationData& AppData)
{
	ImGui::Begin("Personal Password Info");
	
	if (ImGui::Button("Create Password Instance"))
	{
		AppData.ShowPPI_CreatePasswordInstance = !AppData.ShowPPI_CreatePasswordInstance;
	}

	if (ImGui::Button("Change Password Instance"))
	{
		AppData.ShowPPI_ChangePasswordInstance = !AppData.ShowPPI_ChangePasswordInstance;
	}

	if (ImGui::Button("List All Password Instance"))
	{
		AppData.ShowPPI_ListAllPasswordInstance = !AppData.ShowPPI_ListAllPasswordInstance;
	}

	if (ImGui::Button("Delete Password Instance By ID"))
	{
		AppData.ShowPPI_DeletePasswordInstance = true;
	}

	if (ImGui::Button("Delete All Password Instance"))
	{
		AppData.ShowPPI_ConfirmDeleteAllPasswordInstance = true;
	}

	if (ImGui::Button("List Password Instance By ID"))
	{
		AppData.ShowPPI_FindPasswordInstanceByID = true;
	}

	if (ImGui::Button("List Password Instance By Description"))
	{
		AppData.ShowPPI_FindPasswordInstanceByDescription = true;
	}

	if (ImGui::Button("Change UUID(Master Key Material) With System Password"))
	{
		AppData.ShowPPI_ChangeInstanceMasterKeyWithSystemPassword = true;
	}

	if (ImGui::Button("Logout"))
	{
		//Close This GUI
		CurrentApplicationData.ShowGUI_PersonalPasswordInfo = false;

		//Clear Application GUI State Data
		CurrentApplicationData.UserKey = PasswordManagerUserKey();
		CurrentApplicationData.UserData = PasswordManagerUserData();
		CurrentApplicationData.PersonalPasswordInfo = PersonalPasswordInfo();
		CurrentApplicationData.PersonalPasswordInfoFilePath = "";

		//Zero Bytes SystemPassword - Secure Wipe
		memory_set_no_optimize_function<0x00>(BufferLoginPassword.data(), BufferLoginPassword.size());
		
		//Close This All Sub GUI
		AppData.ShowPPI_CreatePasswordInstance = false;
		AppData.ShowPPI_ChangePasswordInstance = false;
		AppData.ShowPPI_ListAllPasswordInstance = false;
		AppData.ShowPPI_ListAllPasswordInstanceData = false;
		AppData.ShowPPI_DeletePasswordInstance = false;
		AppData.ShowPPI_ConfirmDeleteAllPasswordInstance = false;
		AppData.ShowPPI_FindPasswordInstanceByID = false;
		AppData.ShowPPI_FindPasswordInstanceByDescription = false;
	}

	ImGui::End();
}

inline void ShowGUI_PPI_CreatePasswordInstance(std::vector<char>& BufferLoginPassword, ApplicationData& AppData)
{
	if (ImGui::Begin("Create Password Instance"))
	{
		ImGui::InputText("System Password", BufferLoginPassword.data(), BufferLoginPassword.size(), ImGuiInputTextFlags_Password);
		ImGui::InputTextMultiline("New Description", AppData.ShowPPI_Description.data(), AppData.ShowPPI_Description.size(), ImVec2(400, 400), ImGuiInputTextFlags_CtrlEnterForNewLine);
		ImGui::InputText("New Password Text", AppData.ShowPPI_NewPassword.data(), AppData.ShowPPI_NewPassword.size(), ImGuiInputTextFlags_None);

		ImGui::Checkbox("Need AES", &AppData.ShowPPI_NeedAES);
		ImGui::Checkbox("Need RC6", &AppData.ShowPPI_NeedRC6);
		ImGui::Checkbox("Need SM4", &AppData.ShowPPI_NeedSM4);
		ImGui::Checkbox("Need Twofish", &AppData.ShowPPI_NeedTwofish);
		ImGui::Checkbox("Need Serpent", &AppData.ShowPPI_NeedSerpent);

		if (ImGui::Button("Create and Encrypt Password"))
		{
			//Select Algorithms
			if(AppData.ShowPPI_NeedAES)
			{
				AppData.ShowPPI_EncryptionAlgorithms.push_back(CryptoCipherAlgorithmNames[0]);
			}
			if(AppData.ShowPPI_NeedRC6)
			{
				AppData.ShowPPI_EncryptionAlgorithms.push_back(CryptoCipherAlgorithmNames[1]);
			}
			if(AppData.ShowPPI_NeedSM4)
			{
				AppData.ShowPPI_EncryptionAlgorithms.push_back(CryptoCipherAlgorithmNames[2]);
			}
			if(AppData.ShowPPI_NeedTwofish)
			{
				AppData.ShowPPI_EncryptionAlgorithms.push_back(CryptoCipherAlgorithmNames[3]);
			}
			if(AppData.ShowPPI_NeedSerpent)
			{
				AppData.ShowPPI_EncryptionAlgorithms.push_back(CryptoCipherAlgorithmNames[4]);
			}

			AppData.ShowPPI_DecryptionAlgorithms.resize(AppData.ShowPPI_EncryptionAlgorithms.size(), "");
			std::reverse_copy(AppData.ShowPPI_EncryptionAlgorithms.begin(), AppData.ShowPPI_EncryptionAlgorithms.end(), AppData.ShowPPI_DecryptionAlgorithms.begin());

			const bool VaildPassword = VerifyPassword(BufferLoginPassword, AppData.UserKey, AppData.UserData);

			if
			(
				!AppData.UserKey.RandomUUID.empty() && !BufferLoginPassword.empty() && 
				!AppData.ShowPPI_NewPassword.empty() && !AppData.ShowPPI_EncryptionAlgorithms.empty() &&
				!AppData.ShowPPI_DecryptionAlgorithms.empty() && VaildPassword
			)
			{
				auto new_end = std::find_if
				(
					AppData.ShowPPI_NewPassword.rbegin(), AppData.ShowPPI_NewPassword.rend(), 
					[](char character)
					{
						return character != '\x00';
					}
				);

				AppData.ShowPPI_NewPassword.erase(new_end.base(), AppData.ShowPPI_NewPassword.end());
				
				// 调用CreatePasswordInstance函数来执行创建密码实例的操作
				auto PasswordInstance = AppData.PersonalPasswordInfo.CreatePasswordInstance
				(
					MakeTokenString(AppData.UserKey.RandomUUID, BufferLoginPassword),
					AppData.ShowPPI_Description, AppData.ShowPPI_NewPassword,
					AppData.ShowPPI_EncryptionAlgorithms,
					AppData.ShowPPI_DecryptionAlgorithms
				);
				AppData.PersonalPasswordInfo.AppendPasswordInstance(PasswordInstance);

				AppData.PersonalPasswordInfo.Serialization(AppData.PersonalPasswordInfoFilePath);
			}

			AppData.ShowPPI_CreatePasswordInstance = false;

			//Clear Application GUI State Data
			AppData.ShowPPI_NewPassword = std::string(2048, 0x00);
			AppData.ShowPPI_Description = std::string(2048, 0x00);
			AppData.ShowPPI_EncryptionAlgorithms.clear();
			AppData.ShowPPI_DecryptionAlgorithms.clear();
		}
		if (ImGui::Button("Cancel"))
		{
			AppData.ShowPPI_CreatePasswordInstance = false;

			//Clear Application GUI State Data
			AppData.ShowPPI_NewPassword = std::string(2048, 0x00);
			AppData.ShowPPI_Description = std::string(2048, 0x00);
			AppData.ShowPPI_EncryptionAlgorithms.clear();
			AppData.ShowPPI_DecryptionAlgorithms.clear();
		}

		
	}
	ImGui::End();
}

inline void ShowGUI_PPI_ChangePasswordInstance(std::vector<char>& BufferLoginPassword, ApplicationData& AppData)
{
	ImGui::Begin("Change Password Instance By ID");

	BufferLoginPassword.resize(2048, 0x00);
	ImGui::InputText("System Password", BufferLoginPassword.data(), BufferLoginPassword.size(), ImGuiInputTextFlags_Password);

	ImGui::InputScalar("Select Password Instance ID", ImGuiDataType_U64, &AppData.ShowPPI_SelectedPasswordInstanceID);
	ImGui::Checkbox("Change Encrypted Password", &AppData.ShowPPI_ChangeEncryptedPassword);
	ImGui::InputTextMultiline("Change Description", AppData.ShowPPI_Description.data(), AppData.ShowPPI_Description.size(), ImVec2(400, 400), ImGuiInputTextFlags_CtrlEnterForNewLine);
	ImGui::InputText("Change Password Text", AppData.ShowPPI_Password.data(), AppData.ShowPPI_Password.size(), ImGuiInputTextFlags_None);
		
	ImGui::Checkbox("Need AES", &AppData.ShowPPI_NeedAES);
	ImGui::Checkbox("Need RC6", &AppData.ShowPPI_NeedRC6);
	ImGui::Checkbox("Need SM4", &AppData.ShowPPI_NeedSM4);
	ImGui::Checkbox("Need Twofish", &AppData.ShowPPI_NeedTwofish);
	ImGui::Checkbox("Need Serpent", &AppData.ShowPPI_NeedSerpent);

	if (ImGui::Button("Flush Password Instance Description"))
	{
		AppData.ShowPPI_Description = AppData.PersonalPasswordInfo.FindPasswordInstanceDescriptionByID(AppData.ShowPPI_SelectedPasswordInstanceID);
		AppData.ShowPPI_Description.resize(2048, 0x00);
	}

	if (ImGui::Button("Change Password Instance"))
	{
		if(AppData.ShowPPI_ChangeEncryptedPassword)
		{
			if (AppData.ShowPPI_NeedAES)
			{
				AppData.ShowPPI_EncryptionAlgorithms.push_back(CryptoCipherAlgorithmNames[0]);
			}
			if (AppData.ShowPPI_NeedRC6)
			{
				AppData.ShowPPI_EncryptionAlgorithms.push_back(CryptoCipherAlgorithmNames[1]);
			}
			if (AppData.ShowPPI_NeedSM4)
			{
				AppData.ShowPPI_EncryptionAlgorithms.push_back(CryptoCipherAlgorithmNames[2]);
			}
			if (AppData.ShowPPI_NeedTwofish)
			{
				AppData.ShowPPI_EncryptionAlgorithms.push_back(CryptoCipherAlgorithmNames[3]);
			}
			if (AppData.ShowPPI_NeedSerpent)
			{
				AppData.ShowPPI_EncryptionAlgorithms.push_back(CryptoCipherAlgorithmNames[4]);
			}

			AppData.ShowPPI_DecryptionAlgorithms.resize(AppData.ShowPPI_EncryptionAlgorithms.size(), "");
			std::reverse_copy(AppData.ShowPPI_EncryptionAlgorithms.begin(), AppData.ShowPPI_EncryptionAlgorithms.end(), AppData.ShowPPI_DecryptionAlgorithms.begin());
		}

		const bool VaildPassword = VerifyPassword(BufferLoginPassword, AppData.UserKey, AppData.UserData);

		if
		(
			!AppData.UserKey.RandomUUID.empty() && !BufferLoginPassword.empty() && 
			!AppData.ShowPPI_Password.empty() && !AppData.ShowPPI_EncryptionAlgorithms.empty() &&
			!AppData.ShowPPI_DecryptionAlgorithms.empty() && VaildPassword
		)
		{
			auto new_end = std::find_if
			(
				AppData.ShowPPI_Password.rbegin(), AppData.ShowPPI_Password.rend(), 
				[](char character)
				{
					return character != '\x00';
				}
			);

			AppData.ShowPPI_Password.erase(new_end.base(), AppData.ShowPPI_Password.end());

			new_end = std::find_if
			(
				AppData.ShowPPI_Description.rbegin(), AppData.ShowPPI_Description.rend(), 
				[](char character)
				{
					return character != '\x00';
				}
			);

			AppData.ShowPPI_Description.erase(new_end.base(), AppData.ShowPPI_Description.end());

			// 调用ChangePasswordInstance函数来执行更改密码实例的操作
			bool IsChanged = AppData.PersonalPasswordInfo.ChangePasswordInstance
			(
				AppData.ShowPPI_SelectedPasswordInstanceID, AppData.ShowPPI_Description, AppData.ShowPPI_Password, 
				AppData.ShowPPI_EncryptionAlgorithms, AppData.ShowPPI_DecryptionAlgorithms, 
				MakeTokenString(AppData.UserKey.RandomUUID, BufferLoginPassword), AppData.ShowPPI_ChangeEncryptedPassword
			);

			if (IsChanged)
			{
				// 更改成功的处理逻辑
				AppData.PersonalPasswordInfo.Serialization(AppData.PersonalPasswordInfoFilePath);

				AppData.ShowPPI_ChangePasswordInstanceSuccessful = true;

				//Clear Application GUI State Data
				AppData.ShowPPI_Password = std::string(2048, 0x00);
				AppData.ShowPPI_Description = std::string(2048, 0x00);
				AppData.ShowPPI_EncryptionAlgorithms.clear();
				AppData.ShowPPI_DecryptionAlgorithms.clear();
			}
			else
			{
				// 更改失败的处理逻辑

				AppData.ShowPPI_ChangePasswordInstanceFailed = true;

				//Clear Application GUI State Data
				AppData.ShowPPI_Password = std::string(2048, 0x00);
				AppData.ShowPPI_Description = std::string(2048, 0x00);
				AppData.ShowPPI_EncryptionAlgorithms.clear();
				AppData.ShowPPI_DecryptionAlgorithms.clear();
			}
		}
	}
	if (ImGui::Button("Cancel"))
	{
		AppData.ShowPPI_ChangePasswordInstance = false;
	}

	ImGui::End();

	if(AppData.ShowPPI_ChangePasswordInstanceSuccessful)
		ImGui::OpenPopup("Password Instance Is Changed");
	if (ImGui::BeginPopup("Password Instance Is Changed", ImGuiWindowFlags_AlwaysAutoResize))
	{
		ImGui::Text("Password Instance Changed Successfully!");
		if (ImGui::Button("OK"))
		{
			ImGui::CloseCurrentPopup();
			AppData.ShowPPI_ChangePasswordInstance = false;
			AppData.ShowPPI_ChangePasswordInstanceSuccessful = false;
			
		}
		ImGui::EndPopup();
	}

	if(AppData.ShowPPI_ChangePasswordInstanceFailed)
		ImGui::OpenPopup("Password Instance Is Not Changed");
	if (ImGui::BeginPopup("Password Instance Is Not Changed", ImGuiWindowFlags_AlwaysAutoResize))
	{
		ImGui::Text("Failed to Change Password Instance");
		if (ImGui::Button("OK"))
		{
			ImGui::CloseCurrentPopup();
			AppData.ShowPPI_ChangePasswordInstance = false;
			AppData.ShowPPI_ChangePasswordInstanceFailed = false;
			
		}
		ImGui::EndPopup();
	}
}

inline void ShowGUI_PPI_ListAllPasswordInstance(std::vector<char>& BufferLoginPassword, ApplicationData& AppData)
{
	if (ImGui::Begin("List All Password Instance"))
	{
		BufferLoginPassword.resize(2048, 0x00);
		ImGui::InputText("System Password", BufferLoginPassword.data(), BufferLoginPassword.size(), ImGuiInputTextFlags_Password);
		ImGui::Checkbox("List All", &AppData.ShowPPI_ListAllPasswordInstanceData);

		if (ImGui::Button("Hide"))
		{
			AppData.ShowPPI_ListAllPasswordInstance = false;
		}

		if(AppData.ShowPPI_ListAllPasswordInstanceData)
		{
			auto new_end = std::find_if
			(
				BufferLoginPassword.rbegin(), BufferLoginPassword.rend(), 
				[](char character)
				{
					return character != '\x00';
				}
			);

			BufferLoginPassword.erase(new_end.base(), BufferLoginPassword.end());

			const bool VaildPassword = VerifyPassword(BufferLoginPassword, AppData.UserKey, AppData.UserData);

			if (!AppData.UserKey.RandomUUID.empty() && !BufferLoginPassword.empty() && VaildPassword)
			{
				AppData.PersonalPasswordInfo.Deserialization(AppData.PersonalPasswordInfoFilePath);

				// 调用ListAllPasswordInstance函数来执行列出密码实例的操作
				AppData.PersonalPasswordInfo.ListAllPasswordInstance
				(
					MakeTokenString(AppData.UserKey.RandomUUID, BufferLoginPassword)
				);

				auto& PassswordInstances = AppData.PersonalPasswordInfo.GetPassswordInstances();

				// 循环遍历每个PersonalPasswordInstance并在UI中显示
				for (const auto& Instance : PassswordInstances)
				{
					ImGui::Text("ID: %llu", Instance.ID);
					ImGui::Text("New Description: %s", Instance.Description.data());
					ImGui::Text("Decrypted Password: %s", Instance.DecryptedPassword.data());

					// 显示其他信息，如EncryptionAlgorithmNames和DecryptionAlgorithmNames
					ImGui::Text("Encryption Algorithms:");
					for (const auto& algorithm : Instance.EncryptionAlgorithmNames)
					{
						ImGui::Text("- %s", algorithm.data());
					}

					ImGui::Text("Decryption Algorithms:");
					for (const auto& algorithm : Instance.DecryptionAlgorithmNames)
					{
						ImGui::Text("- %s", algorithm.data());
					}

					// 在每个实例之间添加分隔线
					ImGui::Separator();
				}
			}
		}
		// 关闭或隐藏GUI时清除解密的密码
		if (!AppData.ShowPPI_ListAllPasswordInstanceData)
		{
			auto& PassswordInstances = AppData.PersonalPasswordInfo.GetPassswordInstances();

			for (auto& instance : PassswordInstances)
			{
				// 清除解密的密码
				if (instance.DecryptedPassword != "")
				{
					memory_set_no_optimize_function<0x00>(instance.DecryptedPassword.data(), instance.DecryptedPassword.size());
					instance.DecryptedPassword.clear();
				}
			}
		}

		ImGui::End();
	}
}

inline void ShowGUI_PPI_DeletePasswordInstance(ApplicationData& AppData)
{
	if(AppData.ShowPPI_DeletePasswordInstance)
		ImGui::OpenPopup("Delete Password Instance");

	if (ImGui::BeginPopupModal("Delete Password Instance", &AppData.ShowPPI_DeletePasswordInstance, ImGuiWindowFlags_AlwaysAutoResize))
	{
		ImGui::InputScalar("Password Instance ID", ImGuiDataType_U64, &AppData.ShowPPI_SelectedPasswordInstanceID);

		if (ImGui::Button("Delete"))
		{
			if (AppData.PersonalPasswordInfo.RemovePasswordInstance(AppData.ShowPPI_SelectedPasswordInstanceID))
			{
				AppData.PersonalPasswordInfo.Serialization(AppData.PersonalPasswordInfoFilePath);
			}

			AppData.ShowPPI_DeletePasswordInstance = false;
		}
		if (ImGui::Button("Cancel"))
		{
			AppData.ShowPPI_DeletePasswordInstance = false;
		}

		ImGui::EndPopup();
	}
}

inline void ShowGUI_PPI_DeleteAllPasswordInstance(ApplicationData& AppData)
{
	if(AppData.ShowPPI_ConfirmDeleteAllPasswordInstance)
		ImGui::OpenPopup("Confirm Delete All Password Instance");

	if (ImGui::BeginPopupModal("Confirm Delete All Password Instance", &AppData.ShowPPI_ConfirmDeleteAllPasswordInstance, ImGuiWindowFlags_AlwaysAutoResize))
	{
		ImGui::Text("Are you sure you want to delete all instances?");

		if (ImGui::Button("Delete All"))
		{
			AppData.PersonalPasswordInfo.RemoveAllPasswordInstance();
			AppData.PersonalPasswordInfo.Serialization(AppData.PersonalPasswordInfoFilePath);
			AppData.ShowPPI_ConfirmDeleteAllPasswordInstance = false;
		}
		if (ImGui::Button("Cancel"))
		{
			AppData.ShowPPI_ConfirmDeleteAllPasswordInstance = false;
		}

		ImGui::EndPopup();
	}
}

inline void ShowGUI_PPI_FindPasswordInstanceByID(std::vector<char>& BufferLoginPassword, ApplicationData& AppData)
{
	if(AppData.ShowPPI_FindPasswordInstanceByID)
		ImGui::OpenPopup("List Password Instance By ID");

	if (ImGui::BeginPopupModal("List Password Instance By ID", &AppData.ShowPPI_FindPasswordInstanceByID, ImGuiWindowFlags_AlwaysAutoResize))
	{
		BufferLoginPassword.resize(2048, 0x00);
		ImGui::InputText("System Password", BufferLoginPassword.data(), BufferLoginPassword.size(), ImGuiInputTextFlags_Password);
		ImGui::InputScalar("Password Instance ID", ImGuiDataType_U64, &AppData.ShowPPI_SelectedPasswordInstanceID);

		if (ImGui::Button("Hide"))
		{
			AppData.ShowPPI_FindPasswordInstanceByID = false;
		}

		const bool VaildPassword = VerifyPassword(BufferLoginPassword, AppData.UserKey, AppData.UserData);

		if(AppData.ShowPPI_FindPasswordInstanceByID && VaildPassword)
		{
			auto Optional = AppData.PersonalPasswordInfo.FindPasswordInstanceByID
			(
				MakeTokenString(AppData.UserKey.RandomUUID, BufferLoginPassword),
				AppData.ShowPPI_SelectedPasswordInstanceID
			);

			if (Optional.has_value())
			{
				auto& Instance = Optional.value();

				ImGui::Text("ID: %llu", Instance.ID);
				ImGui::Text("New Description %s", Instance.Description.data());
				ImGui::Text("Decrypted Password: %s", Instance.DecryptedPassword.data());

				// 显示其他信息，如EncryptionAlgorithmNames和DecryptionAlgorithmNames
				ImGui::Text("Encryption Algorithms:");
				for (const auto& algorithm : Instance.EncryptionAlgorithmNames)
				{
					ImGui::Text("- %s", algorithm.data());
				}

				ImGui::Text("Decryption Algorithms:");
				for (const auto& algorithm : Instance.DecryptionAlgorithmNames)
				{
					ImGui::Text("- %s", algorithm.data());
				}
			}
		}

		ImGui::EndPopup();
	}
}

inline void ShowGUI_PPI_FindPasswordInstanceByDescription(std::vector<char>& BufferLoginPassword, ApplicationData& AppData)
{
	if(AppData.ShowPPI_FindPasswordInstanceByDescription)
		ImGui::OpenPopup("List Password Instance By Description");

	if (ImGui::BeginPopupModal("List Password Instance By Description", &AppData.ShowPPI_FindPasswordInstanceByDescription, ImGuiWindowFlags_AlwaysAutoResize))
	{
		BufferLoginPassword.resize(2048, 0x00);
		ImGui::InputText("System Password", BufferLoginPassword.data(), BufferLoginPassword.size(), ImGuiInputTextFlags_Password);
		
		AppData.ShowPPI_SelectedPasswordInstanceDescription.resize(2048, 0x00);
		ImGui::InputTextMultiline("Password Instance Description", AppData.ShowPPI_SelectedPasswordInstanceDescription.data(), AppData.ShowPPI_SelectedPasswordInstanceDescription.size(), ImVec2(400, 400), ImGuiInputTextFlags_CtrlEnterForNewLine);

		if (ImGui::Button("Hide"))
		{
			AppData.ShowPPI_FindPasswordInstanceByDescription = false;
		}

		const bool VaildPassword = VerifyPassword(BufferLoginPassword, AppData.UserKey, AppData.UserData);

		if (AppData.ShowPPI_FindPasswordInstanceByDescription && VaildPassword)
		{
			auto new_end = std::find_if
			(
				AppData.ShowPPI_SelectedPasswordInstanceDescription.rbegin(), AppData.ShowPPI_SelectedPasswordInstanceDescription.rend(), 
				[](char character)
				{
					return character != '\x00';
				}
			);

			AppData.ShowPPI_SelectedPasswordInstanceDescription.erase(new_end.base(), AppData.ShowPPI_SelectedPasswordInstanceDescription.end());

			auto Optional = AppData.PersonalPasswordInfo.FindPasswordInstanceByDescription
			(
				MakeTokenString(AppData.UserKey.RandomUUID, BufferLoginPassword),
				AppData.ShowPPI_SelectedPasswordInstanceDescription
			);

			if (Optional.has_value())
			{
				auto& Instance = Optional.value();
					
				ImGui::Text("ID: %llu", Instance.ID);
				ImGui::Text("New Description %s", Instance.Description.data());
				ImGui::Text("Decrypted Password: %s", Instance.DecryptedPassword.data());

				// 显示其他信息，如EncryptionAlgorithmNames和DecryptionAlgorithmNames
				ImGui::Text("Encryption Algorithms:");
				for (const auto& algorithm : Instance.EncryptionAlgorithmNames)
				{
					ImGui::Text("- %s", algorithm.data());
				}

				ImGui::Text("Decryption Algorithms:");
				for (const auto& algorithm : Instance.DecryptionAlgorithmNames)
				{
					ImGui::Text("- %s", algorithm.data());
				}
			}
		}

		ImGui::EndPopup();
	}
}

inline void ShowGUI_PPI_ChangeInstanceMasterKeyWithSystemPassword(std::vector<char>& BufferLoginPassword, ApplicationData& AppData)
{
	ImGui::Begin("Change Master Key With System Password");

	if (AppData.ShowPPI_ChangeInstanceMasterKeyWithSystemPassword)
	{
		BufferLoginPassword.resize(2048, 0x00);
		ImGui::InputText("System Old Password", BufferLoginPassword.data(), BufferLoginPassword.size(), ImGuiInputTextFlags_Password);
		ImGui::InputText("Confirm System Old Password", AppData.ShowPPI_Password.data(), AppData.ShowPPI_Password.size(), ImGuiInputTextFlags_Password);
		ImGui::InputText("New System Password", AppData.ShowPPI_NewPassword.data(), AppData.ShowPPI_NewPassword.size(), ImGuiInputTextFlags_Password);

		if(ImGui::Button("Change Password"))
		{
			auto new_end = std::find_if
			(
				AppData.ShowPPI_Password.rbegin(),AppData.ShowPPI_Password.rend(), 
				[](char character)
				{
					return character != '\x00';
				}
			);

			AppData.ShowPPI_Password.erase(new_end.base(), AppData.ShowPPI_Password.end());

			new_end = std::find_if
			(
				AppData.ShowPPI_NewPassword.rbegin(),AppData.ShowPPI_NewPassword.rend(), 
				[](char character)
				{
					return character != '\x00';
				}
			);

			AppData.ShowPPI_NewPassword.erase(new_end.base(), AppData.ShowPPI_NewPassword.end());

			std::string Password(BufferLoginPassword.begin(), BufferLoginPassword.end());

			new_end = std::find_if
			(
				Password.rbegin(), Password.rend(), 
				[](char character)
				{
					return character != '\x00';
				}
			);

			Password.erase(new_end.base(), Password.end());

			if(!AppData.ShowPPI_Password.empty() && !AppData.ShowPPI_NewPassword.empty())
			{
				// Verify Password
				const bool VaildPassword = VerifyPassword(BufferLoginPassword, AppData.UserKey, AppData.UserData) && std::equal(AppData.ShowPPI_Password.begin(), AppData.ShowPPI_Password.end(), Password.begin(), Password.end());
				
				const bool IsNotChangePassword = std::equal(AppData.ShowPPI_NewPassword.begin(), AppData.ShowPPI_NewPassword.end(), Password.begin(), Password.end());

				if (IsNotChangePassword)
				{
					// 密码未更改的提示框
					AppData.ShowPPI_SystemPasswordNotChange = true;
					goto Flag;
				}

				if(VaildPassword)
				{
					LoadPasswordManagerUser(AppData.UserKey, AppData.UserData);

					AppData.PersonalPasswordInfo.ChangeInstanceMasterKeyWithSystemPassword
					(
						AppData.PersonalPasswordInfoFilePath,
						AppData.UserKey.RandomUUID + AppData.ShowPPI_Password,
						AppData.UserKey.RandomUUID + AppData.ShowPPI_NewPassword
					);

					AppData.UserData.HashedPassword = PasswordAndHash(AppData.ShowPPI_NewPassword, AppData.UserKey.RandomPasswordSalt);
					SavePasswordManagerUser(std::pair<PasswordManagerUserKey, PasswordManagerUserData>{AppData.UserKey, AppData.UserData});

					// 更改密码成功的提示框
					AppData.ShowPPI_SystemPasswordChangeSuccessful = true;
					goto Flag;
				}
				else
				{
					// 更改密码失败的提示框
					AppData.ShowPPI_SystemPasswordChangeFailed = true;
					goto Flag;
				}
			}

			Flag:
			AppData.ShowPPI_Password = std::string(2048, 0x00);
			AppData.ShowPPI_NewPassword = std::string(2048, 0x00);
		}

		if (ImGui::Button("Cancel"))
		{
			AppData.ShowPPI_ChangeInstanceMasterKeyWithSystemPassword = false;
		}
	}

	ImGui::End();

	if(AppData.ShowPPI_SystemPasswordChangeSuccessful)
		ImGui::OpenPopup("Change System Password Successful");
	if (ImGui::BeginPopup("Change System Password Successful", ImGuiWindowFlags_AlwaysAutoResize))
	{
		ImGui::Text("System password has been changed successfully.");
		if (ImGui::Button("OK"))
		{
			ImGui::CloseCurrentPopup();
			AppData.ShowPPI_SystemPasswordChangeSuccessful = false;
			AppData.ShowPPI_ChangeInstanceMasterKeyWithSystemPassword = false;
		}
		ImGui::EndPopup();
	}

	if(AppData.ShowPPI_SystemPasswordNotChange)
		ImGui::OpenPopup("System Password Not Changed");
	if (ImGui::BeginPopup("System Password Not Changed", ImGuiWindowFlags_AlwaysAutoResize))
	{
		ImGui::Text("New system password should be different from the old system password.");
		if (ImGui::Button("OK"))
		{
			ImGui::CloseCurrentPopup();
			AppData.ShowPPI_SystemPasswordNotChange = false;
			AppData.ShowPPI_ChangeInstanceMasterKeyWithSystemPassword = false;
		}
		ImGui::EndPopup();
	}

	if(AppData.ShowPPI_SystemPasswordChangeFailed)
		ImGui::OpenPopup("Change System Password Failed");
	if (ImGui::BeginPopup("Change System Password Failed", ImGuiWindowFlags_AlwaysAutoResize))
	{
		ImGui::Text("The old system password you entered is incorrect.");
		if (ImGui::Button("OK"))
		{
			ImGui::CloseCurrentPopup();
			AppData.ShowPPI_SystemPasswordChangeFailed = false;
			AppData.ShowPPI_ChangeInstanceMasterKeyWithSystemPassword = false;
		}
		ImGui::EndPopup();
	}
}
