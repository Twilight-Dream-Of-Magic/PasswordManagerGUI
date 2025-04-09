#pragma once

inline void RefillData_FilePaths()
{
	if (CurrentApplicationData.UserData.PersonalPasswordInfoFileName.empty() || CurrentApplicationData.UserData.PersonalDataInfoFileName.empty())
	{
		std::string UniqueFileName                                   = GenerateStringFileUUIDFromStringUUID(CurrentApplicationData.UserKey.RandomUUID);
		CurrentApplicationData.UserData.PersonalDataInfoFileName     = "Files_" + UniqueFileName + ".json";
		CurrentApplicationData.UserData.PersonalPasswordInfoFileName = "Passwords_" + UniqueFileName + ".json";
	}

	std::filesystem::path CurrentPath = std::filesystem::current_path();

	CurrentApplicationData.PersonalPasswordInfoFilePath = CurrentPath / "PersonalPasswordData" / CurrentApplicationData.UserData.PersonalPasswordInfoFileName;
	CurrentApplicationData.PersonalDataInfoFilePath     = CurrentPath / "PersonalFileData" / CurrentApplicationData.UserData.PersonalDataInfoFileName;
}

inline void RefillData_PersonalFiles()
{
	RefillData_FilePaths();

	if (std::filesystem::exists(CurrentApplicationData.PersonalPasswordInfoFilePath))
	{
		CurrentApplicationData.PersonalPasswordInfo_.Deserialization(CurrentApplicationData.PersonalPasswordInfoFilePath);
	}
	else
	{
		if (!std::filesystem::is_directory(CurrentApplicationData.PersonalPasswordInfoFilePath.parent_path()))
		{
			std::filesystem::create_directories(CurrentApplicationData.PersonalPasswordInfoFilePath.parent_path());
		}
		CurrentApplicationData.PersonalPasswordInfo_.Serialization(CurrentApplicationData.PersonalPasswordInfoFilePath);
	}

	if (std::filesystem::exists(CurrentApplicationData.PersonalDataInfoFilePath))
	{
		CurrentApplicationData.PersonalFileInfo_.Deserialization(CurrentApplicationData.PersonalDataInfoFilePath);
	}
	else
	{
		if (!std::filesystem::is_directory(CurrentApplicationData.PersonalDataInfoFilePath.parent_path()))
		{
			std::filesystem::create_directories(CurrentApplicationData.PersonalDataInfoFilePath.parent_path());
		}
		CurrentApplicationData.PersonalFileInfo_.Serialization(CurrentApplicationData.PersonalDataInfoFilePath);
	}
}

/* Functions for Managing Personal Password Information */

inline void Do_LogoutPersonalPasswordInfo(std::vector<char> &BufferLoginPassword, ApplicationData &AppData)
{
	// Close This GUI
	CurrentApplicationData.ShowGUI_PersonalPasswordInfo = false;
	CurrentApplicationData.ShowGUI_PersonalFileInfo     = false;

	// Clear Application GUI State Data
	CurrentApplicationData.UserKey                      = PasswordManagerUserKey();
	CurrentApplicationData.UserData                     = PasswordManagerUserData();
	CurrentApplicationData.PersonalPasswordInfo_         = PersonalPasswordInfo();
	CurrentApplicationData.PersonalPasswordInfoFilePath = "";

	// Zero Bytes SystemPassword - Secure Wipe
	memory_set_no_optimize_function<0x00>(BufferLoginPassword.data(), BufferLoginPassword.size());

	// Close This All Sub GUI
	AppData.ShowPPI_CreatePasswordInstance            = false;
	AppData.ShowPPI_ChangePasswordInstance            = false;
	AppData.ShowPPI_ListAllPasswordInstance           = false;
	AppData.ShowPPI_ListAllPasswordInstanceData       = false;
	AppData.ShowPPI_DeletePasswordInstance            = false;
	AppData.ShowPPI_ConfirmDeleteAllPasswordInstance  = false;
	AppData.ShowPPI_FindPasswordInstanceByID          = false;
	AppData.ShowPPI_FindPasswordInstanceByDescription = false;
	AppData.IsPasswordInfoTemporaryValid              = false;

	AppData.ShowPFI_CreateFileInstance                 = false;
	AppData.ShowPFI_ListAllFileInstance                = false;
	AppData.ShowPFI_ListAllFileInstanceData            = false;
	AppData.ShowPFI_DeleteFileInstanceByID             = false;
	AppData.ShowPFI_ConfirmDeleteAllFileInstancesPopup = false;
	AppData.ShowPFI_EncryptFile                        = false;
	AppData.ShowPFI_DecryptFile                        = false;
	AppData.ShowPFI_EncryptFileResultPopup             = false;
	AppData.ShowPFI_DecryptFileResultPopup             = false;
	AppData.ShowPFI_SelectedFileInstanceID             = 0;
}

inline void Do_CreatePasswordInstance(std::vector<char> &BufferLoginPassword, ApplicationData &AppData)
{
	static const auto task_create_and_encrypt_password = [](ApplicationData &AppData, const std::vector<char> &BufferLoginPassword)
	{
		// Select Algorithms
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

		SetProgressTarget(AppData, 0.0f, 0.1f);

		AppData.ShowPPI_DecryptionAlgorithms.resize(AppData.ShowPPI_EncryptionAlgorithms.size(), "");
		std::reverse_copy(AppData.ShowPPI_EncryptionAlgorithms.begin(), AppData.ShowPPI_EncryptionAlgorithms.end(), AppData.ShowPPI_DecryptionAlgorithms.begin());

		SetProgressTarget(AppData, 0.1f, 0.2f);

		const bool ValidPassword = VerifyPassword(BufferLoginPassword, AppData.UserKey, AppData.UserData);

		if (!AppData.UserKey.RandomUUID.empty() && !BufferLoginPassword.empty() && !AppData.ShowPPI_NewPassword.empty() && !AppData.ShowPPI_EncryptionAlgorithms.empty()
		    && !AppData.ShowPPI_DecryptionAlgorithms.empty() && ValidPassword)
		{
			auto new_end = std::find_if(AppData.ShowPPI_NewPassword.rbegin(), AppData.ShowPPI_NewPassword.rend(), [](char character) { return character != '\x00'; });

			AppData.ShowPPI_NewPassword.erase(new_end.base(), AppData.ShowPPI_NewPassword.end());

			SetProgressTarget(AppData, 0.2f, 0.8f);

			// 调用CreatePasswordInstance函数来执行创建密码实例的操作
			auto PasswordInstance = AppData.PersonalPasswordInfo_.CreatePasswordInstance(
			    MakeTokenString(AppData.UserKey.RandomUUID, BufferLoginPassword),
			    AppData.ShowPPI_Description,
			    AppData.ShowPPI_NewPassword,
			    AppData.ShowPPI_EncryptionAlgorithms,
			    AppData.ShowPPI_DecryptionAlgorithms);
			AppData.PersonalPasswordInfo_.AppendPasswordInstance(PasswordInstance);

			SetProgressTarget(AppData, 0.9f, 0.95f);

			AppData.PersonalPasswordInfo_.Serialization(AppData.PersonalPasswordInfoFilePath);

			// AppData.ShowPPI_CreatePasswordInstance = false;
			AppData.IsPasswordInfoTemporaryValid = false;
		}

		SetProgressTarget(AppData, 0.95f, 1.0f);

		// Clear Application GUI State Data
		AppData.ShowPPI_NewPassword = std::string(2048, 0x00);
		AppData.ShowPPI_Description = std::string(2048, 0x00);
		AppData.ShowPPI_EncryptionAlgorithms.clear();
		AppData.ShowPPI_DecryptionAlgorithms.clear();
	};

	static const auto async_task = [](ApplicationData &AppData, const std::vector<char> &BufferLoginPassword, const std::source_location &loc)
	{ DropIfBusy(AppData.TaskInProgress, loc, task_create_and_encrypt_password, std::ref(AppData), std::cref(BufferLoginPassword)); };

	if (!AppData.TaskInProgress)
	{
		std::scoped_lock lock(CurrentApplicationData.mutex_task);
		CurrentApplicationData.current_task = std::bind(async_task, std::ref(AppData), std::cref(BufferLoginPassword), std::source_location::current());
	}
}

inline void Do_ChangePasswordInstance(std::vector<char> &BufferLoginPassword, ApplicationData &AppData)
{
	static const auto task_change_pwd_ins = [](ApplicationData &AppData, const std::vector<char> &BufferLoginPassword)
	{
		if (AppData.ShowPPI_ChangeEncryptedPassword)
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

		SetProgressTarget(AppData, 0.1f, 0.2);

		const bool ValidPassword = VerifyPassword(BufferLoginPassword, AppData.UserKey, AppData.UserData);

		if (!AppData.UserKey.RandomUUID.empty() && !BufferLoginPassword.empty() && !AppData.ShowPPI_Password.empty() && !AppData.ShowPPI_EncryptionAlgorithms.empty()
		    && !AppData.ShowPPI_DecryptionAlgorithms.empty() && ValidPassword)
		{
			SetProgressTarget(AppData, 0.2f, 0.3f);

			auto new_end = std::find_if(AppData.ShowPPI_Password.rbegin(), AppData.ShowPPI_Password.rend(), [](char character) { return character != '\x00'; });

			AppData.ShowPPI_Password.erase(new_end.base(), AppData.ShowPPI_Password.end());

			new_end = std::find_if(AppData.ShowPPI_Description.rbegin(), AppData.ShowPPI_Description.rend(), [](char character) { return character != '\x00'; });

			AppData.ShowPPI_Description.erase(new_end.base(), AppData.ShowPPI_Description.end());

			SetProgressTarget(AppData, 0.3f, 0.8f);

			// 调用ChangePasswordInstance函数来执行更改密码实例的操作
			bool IsChanged = AppData.PersonalPasswordInfo_.ChangePasswordInstance(
			    AppData.ShowPPI_SelectedPasswordInstanceID,
			    AppData.ShowPPI_Description,
			    AppData.ShowPPI_Password,
			    AppData.ShowPPI_EncryptionAlgorithms,
			    AppData.ShowPPI_DecryptionAlgorithms,
			    MakeTokenString(AppData.UserKey.RandomUUID, BufferLoginPassword),
			    AppData.ShowPPI_ChangeEncryptedPassword);

			SetProgressTarget(AppData, 0.8f, 0.9f);

			if (IsChanged)
			{
				// 更改成功的处理逻辑
				AppData.PersonalPasswordInfo_.Serialization(AppData.PersonalPasswordInfoFilePath);
				AppData.IsPasswordInfoTemporaryValid             = false;
				AppData.ShowPPI_ChangePasswordInstanceSuccessful = true;

				// Clear Application GUI State Data
				AppData.ShowPPI_Password    = std::string(2048, 0x00);
				AppData.ShowPPI_Description = std::string(2048, 0x00);
				AppData.ShowPPI_EncryptionAlgorithms.clear();
				AppData.ShowPPI_DecryptionAlgorithms.clear();
			}
			else
			{
				// 更改失败的处理逻辑

				AppData.ShowPPI_ChangePasswordInstanceFailed = true;

				// Clear Application GUI State Data
				AppData.ShowPPI_Password    = std::string(2048, 0x00);
				AppData.ShowPPI_Description = std::string(2048, 0x00);
				AppData.ShowPPI_EncryptionAlgorithms.clear();
				AppData.ShowPPI_DecryptionAlgorithms.clear();
			}

			SetProgressTarget(AppData, 0.9f, 1.0f);
		}
	};

	static const auto async_task = [](ApplicationData &AppData, const std::vector<char> &BufferLoginPassword, const std::source_location &loc)
	{ DropIfBusy(AppData.TaskInProgress, loc, task_change_pwd_ins, std::ref(AppData), std::cref(BufferLoginPassword)); };

	if (!AppData.TaskInProgress)
	{
		std::scoped_lock lock(CurrentApplicationData.mutex_task);
		CurrentApplicationData.current_task = std::bind(async_task, std::ref(AppData), std::cref(BufferLoginPassword), std::source_location::current());
	}
}

inline void Do_DecryptionAllPasswordInstance(std::vector<char> &BufferLoginPassword, ApplicationData &AppData)
{
	static const auto task_list_all_pwd_ins = [](ApplicationData &AppData, const std::vector<char> &BufferLoginPassword)
	{
		AppData.PersonalPasswordInfo_.Deserialization(AppData.PersonalPasswordInfoFilePath);

		SetProgressTarget(AppData, 0.1f, 0.95f);

		// 调用ListAllPasswordInstance函数来执行列出密码实例的操作
		AppData.PersonalPasswordInfo_.ListAllPasswordInstance(MakeTokenString(AppData.UserKey.RandomUUID, BufferLoginPassword));

		SetProgressTarget(AppData, 0.95f, 1.0f);
	};

	static const auto async_task = [](ApplicationData &AppData, const std::vector<char> &BufferLoginPassword, const std::source_location &loc)
	{ DropIfBusy(AppData.TaskInProgress, loc, task_list_all_pwd_ins, std::ref(AppData), std::cref(BufferLoginPassword)); };

	if (!AppData.TaskInProgress)
	{
		std::scoped_lock lock(CurrentApplicationData.mutex_task);
		CurrentApplicationData.current_task = std::bind(async_task, std::ref(AppData), std::cref(BufferLoginPassword), std::source_location::current());
	}
}

inline void Do_FindPasswordInstanceByID(std::vector<char> &BufferLoginPassword, ApplicationData &AppData)
{
	static const auto task_find_pwd_ins_by_id = [](ApplicationData &AppData, const std::vector<char> &BufferLoginPassword)
	{
		SetProgressTarget(AppData, 0.0f, 0.2f);
		auto &buffer = AppData.BUFFER_ShowGUI_PPI_FindPasswordInstanceByID;

		auto Optional
		    = AppData.PersonalPasswordInfo_.FindPasswordInstanceByID(MakeTokenString(AppData.UserKey.RandomUUID, BufferLoginPassword), AppData.ShowPPI_SelectedPasswordInstanceID);

		SetProgressTarget(AppData, 0.2f, 0.4f);

		if (Optional.has_value())
		{
			auto &Instance = Optional.value();
			auto  it       = std::format_to(
                buffer.begin(),
                "ID: {0}\nNew Description {1}\nDecrypted Password: {2}\nEncryption Algorithms:\n",
                Instance.ID,
                Instance.Description.data(),
                Instance.DecryptedPassword.data());

			SetProgressTarget(AppData, 0.4f, 0.6f);

			for (const auto &algorithm : Instance.EncryptionAlgorithmNames)
			{
				it = std::format_to(it, "- {}\n", algorithm.data());
			}

			SetProgressTarget(AppData, 0.6f, 0.8f);

			it = std::format_to(it, "Decryption Algorithms:\n");

			for (const auto &algorithm : Instance.DecryptionAlgorithmNames)
			{
				it = std::format_to(it, "- {}\n", algorithm.data());
			}

			SetProgressTarget(AppData, 0.8f, 0.9f);
		}
		else
		{
			std::fill(buffer.begin(), buffer.end(), 0x00);
			std::format_to(buffer.begin(), "No suitable ID found.");
		}

		SetProgressTarget(AppData, 0.9f, 1.0f);
	};

	static const auto async_task = [](ApplicationData &AppData, const std::vector<char> &BufferLoginPassword, const std::source_location &loc)
	{ DropIfBusy(AppData.TaskInProgress, loc, task_find_pwd_ins_by_id, std::ref(AppData), std::cref(BufferLoginPassword)); };

	if (!AppData.TaskInProgress)
	{
		std::scoped_lock lock(CurrentApplicationData.mutex_task);
		CurrentApplicationData.current_task = std::bind(async_task, std::ref(AppData), std::cref(BufferLoginPassword), std::source_location::current());
	}
}

inline void Do_FindPasswordInstanceByDescription(std::vector<char> &BufferLoginPassword, ApplicationData &AppData)
{
	static const auto task_find_pwd_ins_by_desc = [](ApplicationData &AppData, const std::vector<char> &BufferLoginPassword)
	{
		SetProgressTarget(AppData, 0.0f, 0.8f);
		auto &buffer = AppData.BUFFER_ShowGUI_PPI_FindPasswordInstanceByDescription;

		auto new_end = std::find_if(
		    AppData.ShowPPI_SelectedPasswordInstanceDescription.rbegin(),
		    AppData.ShowPPI_SelectedPasswordInstanceDescription.rend(),
		    [](char character) { return character != '\x00'; });

		AppData.ShowPPI_SelectedPasswordInstanceDescription.erase(new_end.base(), AppData.ShowPPI_SelectedPasswordInstanceDescription.end());

		auto Optional = AppData.PersonalPasswordInfo_.FindPasswordInstanceByDescription(
		    MakeTokenString(AppData.UserKey.RandomUUID, BufferLoginPassword),
		    AppData.ShowPPI_SelectedPasswordInstanceDescription);

		SetProgressTarget(AppData, 0.8f, 0.9f);

		if (Optional.has_value())
		{
			auto &Instance = Optional.value();

			auto it = std::format_to(
			    buffer.begin(),
			    "ID: {0}\nNew Description {1}\nDecrypted Password: {2}\n"
			    "Encryption Algorithms:\n",
			    Instance.ID,
			    Instance.Description.data(),
			    Instance.DecryptedPassword.data());

			for (const auto &algorithm : Instance.EncryptionAlgorithmNames)
			{
				it = std::format_to(it, "- {}\n", algorithm.data());
			}

			it = std::format_to(it, "Decryption Algorithms:\n");

			for (const auto &algorithm : Instance.DecryptionAlgorithmNames)
			{
				it = std::format_to(it, "- {}\n", algorithm.data());
			}
		}
		else
		{
			std::fill(buffer.begin(), buffer.end(), 0x00);
			std::format_to(buffer.begin(), "No suitable Description found.");
		}
		SetProgressTarget(AppData, 0.9f, 1.0f);
	};

	static const auto async_task = [](ApplicationData &AppData, const std::vector<char> &BufferLoginPassword, const std::source_location &loc)
	{ DropIfBusy(AppData.TaskInProgress, loc, task_find_pwd_ins_by_desc, std::ref(AppData), std::cref(BufferLoginPassword)); };

	if (!AppData.TaskInProgress)
	{
		std::scoped_lock lock(CurrentApplicationData.mutex_task);
		CurrentApplicationData.current_task = std::bind(async_task, std::ref(AppData), std::cref(BufferLoginPassword), std::source_location::current());
	}
}

inline void Do_ChangeInstanceMasterKeyWithSystemPassword(std::vector<char> &BufferLoginPassword, ApplicationData &AppData)
{
	static const auto task_change_ins_mst_key_wth_sys_pwd = [](ApplicationData &AppData, const std::vector<char> &BufferLoginPassword)
	{
		auto new_end = std::find_if(AppData.ShowPPI_Password.rbegin(), AppData.ShowPPI_Password.rend(), [](char character) { return character != '\x00'; });

		AppData.ShowPPI_Password.erase(new_end.base(), AppData.ShowPPI_Password.end());

		new_end = std::find_if(AppData.ShowPPI_NewPassword.rbegin(), AppData.ShowPPI_NewPassword.rend(), [](char character) { return character != '\x00'; });

		AppData.ShowPPI_NewPassword.erase(new_end.base(), AppData.ShowPPI_NewPassword.end());

		SetProgressTarget(AppData, 0.2f, 0.4f);

		std::string Password(BufferLoginPassword.begin(), BufferLoginPassword.end());

		new_end = std::find_if(Password.rbegin(), Password.rend(), [](char character) { return character != '\x00'; });

		Password.erase(new_end.base(), Password.end());

		SetProgressTarget(AppData, 0.4f, 0.6f);

		auto SG = MakeScopeGuard(
		    [](ApplicationData &AppData, char ch, size_t size = 2048) // 2028是默认值所以可以不传
		    {
			    AppData.ShowPPI_Password    = std::string(size, ch);
			    AppData.ShowPPI_NewPassword = std::string(size, ch);
		    },
		    std::ref(AppData), // 注意，这里传ref，因为上面要&
		    static_cast<char>(0x00));

		if (!AppData.ShowPPI_Password.empty() && !AppData.ShowPPI_NewPassword.empty())
		{
			// Verify Password
			const bool ValidPassword = VerifyPassword(BufferLoginPassword, AppData.UserKey, AppData.UserData)
			                           && std::equal(AppData.ShowPPI_Password.begin(), AppData.ShowPPI_Password.end(), Password.begin(), Password.end());

			const bool IsNotChangePassword = std::equal(AppData.ShowPPI_NewPassword.begin(), AppData.ShowPPI_NewPassword.end(), Password.begin(), Password.end());

			SetProgressTarget(AppData, 0.6f, 0.7f);

			if (IsNotChangePassword)
			{
				// 密码未更改的提示框
				AppData.ShowPPI_SystemPasswordNotChange = true;
				return;
			}

			if (ValidPassword)
			{
				LoadPasswordManagerUser(AppData.UserKey, AppData.UserData);

				SetProgressTarget(AppData, 0.7f, 0.8f);

				AppData.PersonalPasswordInfo_.ChangeInstanceMasterKeyWithSystemPassword(
				    AppData.PersonalPasswordInfoFilePath,
				    AppData.UserKey.RandomUUID + AppData.ShowPPI_Password,
				    AppData.UserKey.RandomUUID + AppData.ShowPPI_NewPassword);

				SetProgressTarget(AppData, 0.8f, 0.9f);

				AppData.UserData.HashedPassword = PasswordAndHash(AppData.ShowPPI_NewPassword, AppData.UserKey.RandomPasswordSalt);

				SetProgressTarget(AppData, 0.9f, .95f);

				SavePasswordManagerUser(std::pair<PasswordManagerUserKey, PasswordManagerUserData>{AppData.UserKey, AppData.UserData});

				// 更改密码成功的提示框
				AppData.ShowPPI_SystemPasswordChangeSuccessful = true;
			}
			else
			{
				// 更改密码失败的提示框
				AppData.ShowPPI_SystemPasswordChangeFailed = true;
			}

			SetProgressTarget(AppData, 0.95f, 1.0f);
		}
	};

	static const auto async_task = [](ApplicationData &AppData, const std::vector<char> &BufferLoginPassword, const std::source_location &loc)
	{ DropIfBusy(AppData.TaskInProgress, loc, task_change_ins_mst_key_wth_sys_pwd, std::ref(AppData), std::cref(BufferLoginPassword)); };

	if (!AppData.TaskInProgress)
	{
		std::scoped_lock lock(CurrentApplicationData.mutex_task);
		CurrentApplicationData.current_task = std::bind(async_task, std::ref(AppData), std::cref(BufferLoginPassword), std::source_location::current());
	}
}

inline void Do_Login(
    std::vector<char> &BufferLoginUsername,
    std::vector<char> &BufferLoginPassword,
    bool              &ShowInvalidCurrentUUIDFilePopup,
    bool              &ShowUsernameAuthenticationFailedPopup,
    bool              &ShowPasswordAuthenticationFailedPopup,
    bool              &ShowLoadUserFailedPopup)
{
	PasswordManagerUserKey  CurrentUserKey{};
	PasswordManagerUserData CurrentUserData{};

	auto new_end = std::find_if(BufferLoginUsername.rbegin(), BufferLoginUsername.rend(), [](char character) { return character != '\x00'; });

	BufferLoginUsername.erase(new_end.base(), BufferLoginUsername.end());

	new_end = std::find_if(BufferLoginPassword.rbegin(), BufferLoginPassword.rend(), [](char character) { return character != '\x00'; });

	BufferLoginPassword.erase(new_end.base(), BufferLoginPassword.end());

	// Use the "current_uuid.json" file to load the UUID and RandomSalt for logins
	if (LoadPasswordManagerUUID(CurrentUserKey))
	{
		if (CurrentUserKey.RandomSalt.empty() && CurrentUserKey.RandomPasswordSalt.empty() && CurrentUserKey.RegistrationTime == 0)
		{
			Logger::Instance().Warning().Log("Login failed because the UUID of the contents of the 'current_uuid.json' file is invalid!");
			ShowInvalidCurrentUUIDFilePopup = true;

			return;
		}

		// Loading usernames and hashed passwords with UUID
		LoadPasswordManagerUser(CurrentUserKey, CurrentUserData);

		// Verify Username and Password
		const bool ValidUsername = VerifyUUID(BufferLoginUsername, CurrentUserKey.RandomSalt, CurrentUserKey.RegistrationTime, CurrentUserKey);
		const bool ValidPassword = VerifyPassword(BufferLoginPassword, CurrentUserKey, CurrentUserData);

		if (ValidUsername && ValidPassword)
		{
			// Login successful
			Logger::Instance().Notice().Log("Login successful!");

			if (CurrentUserData.IsFirstLogin)
			{
				FirstLoginLogic(BufferLoginPassword, CurrentUserKey, CurrentUserData);
			}

			// Change Application Data
			CurrentApplicationData.UserKey  = CurrentUserKey;
			CurrentApplicationData.UserData = CurrentUserData;

			RefillData_PersonalFiles();

			CurrentApplicationData.ShowGUI_PersonalPasswordInfo = true;

			CurrentApplicationData.ShowPPI_CreatePasswordInstance = true;
			CurrentApplicationData.ShowPPI_ChangePasswordInstance = true;

			CurrentApplicationData.ShowGUI_PersonalFileInfo = true;
			CurrentApplicationData.IsUserLogin              = true;
		}
		else
		{
			if (ValidUsername == false && ValidPassword == true)
			{
				Logger::Instance().Warning().Log("Failed to login, incorrect username by UUID checking");

				// Username validation failed
				ShowUsernameAuthenticationFailedPopup = true;
			}
			else if (ValidUsername == true && ValidPassword == false)
			{
				Logger::Instance().Warning().Log("Failed to login, incorrect password by security comparison");

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

	// Clear Application GUI State Data
	// BufferLoginUsername = std::vector<char>(2048, 0x00);
	// BufferLoginPassword = std::vector<char>(2048, 0x00);
	// std::fill(BufferLoginUsername.begin(), BufferLoginUsername.end(), 0x00);
	std::fill(BufferLoginPassword.begin(), BufferLoginPassword.end(), 0x00);
}
