#pragma once

#include "CodeCore/application_functional.hpp"

struct ApplicationData
{
	bool ShowGUI_PersonalPasswordInfo = false;
	bool ShowGUI_PersonalFileInfo = false;

	/* About PersonalPasswordInfo GUI Data */

	bool ShowPPI_CreatePasswordInstance = false;

	bool ShowPPI_ChangePasswordInstance = false;
	bool ShowPPI_ChangePasswordInstanceSuccessful = false;
	bool ShowPPI_ChangePasswordInstanceFailed = false;

	bool ShowPPI_ListAllPasswordInstance = false;
	bool ShowPPI_ListAllPasswordInstanceData = false;

	bool ShowPPI_DeletePasswordInstance = false;
	bool ShowPPI_ConfirmDeleteAllPasswordInstance = false;
	bool ShowPPI_FindPasswordInstanceByID = false;
	bool ShowPPI_FindPasswordInstanceByDescription = false;
	bool ShowPPI_ChangeInstanceMasterKeyWithSystemPassword = false;
	bool ShowPPI_SystemPasswordChangeSuccessful = false;
	bool ShowPPI_SystemPasswordNotChange = false;
	bool ShowPPI_SystemPasswordChangeFailed = false;

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

	/* About PersonalFileInfo GUI Data */

	bool ShowPFI_NeedAES = false;
	bool ShowPFI_NeedRC6 = false;
	bool ShowPFI_NeedSM4 = false;
	bool ShowPFI_NeedTwofish = false;
	bool ShowPFI_NeedSerpent = false;

	bool ShowPFI_CreateFileInstance = false;

	bool ShowPFI_ListAllFileInstance = false;
	bool ShowPFI_ListAllFileInstanceData = false;

	bool ShowPFI_DeleteFileInstanceByID = false;
	bool ShowPFI_ConfirmDeleteAllFileInstancesPopup = false;

	bool ShowPFI_EncryptFile = false;
	bool ShowPFI_DecryptFile = false;

	bool ShowPFI_EncryptFileResultPopup = false;
	bool ShowPFI_DecryptFileResultPopup = false;

	std::uint64_t ShowPFI_SelectedFileInstanceID = 0;
	std::vector<std::string> ShowPFI_EncryptionAlgorithms;
	std::vector<std::string> ShowPFI_DecryptionAlgorithms;

	/* About PasswordManager Data */

	PasswordManagerUserKey UserKey;
	PasswordManagerUserData UserData;

	PersonalPasswordInfo PersonalPasswordInfo;
	std::filesystem::path PersonalPasswordInfoFilePath;

	PersonalFileInfo PersonalFileInfo;
	std::filesystem::path PersonalDataInfoFilePath;

	bool IsSourceFileSelected = false;
	std::filesystem::path SourceFilePath;
	bool IsEncryptedFileSelected = false;
	std::filesystem::path EncryptedFilePath;
	bool IsDecryptedFileSelected = false;
	std::filesystem::path DecryptedFilePath;

	/* Atomic flag indicating if any background task is currently running */
	std::atomic_bool TaskInProgress = false;

	bool IsPasswordInfoTemporaryValid = false;
	float progress = 0.0f;
};

//global object
ApplicationData CurrentApplicationData;

inline void RefillData_FilePaths()
{
	if ( CurrentApplicationData.UserData.PersonalPasswordInfoFileName.empty() || CurrentApplicationData.UserData.PersonalDataInfoFileName.empty() )
	{
		std::string UniqueFileName = GenerateStringFileUUIDFromStringUUID( CurrentApplicationData.UserKey.RandomUUID );
		CurrentApplicationData.UserData.PersonalDataInfoFileName = "Files_" + UniqueFileName + ".json";
		CurrentApplicationData.UserData.PersonalPasswordInfoFileName = "Passwords_" + UniqueFileName + ".json";
	}

	std::filesystem::path CurrentPath = std::filesystem::current_path();

	CurrentApplicationData.PersonalPasswordInfoFilePath = CurrentPath / "PersonalPasswordData" / CurrentApplicationData.UserData.PersonalPasswordInfoFileName;
	CurrentApplicationData.PersonalDataInfoFilePath = CurrentPath / "PersonalFileData" / CurrentApplicationData.UserData.PersonalDataInfoFileName;
}

inline void RefillData_PersonalFiles()
{
	RefillData_FilePaths();

	if ( std::filesystem::exists( CurrentApplicationData.PersonalPasswordInfoFilePath ) )
	{
		CurrentApplicationData.PersonalPasswordInfo.Deserialization( CurrentApplicationData.PersonalPasswordInfoFilePath );
	}
	else
	{
		if ( !std::filesystem::is_directory( CurrentApplicationData.PersonalPasswordInfoFilePath.parent_path() ) )
		{
			std::filesystem::create_directories( CurrentApplicationData.PersonalPasswordInfoFilePath.parent_path() );
		}
		CurrentApplicationData.PersonalPasswordInfo.Serialization( CurrentApplicationData.PersonalPasswordInfoFilePath );
	}

	if ( std::filesystem::exists( CurrentApplicationData.PersonalDataInfoFilePath ) )
	{
		CurrentApplicationData.PersonalFileInfo.Deserialization( CurrentApplicationData.PersonalDataInfoFilePath );
	}
	else
	{
		if ( !std::filesystem::is_directory( CurrentApplicationData.PersonalDataInfoFilePath.parent_path() ) )
		{
			std::filesystem::create_directories( CurrentApplicationData.PersonalDataInfoFilePath.parent_path() );
		}
		CurrentApplicationData.PersonalFileInfo.Serialization( CurrentApplicationData.PersonalDataInfoFilePath );
	}
}

template<typename F, typename... Args> requires	std::invocable<F, Args...>
void AsyncTask(std::atomic_bool& busy_flag, F task, Args&&... args)
{
	bool expected = false;

	if (!busy_flag.compare_exchange_strong(expected, true))
	{
		LogWarnHelper("Task {} is already running, skipping...", std::make_tuple(typeid(task).name()));
		return;
	}

	auto SG = MakeScopeGuard
	(
		[](std::atomic_bool& flag)
		{
			flag.store(false);
		},
		std::ref(busy_flag)
	);

	// todo: 更好的函数log信息	
	LogNoticeHelper("Task {} is running...", std::make_tuple(typeid(task).name()));
	try
	{
		task(std::forward<Args>(args)...);
	}
	catch (const std::exception& e)
	{
		LogErrorHelper("Error in {}: {}", std::make_tuple(typeid(task).name(),e.what()));
	}
	catch (...)
	{
		LogErrorHelper("Unknown exception in {}", std::make_tuple(typeid(task).name()));
	}
};

/* Functions for Managing Personal Password Information */
inline void Do_LogoutPersonalPasswordInfo(std::vector<char>& BufferLoginPassword, ApplicationData& AppData)
{
	//Close This GUI
	CurrentApplicationData.ShowGUI_PersonalPasswordInfo = false;
	CurrentApplicationData.ShowGUI_PersonalFileInfo = false;

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
	AppData.IsPasswordInfoTemporaryValid = false;

	AppData.ShowPFI_CreateFileInstance = false;
	AppData.ShowPFI_ListAllFileInstance = false;
	AppData.ShowPFI_ListAllFileInstanceData = false;
	AppData.ShowPFI_DeleteFileInstanceByID = false;
	AppData.ShowPFI_ConfirmDeleteAllFileInstancesPopup = false;
	AppData.ShowPFI_EncryptFile = false;
	AppData.ShowPFI_DecryptFile = false;
	AppData.ShowPFI_EncryptFileResultPopup = false;
	AppData.ShowPFI_DecryptFileResultPopup = false;
	AppData.ShowPFI_SelectedFileInstanceID = 0;
}

inline void Do_CreatePasswordInstance(std::vector<char>& BufferLoginPassword, ApplicationData& AppData)
{
	static const auto task_create_and_encrypt_password = [](ApplicationData& AppData, const std::vector<char>& BufferLoginPassword)
	{
		//Select Algorithms
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

		CurrentApplicationData.progress = 0.2f;

		AppData.ShowPPI_DecryptionAlgorithms.resize(AppData.ShowPPI_EncryptionAlgorithms.size(), "");
		std::reverse_copy
		(
			AppData.ShowPPI_EncryptionAlgorithms.begin(), AppData.ShowPPI_EncryptionAlgorithms.end(),
			AppData.ShowPPI_DecryptionAlgorithms.begin()
		);

		CurrentApplicationData.progress = 0.4f;

		const bool ValidPassword = VerifyPassword(BufferLoginPassword, AppData.UserKey, AppData.UserData);

		if
		(
			!AppData.UserKey.RandomUUID.empty() && !BufferLoginPassword.empty() &&
			!AppData.ShowPPI_NewPassword.empty() && !AppData.ShowPPI_EncryptionAlgorithms.empty() &&
			!AppData.ShowPPI_DecryptionAlgorithms.empty() && ValidPassword
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

			CurrentApplicationData.progress = 0.6f;

			// 调用CreatePasswordInstance函数来执行创建密码实例的操作
			auto PasswordInstance = AppData.PersonalPasswordInfo.CreatePasswordInstance
			(
				MakeTokenString(AppData.UserKey.RandomUUID, BufferLoginPassword),
				AppData.ShowPPI_Description, AppData.ShowPPI_NewPassword,
				AppData.ShowPPI_EncryptionAlgorithms,
				AppData.ShowPPI_DecryptionAlgorithms
			);
			AppData.PersonalPasswordInfo.AppendPasswordInstance(PasswordInstance);

			CurrentApplicationData.progress = 0.8f;

			AppData.PersonalPasswordInfo.Serialization(AppData.PersonalPasswordInfoFilePath);

			//AppData.ShowPPI_CreatePasswordInstance = false;
			AppData.IsPasswordInfoTemporaryValid = false;
		}

		CurrentApplicationData.progress = 1.0f;

		//Clear Application GUI State Data
		AppData.ShowPPI_NewPassword = std::string(2048, 0x00);
		AppData.ShowPPI_Description = std::string(2048, 0x00);
		AppData.ShowPPI_EncryptionAlgorithms.clear();
		AppData.ShowPPI_DecryptionAlgorithms.clear();
	};

	static const auto async_task = [](ApplicationData& AppData, const std::vector<char>& BufferLoginPassword)
	{
		AsyncTask(AppData.TaskInProgress, task_create_and_encrypt_password, std::ref(AppData), std::cref(BufferLoginPassword));
	};

	if (!AppData.TaskInProgress)
	{
		std::thread(async_task, std::ref(AppData), std::cref(BufferLoginPassword)).detach();
	}
}

inline void Do_ChangePasswordInstance(std::vector<char>& BufferLoginPassword, ApplicationData& AppData)
{
	static const auto task_change_pwd_ins = [](ApplicationData& AppData, const std::vector<char>& BufferLoginPassword)
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
			std::reverse_copy
			(
				AppData.ShowPPI_EncryptionAlgorithms.begin(), AppData.ShowPPI_EncryptionAlgorithms.end(),
				AppData.ShowPPI_DecryptionAlgorithms.begin()
			);
		}

		CurrentApplicationData.progress = 0.2f;

		const bool ValidPassword = VerifyPassword(BufferLoginPassword, AppData.UserKey, AppData.UserData);

		if
			(
				!AppData.UserKey.RandomUUID.empty() && !BufferLoginPassword.empty() &&
				!AppData.ShowPPI_Password.empty() && !AppData.ShowPPI_EncryptionAlgorithms.empty() &&
				!AppData.ShowPPI_DecryptionAlgorithms.empty() && ValidPassword
				)
		{
			CurrentApplicationData.progress = 0.4f;

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

			CurrentApplicationData.progress = 0.6f;

			// 调用ChangePasswordInstance函数来执行更改密码实例的操作
			bool IsChanged = AppData.PersonalPasswordInfo.ChangePasswordInstance
			(
				AppData.ShowPPI_SelectedPasswordInstanceID, AppData.ShowPPI_Description, AppData.ShowPPI_Password,
				AppData.ShowPPI_EncryptionAlgorithms, AppData.ShowPPI_DecryptionAlgorithms,
				MakeTokenString(AppData.UserKey.RandomUUID, BufferLoginPassword), AppData.ShowPPI_ChangeEncryptedPassword
			);

			CurrentApplicationData.progress = 0.8f;

			if (IsChanged)
			{
				// 更改成功的处理逻辑
				AppData.PersonalPasswordInfo.Serialization(AppData.PersonalPasswordInfoFilePath);
				AppData.IsPasswordInfoTemporaryValid = false;
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

			CurrentApplicationData.progress = 1.0f;
		}
	};

	static const auto async_task = [](ApplicationData& AppData, const std::vector<char>& BufferLoginPassword)
	{
		AsyncTask(AppData.TaskInProgress, task_change_pwd_ins, std::ref(AppData), std::cref(BufferLoginPassword));
	};

	if (!AppData.TaskInProgress)
	{
		std::thread(async_task, std::ref(AppData), std::cref(BufferLoginPassword)).detach();
	}
}

inline void Do_DecryptionAllPasswordInstance(std::vector<char>& BufferLoginPassword, ApplicationData& AppData)
{
	static const auto task_list_all_pwd_ins = [](ApplicationData& AppData, const std::vector<char>& BufferLoginPassword)
	{
		AppData.PersonalPasswordInfo.Deserialization(AppData.PersonalPasswordInfoFilePath);

		CurrentApplicationData.progress = 0.5f;

		// 调用ListAllPasswordInstance函数来执行列出密码实例的操作
		AppData.PersonalPasswordInfo.ListAllPasswordInstance
		(
			MakeTokenString(AppData.UserKey.RandomUUID, BufferLoginPassword)
		);

		CurrentApplicationData.progress = 1.0f;
	};

	static const auto async_task = [](ApplicationData& AppData, const std::vector<char>& BufferLoginPassword)
	{
		AsyncTask(AppData.TaskInProgress, task_list_all_pwd_ins, std::ref(AppData), std::cref(BufferLoginPassword));
	};

	if (!AppData.TaskInProgress)
	{
		std::thread(async_task, std::ref(AppData), std::cref(BufferLoginPassword)).detach();
	}
}

inline void Do_FindPasswordInstanceByID(std::vector<char>& BufferLoginPassword, ApplicationData& AppData, std::string& buffer)
{
	static const auto task_find_pwd_ins_by_id = [](ApplicationData& AppData, const std::vector<char>& BufferLoginPassword, std::string& buffer)
	{
		auto Optional = AppData.PersonalPasswordInfo.FindPasswordInstanceByID
		(
			MakeTokenString(AppData.UserKey.RandomUUID, BufferLoginPassword),
			AppData.ShowPPI_SelectedPasswordInstanceID
		);

		CurrentApplicationData.progress = 0.2f;

		if (Optional.has_value())
		{
			auto& Instance = Optional.value();
			std::ostringstream oss;
			oss << std::format("ID: %llu {}\nNew Description {}\nDecrypted Password: {}\n", Instance.ID, Instance.Description.data(), Instance.DecryptedPassword.data());

			CurrentApplicationData.progress = 0.4f;

			oss << "Encryption Algorithms:\n";
			for (const auto& algorithm : Instance.EncryptionAlgorithmNames)
			{
				oss << std::format("- {}\n", algorithm.data());
			}

			CurrentApplicationData.progress = 0.6f;

			oss << "Decryption Algorithms:\n";
			for (const auto& algorithm : Instance.DecryptionAlgorithmNames)
			{
				oss << std::format("- {}\n", algorithm.data());
			}
			buffer = oss.str();

			CurrentApplicationData.progress = 0.8f;
		}
		else
		{
			buffer = "No suitable ID found.";
		}

		CurrentApplicationData.progress = 1.0f;
	};

	static const auto async_task = [](ApplicationData& AppData, const std::vector<char>& BufferLoginPassword, std::string& buffer)
	{
		AsyncTask(AppData.TaskInProgress, task_find_pwd_ins_by_id, std::ref(AppData), std::cref(BufferLoginPassword), std::ref(buffer));
	};

	if (!AppData.TaskInProgress)
	{
		std::thread(async_task, std::ref(AppData), std::cref(BufferLoginPassword), std::ref(buffer)).detach();
	}
}

inline void Do_FindPasswordInstanceByDescription(std::vector<char>& BufferLoginPassword, ApplicationData& AppData, std::string& buffer)
{
	static const auto task_find_pwd_ins_by_desc = [](ApplicationData& AppData, const std::vector<char>& BufferLoginPassword, std::string& buffer)
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
			std::ostringstream oss;
			oss << std::format("ID: %llu {}\nNew Description {}\nDecrypted Password: {}\n", Instance.ID, Instance.Description.data(), Instance.DecryptedPassword.data());
			oss << "Encryption Algorithms:\n";
			for (const auto& algorithm : Instance.EncryptionAlgorithmNames)
			{
				oss << std::format("- {}\n", algorithm.data());
			}
			oss << "Decryption Algorithms:\n";
			for (const auto& algorithm : Instance.DecryptionAlgorithmNames)
			{
				oss << std::format("- {}\n", algorithm.data());
			}
			buffer = oss.str();
		}
		else
		{
			buffer = "No suitable Description found.";
		}
	};

	static const auto async_task = [](ApplicationData& AppData, const std::vector<char>& BufferLoginPassword, std::string& buffer)
	{
		AsyncTask(AppData.TaskInProgress, task_find_pwd_ins_by_desc, std::ref(AppData), std::cref(BufferLoginPassword), std::ref(buffer));
	};

	if (!AppData.TaskInProgress)
	{
		std::thread(async_task, std::ref(AppData), std::cref(BufferLoginPassword), std::ref(buffer)).detach();
	}
}

inline void Do_ChangeInstanceMasterKeyWithSystemPassword(std::vector<char>& BufferLoginPassword, ApplicationData& AppData)
{
	static const auto task_change_ins_mst_key_wth_sys_pwd = [](ApplicationData& AppData, const std::vector<char>& BufferLoginPassword)
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
			AppData.ShowPPI_NewPassword.rbegin(), AppData.ShowPPI_NewPassword.rend(),
			[](char character)
			{
				return character != '\x00';
			}
		);

		AppData.ShowPPI_NewPassword.erase(new_end.base(), AppData.ShowPPI_NewPassword.end());

		CurrentApplicationData.progress = 0.2f;

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

		CurrentApplicationData.progress = 0.4f;

		auto SG = MakeScopeGuard
		(
			[](ApplicationData& AppData, char ch, size_t size = 2048) //2028是默认值所以可以不传
			{
				AppData.ShowPPI_Password = std::string(size, ch);
				AppData.ShowPPI_NewPassword = std::string(size, ch);
			},
			std::ref(AppData),  //注意，这里传ref，因为上面要&
			static_cast<char>(0x00)
		);

		if (!AppData.ShowPPI_Password.empty() && !AppData.ShowPPI_NewPassword.empty())
		{
			// Verify Password
			const bool ValidPassword = VerifyPassword(BufferLoginPassword, AppData.UserKey, AppData.UserData) && std::equal(AppData.ShowPPI_Password.begin(), AppData.ShowPPI_Password.end(), Password.begin(), Password.end());

			const bool IsNotChangePassword = std::equal(AppData.ShowPPI_NewPassword.begin(), AppData.ShowPPI_NewPassword.end(), Password.begin(), Password.end());

			CurrentApplicationData.progress = 0.6f;

			if (IsNotChangePassword)
			{
				// 密码未更改的提示框
				AppData.ShowPPI_SystemPasswordNotChange = true;
				return;
			}

			if (ValidPassword)
			{
				LoadPasswordManagerUser(AppData.UserKey, AppData.UserData);

				CurrentApplicationData.progress = 0.7f;

				AppData.PersonalPasswordInfo.ChangeInstanceMasterKeyWithSystemPassword
				(
					AppData.PersonalPasswordInfoFilePath,
					AppData.UserKey.RandomUUID + AppData.ShowPPI_Password,
					AppData.UserKey.RandomUUID + AppData.ShowPPI_NewPassword
				);

				CurrentApplicationData.progress = 0.8f;

				AppData.UserData.HashedPassword = PasswordAndHash(AppData.ShowPPI_NewPassword, AppData.UserKey.RandomPasswordSalt);

				CurrentApplicationData.progress = 0.9f;

				SavePasswordManagerUser(std::pair<PasswordManagerUserKey, PasswordManagerUserData>{AppData.UserKey, AppData.UserData});

				// 更改密码成功的提示框
				AppData.ShowPPI_SystemPasswordChangeSuccessful = true;
			}
			else
			{
				// 更改密码失败的提示框
				AppData.ShowPPI_SystemPasswordChangeFailed = true;
			}

			CurrentApplicationData.progress = 1.0f;
		}
	};

	static const auto async_task = [](ApplicationData& AppData, const std::vector<char>& BufferLoginPassword)
	{
		AsyncTask(AppData.TaskInProgress, task_change_ins_mst_key_wth_sys_pwd, std::ref(AppData), std::cref(BufferLoginPassword));
	};

	if (!AppData.TaskInProgress)
	{
		std::thread(async_task, std::ref(AppData), std::cref(BufferLoginPassword)).detach();
	}
}

inline void Do_Login(
	std::vector<char>& BufferLoginUsername, std::vector<char>& BufferLoginPassword,
	bool& ShowInvalidCurrentUUIDFilePopup, bool& ShowUsernameAuthenticationFailedPopup,
	bool& ShowPasswordAuthenticationFailedPopup, bool& ShowLoadUserFailedPopup
)
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
			//std::cout << "Login failed because the UUID of the contents of the 'current_uuid.json' file is invalid!" << std::endl;
			LogWarnHelper("Login failed because the UUID of the contents of the 'current_uuid.json' file is invalid!");
			ShowInvalidCurrentUUIDFilePopup = true;

			return;
		}

		//Loading usernames and hashed passwords with UUID
		LoadPasswordManagerUser(CurrentUserKey, CurrentUserData);

		// Verify Username and Password
		const bool ValidUsername = VerifyUUID(BufferLoginUsername, CurrentUserKey.RandomSalt, CurrentUserKey.RegistrationTime, CurrentUserKey);
		const bool ValidPassword = VerifyPassword(BufferLoginPassword, CurrentUserKey, CurrentUserData);

		if (ValidUsername && ValidPassword)
		{
			// Login successful
			LogNoticeHelper("Login successful!");

			if (CurrentUserData.IsFirstLogin)
			{
				FirstLoginLogic(BufferLoginPassword, CurrentUserKey, CurrentUserData);
			}

			//Change Application Data
			CurrentApplicationData.UserKey = CurrentUserKey;
			CurrentApplicationData.UserData = CurrentUserData;
			
			RefillData_PersonalFiles();

			CurrentApplicationData.ShowGUI_PersonalPasswordInfo = true;

			CurrentApplicationData.ShowPPI_CreatePasswordInstance = true;
			CurrentApplicationData.ShowPPI_ChangePasswordInstance = true;

			CurrentApplicationData.ShowGUI_PersonalFileInfo = true;
		}
		else
		{
			if (ValidUsername == false && ValidPassword == true)
			{
				LogWarnHelper("Failed to login, incorrect username by UUID checking");
				// Username validation failed
				ShowUsernameAuthenticationFailedPopup = true;
			}
			else if (ValidUsername == true && ValidPassword == false)
			{
				LogWarnHelper("Failed to login, incorrect password by security comparison");

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

/* */

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

	if (ImGui::Button("Register"))
	{

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
		Do_Login(BufferLoginUsername, BufferLoginPassword, ShowInvalidCurrentUUIDFilePopup, ShowUsernameAuthenticationFailedPopup, ShowPasswordAuthenticationFailedPopup, ShowLoadUserFailedPopup);
	}

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

/* ShowGUI PersonalPasswordInfo Part */

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
		AppData.ShowPPI_DeletePasswordInstance = !AppData.ShowPPI_DeletePasswordInstance;
	}

	if (ImGui::Button("Delete All Password Instance"))
	{
		AppData.ShowPPI_ConfirmDeleteAllPasswordInstance = !AppData.ShowPPI_ConfirmDeleteAllPasswordInstance;
	}

	if (ImGui::Button("List Password Instance By ID"))
	{
		AppData.ShowPPI_FindPasswordInstanceByID = !AppData.ShowPPI_FindPasswordInstanceByID;
	}

	if (ImGui::Button("List Password Instance By Description"))
	{
		AppData.ShowPPI_FindPasswordInstanceByDescription = !AppData.ShowPPI_FindPasswordInstanceByDescription;
	}

	if (ImGui::Button("Change UUID(Master Key Material) With\n System Password"))
	{
		AppData.ShowPPI_ChangeInstanceMasterKeyWithSystemPassword = !AppData.ShowPPI_ChangeInstanceMasterKeyWithSystemPassword;
	}

	if(ImGui::Button("File Instance Window"))
	{
		AppData.ShowGUI_PersonalFileInfo = true;
		AppData.ShowGUI_PersonalPasswordInfo = false;

		AppData.ShowPPI_CreatePasswordInstance = false;
		AppData.ShowPPI_ChangePasswordInstance = false;
		AppData.ShowPPI_ListAllPasswordInstance = false;
		AppData.ShowPPI_DeletePasswordInstance = false;
		AppData.ShowPPI_ConfirmDeleteAllPasswordInstance = false;
		AppData.ShowPPI_FindPasswordInstanceByID = false;
		AppData.ShowPPI_FindPasswordInstanceByDescription = false;
		AppData.ShowPPI_ChangeInstanceMasterKeyWithSystemPassword = false;
	}

	if (ImGui::Button("Logout"))
	{
		Do_LogoutPersonalPasswordInfo(BufferLoginPassword, AppData);
		LogNoticeHelper("Logout successful!");
	}

	ImGui::End();
}

inline void ShowGUI_PPI_CreatePasswordInstance(std::vector<char>& BufferLoginPassword, ApplicationData& AppData)
{
	if (ImGui::Begin("Create Password Instance"))
	{
		ImGui::InputText("System Password", BufferLoginPassword.data(), BufferLoginPassword.size(), ImGuiInputTextFlags_Password);

		if(!VerifyPassword(BufferLoginPassword, AppData.UserKey, AppData.UserData))
		{
			ImGui::Text("Incorrect system password, you forget it?");
		}
		else
		{
			ImGui::Text("System password is correct.");
		}

		ImGui::InputTextMultiline("New Description", AppData.ShowPPI_Description.data(), AppData.ShowPPI_Description.size(), ImVec2(400, 400), ImGuiInputTextFlags_CtrlEnterForNewLine);
		ImGui::InputText("New Password Text", AppData.ShowPPI_NewPassword.data(), AppData.ShowPPI_NewPassword.size(), ImGuiInputTextFlags_None);

		ImGui::Checkbox("Need AES", &AppData.ShowPPI_NeedAES);
		ImGui::Checkbox("Need RC6", &AppData.ShowPPI_NeedRC6);
		ImGui::Checkbox("Need SM4", &AppData.ShowPPI_NeedSM4);
		ImGui::Checkbox("Need Twofish", &AppData.ShowPPI_NeedTwofish);
		ImGui::Checkbox("Need Serpent", &AppData.ShowPPI_NeedSerpent);

		if (ImGui::Button("Create and Encrypt Password"))
		{
			Do_CreatePasswordInstance(BufferLoginPassword, AppData);
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
	if ( ImGui::Begin( "Change Password Instance By ID" ) )
	{
		BufferLoginPassword.resize( 2048, 0x00 );
		ImGui::InputText( "System Password", BufferLoginPassword.data(), BufferLoginPassword.size(), ImGuiInputTextFlags_Password );

		if ( !VerifyPassword( BufferLoginPassword, AppData.UserKey, AppData.UserData ) )
		{
			ImGui::Text( "Incorrect system password, you forget it?" );
		}
		else
		{
			ImGui::Text( "System password is correct." );
		}

		ImGui::InputScalar( "Select Password Instance ID", ImGuiDataType_U64, &AppData.ShowPPI_SelectedPasswordInstanceID );
		ImGui::Checkbox( "Change Encrypted Password", &AppData.ShowPPI_ChangeEncryptedPassword );
		ImGui::InputTextMultiline( "Change Description", AppData.ShowPPI_Description.data(), AppData.ShowPPI_Description.size(), ImVec2( 400, 400 ), ImGuiInputTextFlags_CtrlEnterForNewLine );
		ImGui::InputText( "Change Password Text", AppData.ShowPPI_Password.data(), AppData.ShowPPI_Password.size(), ImGuiInputTextFlags_None );

		ImGui::Checkbox( "Need AES", &AppData.ShowPPI_NeedAES );
		ImGui::Checkbox( "Need RC6", &AppData.ShowPPI_NeedRC6 );
		ImGui::Checkbox( "Need SM4", &AppData.ShowPPI_NeedSM4 );
		ImGui::Checkbox( "Need Twofish", &AppData.ShowPPI_NeedTwofish );
		ImGui::Checkbox( "Need Serpent", &AppData.ShowPPI_NeedSerpent );

		if ( ImGui::Button( "Flush Password Instance Description" ) )
		{
			AppData.ShowPPI_Description = AppData.PersonalPasswordInfo.FindPasswordInstanceDescriptionByID( AppData.ShowPPI_SelectedPasswordInstanceID );
			AppData.ShowPPI_Description.resize( 2048, 0x00 );
		}

		if ( ImGui::Button( "Change Password Instance" ) )
		{
			Do_ChangePasswordInstance( BufferLoginPassword, AppData );
		}

		if ( ImGui::Button( "Cancel" ) )
		{
			AppData.ShowPPI_ChangePasswordInstance = false;
		}
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
			//AppData.ShowPPI_ChangePasswordInstance = false;
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
			//AppData.ShowPPI_ChangePasswordInstance = false;
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

		if ( !VerifyPassword( BufferLoginPassword, AppData.UserKey, AppData.UserData ) )
		{
			ImGui::Text( "Incorrect system password, you forget it?" );
		}
		else
		{
			ImGui::Text( "System password is correct." );
		}

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

			const bool ValidPassword = VerifyPassword(BufferLoginPassword, AppData.UserKey, AppData.UserData);

			if (!AppData.UserKey.RandomUUID.empty() && !BufferLoginPassword.empty() && ValidPassword)
			{
				if (!AppData.IsPasswordInfoTemporaryValid)
				{
					Do_DecryptionAllPasswordInstance(BufferLoginPassword, AppData);
				}

				AppData.IsPasswordInfoTemporaryValid = true;
				auto& PassswordInstances = AppData.PersonalPasswordInfo.GetPassswordInstances();

				// 循环遍历每个PersonalPasswordInstance并在UI中显示
				for (const auto& Instance : PassswordInstances)
				{
					ImGui::Text("ID: %llu", Instance.ID);
					ImGui::Text("New Description: %s", Instance.Description.data());
					ImGui::Text("Decrypted Password: %s", Instance.DecryptedPassword.data());

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

			AppData.IsPasswordInfoTemporaryValid = false;
		}

	}
	else 
	{
		AppData.ShowPPI_ListAllPasswordInstanceData = false;
	}
	ImGui::End();
}

inline void ShowGUI_PPI_DeletePasswordInstance( std::vector<char>& BufferLoginPassword, ApplicationData& AppData )
{
	if ( AppData.ShowPPI_DeletePasswordInstance )
		ImGui::OpenPopup( "Delete Password Instance" );

	if ( ImGui::BeginPopupModal( "Delete Password Instance", &AppData.ShowPPI_DeletePasswordInstance, ImGuiWindowFlags_AlwaysAutoResize ) )
	{
		BufferLoginPassword.resize( 2048, 0x00 );

		ImGui::InputScalar( "Password Instance ID", ImGuiDataType_U64, &AppData.ShowPPI_SelectedPasswordInstanceID );

		ImGui::Text( "Please enter system password to confirm:" );
		ImGui::InputText( "System Password", BufferLoginPassword.data(), BufferLoginPassword.size(), ImGuiInputTextFlags_Password );

		bool correct_password = false;

		if ( ImGui::Button( "Delete" ) )
		{
			correct_password = VerifyPassword( BufferLoginPassword, AppData.UserKey, AppData.UserData );

			if ( AppData.PersonalPasswordInfo.RemovePasswordInstance( AppData.ShowPPI_SelectedPasswordInstanceID ) )
			{
				AppData.PersonalPasswordInfo.Serialization( AppData.PersonalPasswordInfoFilePath );
				AppData.IsPasswordInfoTemporaryValid = false;
				ImGui::CloseCurrentPopup();
				AppData.ShowPPI_DeletePasswordInstance = false;
			}
		}

		if ( !correct_password )
		{
			ImGui::TextColored( ImVec4( 1.0f, 0.0f, 0.0f, 1.0f ), "Incorrect system password, you forget it?" );
		}
		else
		{
			ImGui::TextColored( ImVec4( 0.0f, 1.0f, 0.0f, 1.0f ), "System password is correct." );
		}

		if ( ImGui::Button( "Cancel" ) )
		{
			AppData.ShowPPI_DeletePasswordInstance = false;
		}

		ImGui::EndPopup();
	}
}

inline void ShowGUI_PPI_DeleteAllPasswordInstance( std::vector<char>& BufferLoginPassword, ApplicationData& AppData )
{
	if ( AppData.ShowPPI_ConfirmDeleteAllPasswordInstance )
		ImGui::OpenPopup( "Confirm Delete All Password Instance" );

	if ( ImGui::BeginPopupModal( "Confirm Delete All Password Instance", &AppData.ShowPPI_ConfirmDeleteAllPasswordInstance, ImGuiWindowFlags_AlwaysAutoResize ) )
	{
		BufferLoginPassword.resize( 2048, 0x00 );

		ImGui::Text( "Are you sure you want to delete all instances?" );
		ImGui::Text( "Please enter system password to confirm:" );

		ImGui::InputText( "System Password", BufferLoginPassword.data(), BufferLoginPassword.size(), ImGuiInputTextFlags_Password );

		bool correct_password = false;

		if ( ImGui::Button( "Delete All" ) )
		{
			correct_password = VerifyPassword( BufferLoginPassword, AppData.UserKey, AppData.UserData );

			AppData.PersonalPasswordInfo.RemoveAllPasswordInstance();
			AppData.PersonalPasswordInfo.Serialization( AppData.PersonalPasswordInfoFilePath );

			AppData.IsPasswordInfoTemporaryValid = false;
			ImGui::CloseCurrentPopup();
			AppData.ShowPPI_ConfirmDeleteAllPasswordInstance = false;
		}

		if ( !correct_password )
		{
			ImGui::TextColored( ImVec4( 1.0f, 0.0f, 0.0f, 1.0f ), "Incorrect system password, you forget it?" );
		}
		else
		{
			ImGui::TextColored( ImVec4( 0.0f, 1.0f, 0.0f, 1.0f ), "System password is correct." );
		}

		if ( ImGui::Button( "Cancel" ) )
		{
			AppData.ShowPPI_ConfirmDeleteAllPasswordInstance = false;
		}

		ImGui::EndPopup();
	}
}

inline void ShowGUI_PPI_FindPasswordInstanceByID(std::vector<char>& BufferLoginPassword, ApplicationData& AppData)
{
	static std::string buffer;
	if (AppData.ShowPPI_FindPasswordInstanceByID) 
	{
		ImGui::OpenPopup("List Password Instance By ID");
	}
	else
	{
		buffer.clear();
	}

	if (ImGui::BeginPopupModal("List Password Instance By ID", &AppData.ShowPPI_FindPasswordInstanceByID, ImGuiWindowFlags_AlwaysAutoResize))
	{
		BufferLoginPassword.resize(2048, 0x00);
		ImGui::InputText("System Password", BufferLoginPassword.data(), BufferLoginPassword.size(), ImGuiInputTextFlags_Password);
		ImGui::InputScalar("Password Instance ID", ImGuiDataType_U64, &AppData.ShowPPI_SelectedPasswordInstanceID);

		const bool ValidPassword = VerifyPassword(BufferLoginPassword, AppData.UserKey, AppData.UserData);

		if (ImGui::Button("find") && AppData.ShowPPI_FindPasswordInstanceByID && ValidPassword)
		{
			Do_FindPasswordInstanceByID(BufferLoginPassword, AppData, buffer);
		}

		ImGui::SameLine();

		if (ImGui::Button("Hide"))
		{
			AppData.ShowPPI_FindPasswordInstanceByID = false;
			buffer.clear();
		}

		if (!buffer.empty() && AppData.ShowPPI_FindPasswordInstanceByID && ValidPassword)
		{
			ImGui::TextUnformatted(buffer.c_str());
		}

		ImGui::EndPopup();
	}
}

inline void ShowGUI_PPI_FindPasswordInstanceByDescription(std::vector<char>& BufferLoginPassword, ApplicationData& AppData)
{
	static std::string buffer;
	if (AppData.ShowPPI_FindPasswordInstanceByDescription)
	{
		ImGui::OpenPopup("List Password Instance By Description");
	}
	else
	{
		buffer.clear();
	}

	if (ImGui::BeginPopupModal("List Password Instance By Description", &AppData.ShowPPI_FindPasswordInstanceByDescription, ImGuiWindowFlags_AlwaysAutoResize))
	{
		BufferLoginPassword.resize(2048, 0x00);

		ImGui::InputText("System Password", BufferLoginPassword.data(), BufferLoginPassword.size(), ImGuiInputTextFlags_Password);

		AppData.ShowPPI_SelectedPasswordInstanceDescription.resize(2048, 0x00);
		ImGui::InputTextMultiline("Password Instance\nDescription", AppData.ShowPPI_SelectedPasswordInstanceDescription.data(), AppData.ShowPPI_SelectedPasswordInstanceDescription.size(), ImVec2(400, 400), ImGuiInputTextFlags_CtrlEnterForNewLine);

		const bool ValidPassword = VerifyPassword(BufferLoginPassword, AppData.UserKey, AppData.UserData);

		if (ImGui::Button("find") && AppData.ShowPPI_FindPasswordInstanceByDescription && ValidPassword)
		{
			Do_FindPasswordInstanceByDescription(BufferLoginPassword, AppData, buffer);
		}

		ImGui::SameLine();
		
		if (ImGui::Button("Hide"))
		{
			AppData.ShowPPI_FindPasswordInstanceByDescription = false;
			buffer.clear();
		}

		if (!buffer.empty() && AppData.ShowPPI_FindPasswordInstanceByDescription && ValidPassword)
		{
			ImGui::TextUnformatted(buffer.c_str());
		}

		ImGui::EndPopup();
	}
}

inline void ShowGUI_PPI_ChangeInstanceMasterKeyWithSystemPassword( std::vector<char>& BufferLoginPassword, ApplicationData& AppData )
{
	ImGui::Begin( "Change Master Key With System Password" );

	if ( AppData.ShowPPI_ChangeInstanceMasterKeyWithSystemPassword )
	{
		// 密码输入框
		ImGui::InputText( "System Old Password", BufferLoginPassword.data(), BufferLoginPassword.size(), ImGuiInputTextFlags_Password );
		ImGui::InputText( "Confirm System Old Password", AppData.ShowPPI_Password.data(), AppData.ShowPPI_Password.size(), ImGuiInputTextFlags_Password );
		ImGui::InputText( "New System Password", AppData.ShowPPI_NewPassword.data(), AppData.ShowPPI_NewPassword.size(), ImGuiInputTextFlags_Password );

		bool correct_password = false;

		if ( ImGui::Button( "Change Password" ) && correct_password )
		{
			correct_password = VerifyPassword( BufferLoginPassword, AppData.UserKey, AppData.UserData );

			Do_ChangeInstanceMasterKeyWithSystemPassword( BufferLoginPassword, AppData );

			BufferLoginPassword.resize( 2048, 0x00 );
			AppData.ShowPPI_ChangeInstanceMasterKeyWithSystemPassword = false;
		}

		if ( !correct_password )
		{
			ImGui::TextColored( ImVec4( 1.0f, 0.0f, 0.0f, 1.0f ), "Incorrect system password, you forget it?" );
		}
		else
		{
			ImGui::TextColored( ImVec4( 0.0f, 1.0f, 0.0f, 1.0f ), "System password is correct." );
		}

		if ( ImGui::Button( "Cancel" ) )
		{
			AppData.ShowPPI_ChangeInstanceMasterKeyWithSystemPassword = false;
		}
	}

	ImGui::End();

	// Other Popup Logic for Success and Failure
	if ( AppData.ShowPPI_SystemPasswordChangeSuccessful )
		ImGui::OpenPopup( "Change System Password Successful" );
	if ( ImGui::BeginPopup( "Change System Password Successful", ImGuiWindowFlags_AlwaysAutoResize ) )
	{
		ImGui::Text( "System password has been changed successfully." );
		if ( ImGui::Button( "OK" ) )
		{
			ImGui::CloseCurrentPopup();
			AppData.ShowPPI_SystemPasswordChangeSuccessful = false;
			AppData.ShowPPI_ChangeInstanceMasterKeyWithSystemPassword = false;
		}
		ImGui::EndPopup();
	}

	if ( AppData.ShowPPI_SystemPasswordNotChange )
		ImGui::OpenPopup( "System Password Not Changed" );
	if ( ImGui::BeginPopup( "System Password Not Changed", ImGuiWindowFlags_AlwaysAutoResize ) )
	{
		ImGui::Text( "New system password should be different from the old system password." );
		if ( ImGui::Button( "OK" ) )
		{
			ImGui::CloseCurrentPopup();
			AppData.ShowPPI_SystemPasswordNotChange = false;
			AppData.ShowPPI_ChangeInstanceMasterKeyWithSystemPassword = false;
		}
		ImGui::EndPopup();
	}

	if ( AppData.ShowPPI_SystemPasswordChangeFailed )
		ImGui::OpenPopup( "Change System Password Failed" );
	if ( ImGui::BeginPopup( "Change System Password Failed", ImGuiWindowFlags_AlwaysAutoResize ) )
	{
		ImGui::Text( "The old system password you entered is incorrect." );
		if ( ImGui::Button( "OK" ) )
		{
			ImGui::CloseCurrentPopup();
			AppData.ShowPPI_SystemPasswordChangeFailed = false;
			AppData.ShowPPI_ChangeInstanceMasterKeyWithSystemPassword = false;
		}
		ImGui::EndPopup();
	}
}

/* ShowGUI PersonalFileInfo Part */

template <typename Callback_t, typename... Args>
	requires std::invocable<Callback_t, std::filesystem::path, Args...>
auto FileDialogCallback( const char* dialog_title, Callback_t&& callback, Args&&... args ) -> std::conditional_t<std::is_void_v<std::invoke_result_t<Callback_t, std::filesystem::path, Args&&...>>, void, std::optional<std::invoke_result_t<Callback_t, std::filesystem::path, Args&&...>>>
{
	using CallBackReturnType = std::invoke_result_t<Callback_t, std::filesystem::path, Args&&...>;

	if ( ImGui::Button( dialog_title ) )
	{
		IGFD::FileDialogConfig FDConfig {};
		FDConfig.path = ".";
		FDConfig.flags = ImGuiFileDialogFlags_Modal;
		ImGuiFileDialog::Instance()->OpenDialog
		(
			"ChooseFileDialogKey",
			dialog_title,
			".*",	// 文件后缀名过滤器  (".*") (nullptr)
			FDConfig
		);
	}

	if ( ImGuiFileDialog::Instance()->Display( "ChooseFileDialogKey", ImGuiWindowFlags_NoCollapse, ImVec2( 800, 600 ), ImVec2( 1200, 800 ) ) )
	{
		if ( ImGuiFileDialog::Instance()->IsOk() )
		{
			auto SelectedPath = ImGuiFileDialog::Instance()->GetFilePathName();
			ImGuiFileDialog::Instance()->Close();

			if constexpr ( std::is_void_v<CallBackReturnType> )
			{
				std::forward<Callback_t>( callback )( SelectedPath, std::forward<Args>( args )... );
				return;
			}
			else
			{
				return std::forward<Callback_t>( callback )( SelectedPath, std::forward<Args>( args )... );
			}
		}
		ImGuiFileDialog::Instance()->Close();
	}
	if constexpr ( !std::is_void_v<CallBackReturnType> )
		return std::nullopt;
}

void ShowGUI_PFI_CreateFileInstance( ApplicationData& AppData )
{
	if ( AppData.ShowPFI_CreateFileInstance )
	{
		if ( ImGui::Begin( "Create File Instance", &AppData.ShowPFI_CreateFileInstance, ImGuiWindowFlags_AlwaysAutoResize ) )
		{
			ImGui::InputScalar( "File Instance ID", ImGuiDataType_U64, &AppData.ShowPFI_SelectedFileInstanceID );

			ImGui::Checkbox( "Need AES", &AppData.ShowPFI_NeedAES );
			ImGui::Checkbox( "Need RC6", &AppData.ShowPFI_NeedRC6 );
			ImGui::Checkbox( "Need SM4", &AppData.ShowPFI_NeedSM4 );
			ImGui::Checkbox( "Need Twofish", &AppData.ShowPFI_NeedTwofish );
			ImGui::Checkbox( "Need Serpent", &AppData.ShowPFI_NeedSerpent );

			if ( ImGui::Button( "Create File Instance" ) )
			{
				// 选择加密算法
				AppData.ShowPFI_EncryptionAlgorithms.clear();
				if ( AppData.ShowPFI_NeedAES )
					AppData.ShowPFI_EncryptionAlgorithms.push_back( CryptoCipherAlgorithmNames[ 0 ] );
				if ( AppData.ShowPFI_NeedRC6 )
					AppData.ShowPFI_EncryptionAlgorithms.push_back( CryptoCipherAlgorithmNames[ 1 ] );
				if ( AppData.ShowPFI_NeedSM4 )
					AppData.ShowPFI_EncryptionAlgorithms.push_back( CryptoCipherAlgorithmNames[ 2 ] );
				if ( AppData.ShowPFI_NeedTwofish )
					AppData.ShowPFI_EncryptionAlgorithms.push_back( CryptoCipherAlgorithmNames[ 3 ] );
				if ( AppData.ShowPFI_NeedSerpent )
					AppData.ShowPFI_EncryptionAlgorithms.push_back( CryptoCipherAlgorithmNames[ 4 ] );

				// 生成解密算法名称（反向顺序）
				AppData.ShowPFI_DecryptionAlgorithms.resize(AppData.ShowPFI_EncryptionAlgorithms.size(), "");
				std::reverse_copy
				(
					AppData.ShowPFI_EncryptionAlgorithms.begin(), AppData.ShowPFI_EncryptionAlgorithms.end(),
					AppData.ShowPFI_DecryptionAlgorithms.begin()
				);

				// 创建文件实例
				auto FileInstance = AppData.PersonalFileInfo.CreateFileInstance( MakeTokenString( AppData.UserKey.RandomUUID, AppData.ShowPPI_Password ), AppData.ShowPFI_EncryptionAlgorithms, AppData.ShowPFI_DecryptionAlgorithms );

				AppData.PersonalFileInfo.AppendFileInstance( FileInstance );
				AppData.PersonalFileInfo.Serialization( AppData.PersonalDataInfoFilePath );

				AppData.ShowPFI_CreateFileInstance = false;

				// 清除 GUI 状态数据
				AppData.ShowPFI_EncryptionAlgorithms.clear();
				AppData.ShowPFI_DecryptionAlgorithms.clear();
			}

			if ( ImGui::Button( "Cancel" ) )
			{
				AppData.ShowPFI_CreateFileInstance = false;

				// 清除 GUI 状态数据
				AppData.ShowPFI_EncryptionAlgorithms.clear();
				AppData.ShowPFI_DecryptionAlgorithms.clear();
			}
		}
		ImGui::End();
	}
}

inline void ShowGUI_PFI_ListAllFileInstance( ApplicationData& AppData )
{
	if ( ImGui::Begin( "List All File Instances") )
	{
		ImGui::Checkbox("List All", &AppData.ShowPFI_ListAllFileInstanceData);

		if (ImGui::Button("Hide"))
		{
			AppData.ShowPFI_ListAllFileInstance = false;
		}

		// 控制文件实例数据的显示
		if ( AppData.ShowPFI_ListAllFileInstanceData )
		{
			auto& FileInstances = AppData.PersonalFileInfo.GetFileInstances();

			// 遍历每个 PersonalFileInstance 并显示相关信息
			for ( const auto& Instance : FileInstances )
			{
				ImGui::Text( "ID: %llu", Instance.ID );

				ImGui::Text( "Encryption Algorithms:" );
				for ( const auto& algorithm : Instance.EncryptionAlgorithmNames )
				{
					ImGui::Text( "- %s", algorithm.data() );
				}

				ImGui::Text( "Decryption Algorithms:" );
				for ( const auto& algorithm : Instance.DecryptionAlgorithmNames )
				{
					ImGui::Text( "- %s", algorithm.data() );
				}

				// 在每个实例之间添加分隔线
				ImGui::Separator();
			}
		}
	}
	ImGui::End();
}

void ShowGUI_PFI_DeleteFileInstance( ApplicationData& AppData )
{
	if ( AppData.ShowPFI_DeleteFileInstanceByID )
	{
		if ( ImGui::Begin( "Delete File Instance", &AppData.ShowPFI_DeleteFileInstanceByID, ImGuiWindowFlags_AlwaysAutoResize ) )
		{
			ImGui::InputScalar( "File Instance ID to Delete", ImGuiDataType_U64, &AppData.ShowPFI_SelectedFileInstanceID );

			if ( ImGui::Button( "Delete" ) )
			{
				if ( AppData.PersonalFileInfo.RemoveFileInstance( AppData.ShowPFI_SelectedFileInstanceID ) )
				{
					AppData.PersonalFileInfo.Serialization( AppData.PersonalDataInfoFilePath );
				}

				AppData.ShowPFI_DeleteFileInstanceByID = false;
			}

			if ( ImGui::Button( "Cancel" ) )
			{
				AppData.ShowPFI_DeleteFileInstanceByID = false;
			}
		}
		ImGui::End();
	}
}

void ShowGUI_PFI_ConfirmDeleteAllFileInstances( ApplicationData& AppData )
{
	if ( AppData.ShowPFI_ConfirmDeleteAllFileInstancesPopup )
	{
		ImGui::OpenPopup("Confirm Delete All File Instances");
	}
	if ( ImGui::BeginPopupModal( "Confirm Delete All File Instances", &AppData.ShowPFI_ConfirmDeleteAllFileInstancesPopup, ImGuiWindowFlags_AlwaysAutoResize ) )
	{
		ImGui::Text( "Are you sure you want to delete all file instances?" );

		if ( ImGui::Button( "Delete All" ) )
		{
			AppData.PersonalFileInfo.RemoveAllFileInstances();
			AppData.PersonalFileInfo.Serialization( AppData.PersonalDataInfoFilePath );
			AppData.ShowPFI_ConfirmDeleteAllFileInstancesPopup = false;
			ImGui::CloseCurrentPopup();
		}

		if ( ImGui::Button( "Cancel" ) )
		{
			AppData.ShowPFI_ConfirmDeleteAllFileInstancesPopup = false;
			ImGui::CloseCurrentPopup();
		}

		ImGui::EndPopup();
	}
}

void ShowGUI_PFI_EncryptFile(std::vector<char>& BufferLoginPassword, ApplicationData& AppData )
{
	if ( AppData.ShowPFI_EncryptFile )
	{
		if ( ImGui::Begin( "Encrypt File", &AppData.ShowPFI_EncryptFile, ImGuiWindowFlags_AlwaysAutoResize ) )
		{
			ImGui::InputText("System Password", BufferLoginPassword.data(), BufferLoginPassword.size(), ImGuiInputTextFlags_Password);
			// 选择文件实例
			ImGui::InputScalar( "Select File Instance ID", ImGuiDataType_U64, &AppData.ShowPFI_SelectedFileInstanceID );

			if(!VerifyPassword(BufferLoginPassword, AppData.UserKey, AppData.UserData))
			{
				ImGui::Text("Incorrect system password, you forget it?");
			}
			else
			{
				ImGui::Text("System password is correct.");
			}

			if(!AppData.IsSourceFileSelected)
			{
				// 选择源文件
				FileDialogCallback
				( 
					"Select File to Encrypt",
					[](const std::filesystem::path& in_path, std::filesystem::path& out_path, bool& result)
					{
						out_path = in_path;
						result = !out_path.empty();
						return out_path;
					}, std::ref(AppData.SourceFilePath), std::ref(AppData.IsSourceFileSelected)
				);
			}

			if(!AppData.IsEncryptedFileSelected)
			{
				// 选择加密文件
				FileDialogCallback
				( 
					"Save Encrypted File",
					[](const std::filesystem::path& SelectedPath, std::filesystem::path& out_path, bool& result)
					{
						out_path = SelectedPath;
						result = !out_path.empty();
						return out_path;
					}, std::ref(AppData.EncryptedFilePath), std::ref(AppData.IsEncryptedFileSelected)
				);
			}

			bool Success = false;
			if ( ImGui::Button( "Encrypt" ) )
			{
				if ( !AppData.SourceFilePath.empty() && !AppData.EncryptedFilePath.empty() )
				{
					std::string Password(BufferLoginPassword.begin(), BufferLoginPassword.end());

					auto new_end = std::find_if
					(
						Password.rbegin(), Password.rend(),
						[](char character)
						{
							return character != '\x00';
						}
					);

					Password.erase(new_end.base(), Password.end());

					// 查找对应的文件实例
					auto& FileInstance = AppData.PersonalFileInfo.GetFileInstanceByID( AppData.ShowPFI_SelectedFileInstanceID );

					Success = AppData.PersonalFileInfo.EncryptFile
					(
						MakeTokenString( AppData.UserKey.RandomUUID, Password ),
						FileInstance, AppData.SourceFilePath, AppData.EncryptedFilePath
					);

					AppData.SourceFilePath.clear();
					AppData.EncryptedFilePath.clear();
				}

				AppData.IsSourceFileSelected = false;
				AppData.IsEncryptedFileSelected = false;
			}

			if ( AppData.ShowPFI_EncryptFileResultPopup )
			{
				ImGui::OpenPopup("Encrypt File Result");
			}
			if ( ImGui::BeginPopupModal( "Encrypt File Result", &AppData.ShowPFI_EncryptFileResultPopup, ImGuiWindowFlags_AlwaysAutoResize ) )
			{
				if ( Success )
				{
					ImGui::Text( "File encrypted successfully." );
					AppData.ShowPFI_EncryptFileResultPopup = false;
					ImGui::CloseCurrentPopup();
				}
				else
				{
					ImGui::Text( "File encryption failed." );
					AppData.ShowPFI_EncryptFileResultPopup = false;
					ImGui::CloseCurrentPopup();
				}

				ImGui::EndPopup();
			}

			if ( ImGui::Button( "Close" ) )
			{
				AppData.ShowPFI_EncryptFile = false;
			}
		}
		ImGui::End();
	}
}

void ShowGUI_PFI_DecryptFile( std::vector<char>& BufferLoginPassword, ApplicationData& AppData )
{
	if ( AppData.ShowPFI_DecryptFile )
	{
		if ( ImGui::Begin( "Decrypt File", &AppData.ShowPFI_DecryptFile, ImGuiWindowFlags_AlwaysAutoResize ) )
		{
			ImGui::InputText("System Password", BufferLoginPassword.data(), BufferLoginPassword.size(), ImGuiInputTextFlags_Password);
			// 选择文件实例
			ImGui::InputScalar( "Select File Instance ID", ImGuiDataType_U64, &AppData.ShowPFI_SelectedFileInstanceID );

			if(!VerifyPassword(BufferLoginPassword, AppData.UserKey, AppData.UserData))
			{
				ImGui::Text("Incorrect system password, you forget it?");
			}
			else
			{
				ImGui::Text("System password is correct.");
			}

			if(!AppData.IsEncryptedFileSelected)
			{
				// 选择加密文件
				FileDialogCallback
				( 
					"Select Encrypted File to Decrypt",
					[](const std::filesystem::path& in_path, std::filesystem::path& out_path, bool& result)
					{
						out_path = in_path;
						result = !out_path.empty();
						return out_path;
					}, std::ref(AppData.EncryptedFilePath), std::ref(AppData.IsEncryptedFileSelected)
				);
			}
			
			if(!AppData.IsDecryptedFileSelected)
			{
				// 选择解密文件
				FileDialogCallback
				( 
					"Save Decrypted File",
					[](const std::filesystem::path& in_path, std::filesystem::path& out_path, bool& result)
					{
						out_path = in_path;
						result = !out_path.empty();
						return out_path;
					}, std::ref(AppData.DecryptedFilePath), std::ref(AppData.IsDecryptedFileSelected)
				);
			}

			bool Success = false;
			if ( ImGui::Button( "Decrypt" ) )
			{
				if ( !AppData.EncryptedFilePath.empty() && !AppData.DecryptedFilePath.empty() )
				{
					std::string Password(BufferLoginPassword.begin(), BufferLoginPassword.end());

					auto new_end = std::find_if
					(
						Password.rbegin(), Password.rend(),
						[](char character)
						{
							return character != '\x00';
						}
					);

					Password.erase(new_end.base(), Password.end());

					// 查找对应的文件实例
					auto& FileInstance = AppData.PersonalFileInfo.GetFileInstanceByID( AppData.ShowPFI_SelectedFileInstanceID );

					Success = AppData.PersonalFileInfo.DecryptFile
					(
						MakeTokenString( AppData.UserKey.RandomUUID, Password ),
						FileInstance, AppData.EncryptedFilePath, AppData.DecryptedFilePath
					);

					AppData.EncryptedFilePath.clear();
					AppData.DecryptedFilePath.clear();
				}

				AppData.IsEncryptedFileSelected = false;
				AppData.IsDecryptedFileSelected = false;
			}

			if ( AppData.ShowPFI_DecryptFileResultPopup )
			{
				ImGui::OpenPopup("Decrypt File Result");
			}

			if ( ImGui::BeginPopupModal( "Decrypt File Result", &AppData.ShowPFI_DecryptFileResultPopup, ImGuiWindowFlags_AlwaysAutoResize ) )
			{
				if ( Success )
				{
					ImGui::Text( "File decrypted successfully." );
					AppData.ShowPFI_DecryptFileResultPopup = false;
					ImGui::CloseCurrentPopup();
				}
				else
				{
					ImGui::Text( "File decryption failed." );
					AppData.ShowPFI_DecryptFileResultPopup = false;
					ImGui::CloseCurrentPopup();
				}

				ImGui::EndPopup();
			}

			if ( ImGui::Button( "Close" ) )
			{
				AppData.ShowPFI_DecryptFile = false;
			}
		}
		ImGui::End();
	}
}

// 显示 PersonalFileInfo 的 GUI
inline void ShowGUI_PersonalFileInfo(std::vector<char>& BufferLoginPassword, ApplicationData& AppData)
{
	ImGui::Begin("Personal File Info");

	if (ImGui::Button("Create File Instance"))
	{
		AppData.ShowPFI_CreateFileInstance = !AppData.ShowPFI_CreateFileInstance;
	}

	if (ImGui::Button("List All File Instances"))
	{
		AppData.ShowPFI_ListAllFileInstance = !AppData.ShowPFI_ListAllFileInstance;
	}

	if (ImGui::Button("Delete File Instance By ID"))
	{
		AppData.ShowPFI_DeleteFileInstanceByID = !AppData.ShowPFI_DeleteFileInstanceByID;
	}

	if (ImGui::Button("Encrypt File"))
	{
		AppData.ShowPFI_EncryptFile = !AppData.ShowPFI_EncryptFile;
	}

	if (ImGui::Button("Decrypt File"))
	{
		AppData.ShowPFI_DecryptFile = !AppData.ShowPFI_DecryptFile;
	}

	if (ImGui::Button("Delete All File Instances"))
	{
		AppData.ShowPFI_ConfirmDeleteAllFileInstancesPopup = true;
	}

	if (ImGui::Button("Password Instance Window"))
	{
		AppData.ShowGUI_PersonalFileInfo = false;
		AppData.ShowGUI_PersonalPasswordInfo = true;

		AppData.ShowPFI_CreateFileInstance = false;
		AppData.ShowPFI_DeleteFileInstanceByID = false;
		AppData.ShowPFI_EncryptFile = false;
		AppData.ShowPFI_DecryptFile = false;
		AppData.ShowPFI_ConfirmDeleteAllFileInstancesPopup = false;
	}

	ImGui::End();
}
