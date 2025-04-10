#pragma once

#include "application_functional.hpp"

inline constexpr size_t TEXT_BUFFER_CAPACITY = 2048;

struct ApplicationData
{
	bool ShowGUI_PersonalPasswordInfo = false;
	bool ShowGUI_PersonalFileInfo     = false;

	/* About PersonalPasswordInfo GUI Data */

	bool ShowPPI_CreatePasswordInstance = false;

	bool ShowPPI_ChangePasswordInstance           = false;
	bool ShowPPI_ChangePasswordInstanceSuccessful = false;
	bool ShowPPI_ChangePasswordInstanceFailed     = false;

	bool ShowPPI_ListAllPasswordInstance     = false;
	bool ShowPPI_ListAllPasswordInstanceData = false;

	bool ShowPPI_DeletePasswordInstance                    = false;
	bool ShowPPI_ConfirmDeleteAllPasswordInstance          = false;
	bool ShowPPI_FindPasswordInstanceByID                  = false;
	bool ShowPPI_FindPasswordInstanceByDescription         = false;
	bool ShowPPI_ChangeInstanceMasterKeyWithSystemPassword = false;
	bool ShowPPI_SystemPasswordChangeSuccessful            = false;
	bool ShowPPI_SystemPasswordNotChange                   = false;
	bool ShowPPI_SystemPasswordChangeFailed                = false;

	bool ShowPPI_NeedAES     = false;
	bool ShowPPI_NeedRC6     = false;
	bool ShowPPI_NeedSM4     = false;
	bool ShowPPI_NeedTwofish = false;
	bool ShowPPI_NeedSerpent = false;

	std::uint64_t ShowPPI_SelectedPasswordInstanceID          = 0;
	std::string   ShowPPI_Description                         = std::string(TEXT_BUFFER_CAPACITY, 0x00);
	std::string   ShowPPI_SelectedPasswordInstanceDescription = "";
	std::string   ShowPPI_Password                            = std::string(TEXT_BUFFER_CAPACITY, 0x00);
	std::string   ShowPPI_ConfirmPassword                     = std::string(TEXT_BUFFER_CAPACITY, 0x00);
	std::string   ShowPPI_ChangedPassword                     = std::string(TEXT_BUFFER_CAPACITY, 0x00);
	std::string   ShowPPI_NewPassword                         = std::string(TEXT_BUFFER_CAPACITY, 0x00);

	std::vector<char> BufferRegisterUsername = std::vector<char>(TEXT_BUFFER_CAPACITY, 0x00);
	std::vector<char> BufferRegisterPassword = std::vector<char>(TEXT_BUFFER_CAPACITY, 0x00);

	std::vector<char> BufferLoginUsername = std::vector<char>(TEXT_BUFFER_CAPACITY, 0x00);
	std::vector<char> BufferLoginPassword = std::vector<char>(TEXT_BUFFER_CAPACITY, 0x00);

	std::vector<char> BUFFER_ShowGUI_PPI_FindPasswordInstanceByID          = std::vector<char>(8192, 0x00);
	std::vector<char> BUFFER_ShowGUI_PPI_FindPasswordInstanceByDescription = std::vector<char>(8192, 0x00);

	std::vector<std::string> ShowPPI_EncryptionAlgorithms;
	std::vector<std::string> ShowPPI_DecryptionAlgorithms;

	bool ShowPPI_ChangeEncryptedPassword = false;

	/* About PersonalFileInfo GUI Data */

	bool ShowPFI_NeedAES     = false;
	bool ShowPFI_NeedRC6     = false;
	bool ShowPFI_NeedSM4     = false;
	bool ShowPFI_NeedTwofish = false;
	bool ShowPFI_NeedSerpent = false;

	bool ShowPFI_CreateFileInstance = false;

	bool ShowPFI_ListAllFileInstance     = false;
	bool ShowPFI_ListAllFileInstanceData = false;

	bool ShowPFI_DeleteFileInstanceByID             = false;
	bool ShowPFI_ConfirmDeleteAllFileInstancesPopup = false;

	bool ShowPFI_EncryptFile = false;
	bool ShowPFI_DecryptFile = false;

	bool ShowPFI_EncryptFileResultPopup = false;
	bool ShowPFI_DecryptFileResultPopup = false;

	std::uint64_t            ShowPFI_SelectedFileInstanceID = 0;
	std::vector<std::string> ShowPFI_EncryptionAlgorithms;
	std::vector<std::string> ShowPFI_DecryptionAlgorithms;

	/* About PasswordManager Data */

	PasswordManagerUserKey  UserKey;
	PasswordManagerUserData UserData;

	PersonalPasswordInfo  PersonalPasswordObject;
	std::filesystem::path PersonalPasswordInfoFilePath;

	PersonalFileInfo      PersonalFileObject;
	std::filesystem::path PersonalDataInfoFilePath;

	bool                  IsOriginalFileSelected = false;
	std::filesystem::path SourceFilePath;
	bool                  IsTargetEncryptedFileSelected = false;
	std::filesystem::path TargetEncryptedFilePath;
	bool                  IsSourceEncryptedFileSelected = false;
	std::filesystem::path SourceEncryptedFilePath;
	bool                  IsDecryptedFileSelected = false;
	std::filesystem::path DecryptedFilePath;

	/* Atomic flag indicating if any background task is currently running */
	std::atomic_bool                     TaskInProgress     = false;
	float                                progress           = 0.0f;
	float                                progress_target    = 0.0f;
	float                                progress_life_time = 0.0f;
	std::mutex                           mutex_task;
	std::optional<std::jthread>          background_thread;
	std::optional<std::function<void()>> current_task;
	GLFWwindow                          *window;
	std::once_flag                       cleanup_once;

	/* Other state data */
	bool IsUserLogin                  = false;
	bool IsPasswordInfoTemporaryValid = false;
};

// global object
ApplicationData CurrentApplicationData;
