#pragma once

/* ShowGUI PersonalFileInfo Part */

// FIXME: 处理创建成功，失败后的弹窗，处理文件实例覆盖的问题，需要创建一个模态框，向用户确认是否覆盖，目前ID是以插入的方式添加的，会导致后面的ID跟着漂移
inline void ShowGUI_PFI_CreateFileInstance(ApplicationData &AppData)
{
	if (AppData.ShowPFI_CreateFileInstance)
	{
		if (ImGui::Begin("Create File Instance", &AppData.ShowPFI_CreateFileInstance, ImGuiWindowFlags_AlwaysAutoResize))
		{
			ImGui::Text("File Instance ID:");
			ImGui::InputScalar("##File Instance ID", ImGuiDataType_U64, &AppData.ShowPFI_SelectedFileInstanceID);

			ImGui::Checkbox("Need AES", &AppData.ShowPFI_NeedAES);
			ImGui::Checkbox("Need RC6", &AppData.ShowPFI_NeedRC6);
			ImGui::Checkbox("Need SM4", &AppData.ShowPFI_NeedSM4);
			ImGui::Checkbox("Need Twofish", &AppData.ShowPFI_NeedTwofish);
			ImGui::Checkbox("Need Serpent", &AppData.ShowPFI_NeedSerpent);

			if (ImGui::Button("Create File Instance"))
			{
				// 选择加密算法
				AppData.ShowPFI_EncryptionAlgorithms.clear();
				if (AppData.ShowPFI_NeedAES)
					AppData.ShowPFI_EncryptionAlgorithms.push_back(CryptoCipherAlgorithmNames[0]);
				if (AppData.ShowPFI_NeedRC6)
					AppData.ShowPFI_EncryptionAlgorithms.push_back(CryptoCipherAlgorithmNames[1]);
				if (AppData.ShowPFI_NeedSM4)
					AppData.ShowPFI_EncryptionAlgorithms.push_back(CryptoCipherAlgorithmNames[2]);
				if (AppData.ShowPFI_NeedTwofish)
					AppData.ShowPFI_EncryptionAlgorithms.push_back(CryptoCipherAlgorithmNames[3]);
				if (AppData.ShowPFI_NeedSerpent)
					AppData.ShowPFI_EncryptionAlgorithms.push_back(CryptoCipherAlgorithmNames[4]);

				// 生成解密算法名称（反向顺序）
				AppData.ShowPFI_DecryptionAlgorithms.resize(AppData.ShowPFI_EncryptionAlgorithms.size(), "");
				std::reverse_copy(AppData.ShowPFI_EncryptionAlgorithms.begin(), AppData.ShowPFI_EncryptionAlgorithms.end(), AppData.ShowPFI_DecryptionAlgorithms.begin());

				// 创建文件实例
				auto FileInstance = AppData.PersonalFileInfo_.CreateFileInstance(
				    MakeTokenString(AppData.UserKey.RandomUUID, AppData.ShowPPI_Password),
				    AppData.ShowPFI_EncryptionAlgorithms,
				    AppData.ShowPFI_DecryptionAlgorithms);

				AppData.PersonalFileInfo_.AppendFileInstance(FileInstance);
				AppData.PersonalFileInfo_.Serialization(AppData.PersonalDataInfoFilePath);

				//AppData.ShowPFI_CreateFileInstance = false;

				// 清除 GUI 状态数据
				AppData.ShowPFI_EncryptionAlgorithms.clear();
				AppData.ShowPFI_DecryptionAlgorithms.clear();
			}

			ImGui::SameLine();

			if (ImGui::Button("Cancel"))
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

inline void ShowGUI_PFI_ListAllFileInstance(ApplicationData &AppData)
{
	if (ImGui::Begin("List All File Instances"))
	{
		ImGui::Checkbox("List All", &AppData.ShowPFI_ListAllFileInstanceData);

		if (ImGui::Button("Close"))
		{
			AppData.ShowPFI_ListAllFileInstance = false;
		}

		// 控制文件实例数据的显示
		if (AppData.ShowPFI_ListAllFileInstanceData)
		{
			auto &FileInstances = AppData.PersonalFileInfo_.GetFileInstances();

			// 遍历每个 PersonalFileInstance 并显示相关信息
			for (const auto &Instance : FileInstances)
			{
				ImGui::Text("ID: %lu", Instance.ID);
				ImGui::Text("Encryption Algorithms:");
				for (const auto &algorithm : Instance.EncryptionAlgorithmNames)
				{
					ImGui::Text("- %s", algorithm.data());
				}

				ImGui::Text("Decryption Algorithms:");
				for (const auto &algorithm : Instance.DecryptionAlgorithmNames)
				{
					ImGui::Text("- %s", algorithm.data());
				}

				// 在每个实例之间添加分隔线
				ImGui::Separator();
			}
		}
	}
	ImGui::End();
}

inline void ShowGUI_PFI_DeleteFileInstance(ApplicationData &AppData)
{
	if (AppData.ShowPFI_DeleteFileInstanceByID)
	{
		if (ImGui::Begin("Delete File Instance", &AppData.ShowPFI_DeleteFileInstanceByID, ImGuiWindowFlags_AlwaysAutoResize))
		{
			ImGui::Text("File Instance ID to Delete");
			ImGui::InputScalar("##File Instance ID to Delete", ImGuiDataType_U64, &AppData.ShowPFI_SelectedFileInstanceID);

			if (ImGui::Button("Delete"))
			{
				if (AppData.PersonalFileInfo_.RemoveFileInstance(AppData.ShowPFI_SelectedFileInstanceID))
				{
					AppData.PersonalFileInfo_.Serialization(AppData.PersonalDataInfoFilePath);
				}

				AppData.ShowPFI_DeleteFileInstanceByID = false;
			}

			ImGui::SameLine();

			if (ImGui::Button("Cancel"))
			{
				AppData.ShowPFI_DeleteFileInstanceByID = false;
			}
		}
		ImGui::End();
	}
}

inline void ShowGUI_PFI_ConfirmDeleteAllFileInstances(ApplicationData &AppData)
{
	if (AppData.ShowPFI_ConfirmDeleteAllFileInstancesPopup)
	{
		ImGui::OpenPopup("Confirm Delete All File Instances");
	}
	if (ImGui::BeginPopupModal("Confirm Delete All File Instances", &AppData.ShowPFI_ConfirmDeleteAllFileInstancesPopup, ImGuiWindowFlags_AlwaysAutoResize))
	{
		ImGui::Text("Are you sure you want to delete all file instances?");

		if (ImGui::Button("Delete All"))
		{
			AppData.PersonalFileInfo_.RemoveAllFileInstances();
			AppData.PersonalFileInfo_.Serialization(AppData.PersonalDataInfoFilePath);
			AppData.ShowPFI_ConfirmDeleteAllFileInstancesPopup = false;
			ImGui::CloseCurrentPopup();
		}

		ImGui::SameLine();

		if (ImGui::Button("Cancel"))
		{
			AppData.ShowPFI_ConfirmDeleteAllFileInstancesPopup = false;
			ImGui::CloseCurrentPopup();
		}

		ImGui::EndPopup();
	}
}

inline void ShowGUI_PFI_EncryptFile(std::vector<char> &BufferLoginPassword, ApplicationData &AppData)
{
	if (AppData.ShowPFI_EncryptFile)
	{
		if (ImGui::Begin("Encrypt File", &AppData.ShowPFI_EncryptFile, ImGuiWindowFlags_AlwaysAutoResize))
		{
			ImGui::Text("System Password:");
			ImGui::InputText("##System Password", BufferLoginPassword.data(), BufferLoginPassword.size(), ImGuiInputTextFlags_Password);
			// 选择文件实例
			ImGui::Text("Select File Instance ID:");
			ImGui::InputScalar("##Select File Instance ID", ImGuiDataType_U64, &AppData.ShowPFI_SelectedFileInstanceID);

			VerifyPasswordText(VerifyPassword(BufferLoginPassword, AppData.UserKey, AppData.UserData));

			//if (!AppData.IsSourceFileSelected)
			{
				// 选择源文件
				FileDialogCallback(
				    "Select File to Encrypt",
				    AppData.IsSourceFileSelected,
					false,
				    [](const std::filesystem::path &in_path, std::filesystem::path &out_path, bool &result)
				    {
					    out_path = in_path;
					    result   = !out_path.empty();
				    },
				    std::ref(AppData.SourceFilePath),
				    std::ref(AppData.IsSourceFileSelected));
			}

			//if (!AppData.IsEncryptedFileSelected)
			{
				// 选择加密文件
				FileDialogCallback(
				    "Save Encrypted File",
				    AppData.IsEncryptedFileSelected,
					true,
				    [](const std::filesystem::path &SelectedPath, std::filesystem::path &out_path, bool &result)
				    {
					    out_path = SelectedPath;
					    result   = !out_path.empty();
				    },
				    std::ref(AppData.EncryptedFilePath),
				    std::ref(AppData.IsEncryptedFileSelected));
			}

			static bool Success = false;
			if (ImGui::Button("Encrypt"))
			{
				if (!AppData.SourceFilePath.empty() && !AppData.EncryptedFilePath.empty())
				{
					std::string Password(BufferLoginPassword.begin(), BufferLoginPassword.end());

					auto new_end = std::find_if(Password.rbegin(), Password.rend(), [](char character) { return character != '\x00'; });

					Password.erase(new_end.base(), Password.end());

					// 查找对应的文件实例
					auto FileInstance = AppData.PersonalFileInfo_.GetFileInstanceByID(AppData.ShowPFI_SelectedFileInstanceID);

					if (FileInstance.has_value())
					{
						Success = AppData.PersonalFileInfo_.EncryptFile(
						    MakeTokenString(AppData.UserKey.RandomUUID, Password),
						    FileInstance.value().get(),
						    AppData.SourceFilePath,
						    AppData.EncryptedFilePath);

						AppData.SourceFilePath.clear();
						AppData.EncryptedFilePath.clear();
						AppData.ShowPFI_EncryptFileResultPopup = true;
					}
					else
					{
						ImGui::OpenPopup("Invalid File Instance");
					}
				}

				AppData.IsSourceFileSelected    = false;
				AppData.IsEncryptedFileSelected = false;
			}

			if (ImGui::BeginPopupModal("Invalid File Instance", nullptr, ImGuiWindowFlags_AlwaysAutoResize))
			{
				ImGui::Text("Invalid File Instance");

				if (ImGui::Button("Ok"))
				{
					ImGui::CloseCurrentPopup();
				}
				ImGui::EndPopup();
			}

			if (AppData.ShowPFI_EncryptFileResultPopup)
			{
				ImGui::OpenPopup("Encrypt File Result");
			}

			if (ImGui::BeginPopupModal("Encrypt File Result", &AppData.ShowPFI_EncryptFileResultPopup, ImGuiWindowFlags_AlwaysAutoResize))
			{

				ImGui::Text(Success ? "File encryption successfully." : "File encryption failed.");

				if (ImGui::Button("Ok"))
				{
					AppData.ShowPFI_EncryptFileResultPopup = false;
					Success                                = false;
					ImGui::CloseCurrentPopup();
				}
				ImGui::EndPopup();
			}

			if (ImGui::Button("Close"))
			{
				AppData.ShowPFI_EncryptFile = false;
			}
		}
		ImGui::End();
	}
}

inline void ShowGUI_PFI_DecryptFile(std::vector<char> &BufferLoginPassword, ApplicationData &AppData)
{
	if (AppData.ShowPFI_DecryptFile)
	{
		if (ImGui::Begin("Decrypt File", &AppData.ShowPFI_DecryptFile, ImGuiWindowFlags_AlwaysAutoResize))
		{
			ImGui::Text("System Password:");
			ImGui::InputText("##System Password", BufferLoginPassword.data(), BufferLoginPassword.size(), ImGuiInputTextFlags_Password);
			// 选择文件实例
			ImGui::Text("Select File Instance ID:");
			ImGui::InputScalar("##Select File Instance ID", ImGuiDataType_U64, &AppData.ShowPFI_SelectedFileInstanceID);

			VerifyPasswordText(VerifyPassword(BufferLoginPassword, AppData.UserKey, AppData.UserData));

			//if (!AppData.IsEncryptedFileSelected)
			{
				// 选择加密文件
				FileDialogCallback(
				    "Select Encrypted File to Decrypt",
					false,
				    AppData.IsEncryptedFileSelected,
				    [](const std::filesystem::path &in_path, std::filesystem::path &out_path, bool &result)
				    {
					    out_path = in_path;
					    result   = !out_path.empty();
				    },
				    std::ref(AppData.EncryptedFilePath),
				    std::ref(AppData.IsEncryptedFileSelected));
			}

			//if (!AppData.IsDecryptedFileSelected)
			{
				// 选择解密文件
				FileDialogCallback(
				    "Save Decrypted File",
					true,
				    AppData.IsDecryptedFileSelected,
				    [](const std::filesystem::path &in_path, std::filesystem::path &out_path, bool &result)
				    {
					    out_path = in_path;
					    result   = !out_path.empty();
				    },
				    std::ref(AppData.DecryptedFilePath),
				    std::ref(AppData.IsDecryptedFileSelected));
			}

			static bool Success = false;
			if (ImGui::Button("Decrypt"))
			{
				if (!AppData.EncryptedFilePath.empty() && !AppData.DecryptedFilePath.empty())
				{
					std::string Password(BufferLoginPassword.begin(), BufferLoginPassword.end());

					auto new_end = std::find_if(Password.rbegin(), Password.rend(), [](char character) { return character != '\x00'; });

					Password.erase(new_end.base(), Password.end());

					// 查找对应的文件实例
					auto FileInstance = AppData.PersonalFileInfo_.GetFileInstanceByID(AppData.ShowPFI_SelectedFileInstanceID);

					if (FileInstance.has_value())
					{
						Success = AppData.PersonalFileInfo_.DecryptFile(
						    MakeTokenString(AppData.UserKey.RandomUUID, Password),
						    FileInstance.value().get(),
						    AppData.EncryptedFilePath,
						    AppData.DecryptedFilePath);

						AppData.EncryptedFilePath.clear();
						AppData.DecryptedFilePath.clear();
						AppData.ShowPFI_DecryptFileResultPopup = true;

					}
					else
					{
						ImGui::OpenPopup("Invalid File Instance");
					}
				}

				AppData.IsEncryptedFileSelected = false;
				AppData.IsDecryptedFileSelected = false;
			}

			if (ImGui::BeginPopupModal("Invalid File Instance", nullptr, ImGuiWindowFlags_AlwaysAutoResize))
			{
				ImGui::Text("Invalid File Instance");

				if (ImGui::Button("Ok"))
				{
					ImGui::CloseCurrentPopup();
				}
				ImGui::EndPopup();
			}


			if (AppData.ShowPFI_DecryptFileResultPopup)
			{
				ImGui::OpenPopup("Decrypt File Result");
			}

			if (ImGui::BeginPopupModal("Decrypt File Result", &AppData.ShowPFI_DecryptFileResultPopup, ImGuiWindowFlags_AlwaysAutoResize))
			{

				ImGui::Text(Success ? "File dencryption successfully." : "File dencryption failed.");

				if (ImGui::Button("Ok"))
				{
					AppData.ShowPFI_DecryptFileResultPopup = false;
					Success                                = false;
					ImGui::CloseCurrentPopup();
				}
				ImGui::EndPopup();
			}
			if (ImGui::Button("Close"))
			{
				AppData.ShowPFI_DecryptFile = false;
			}
		}
		ImGui::End();
	}
}

// 显示 PersonalFileInfo 的 GUI
inline void ShowGUI_PersonalFileInfo([[maybe_unused]] std::vector<char> &BufferLoginPassword, ApplicationData &AppData)
{
	ImGui::Begin("Personal File Info");

	if (ImGui::Button("Create File Instance"))
	{
		AppData.ShowPFI_CreateFileInstance = true; //! AppData.ShowPFI_CreateFileInstance;
		ImGui::SetWindowFocus("Create File Instance");
	}

	if (ImGui::Button("List All File Instances"))
	{
		AppData.ShowPFI_ListAllFileInstance = true; //! AppData.ShowPFI_ListAllFileInstance;
		ImGui::SetWindowFocus("List All File Instances");
	}

	if (ImGui::Button("Delete File Instance By ID"))
	{
		AppData.ShowPFI_DeleteFileInstanceByID = true; //! AppData.ShowPFI_DeleteFileInstanceByID;
		ImGui::SetWindowFocus("Delete File Instance");
	}

	if (ImGui::Button("Encrypt File"))
	{
		AppData.ShowPFI_EncryptFile = true; //! AppData.ShowPFI_EncryptFile;
		ImGui::SetWindowFocus("Encrypt File");
	}

	if (ImGui::Button("Decrypt File"))
	{
		AppData.ShowPFI_DecryptFile = true; //! AppData.ShowPFI_DecryptFile;
		ImGui::SetWindowFocus("Decrypt File");
	}

	if (ImGui::Button("Delete All File Instances"))
	{
		AppData.ShowPFI_ConfirmDeleteAllFileInstancesPopup = true;
	}

	if (ImGui::Button("Close All"))
	{
		// AppData.ShowGUI_PersonalPasswordInfo = true;
		// AppData.ShowGUI_PersonalFileInfo = false;

		AppData.ShowPFI_ListAllFileInstance                = false;
		AppData.ShowPFI_CreateFileInstance                 = false;
		AppData.ShowPFI_DeleteFileInstanceByID             = false;
		AppData.ShowPFI_EncryptFile                        = false;
		AppData.ShowPFI_DecryptFile                        = false;
		AppData.ShowPFI_ConfirmDeleteAllFileInstancesPopup = false;
	}

	ImGui::End();
}
