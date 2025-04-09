#pragma once

/* ShowGUI PersonalPasswordInfo Part */

inline void ShowGUI_PersonalPasswordInfo(std::vector<char> &BufferLoginPassword, ApplicationData &AppData)
{
	ImGui::Begin("Personal Password Info");

	if (ImGui::Button("Create Password Instance"))
	{
		AppData.ShowPPI_CreatePasswordInstance = true; //! AppData.ShowPPI_CreatePasswordInstance;
		ImGui::SetWindowFocus("Create Password Instance");
	}

	if (ImGui::Button("Change Password Instance"))
	{
		AppData.ShowPPI_ChangePasswordInstance = true; //! AppData.ShowPPI_ChangePasswordInstance;
		ImGui::SetWindowFocus("Change Password Instance By ID");
	}

	if (ImGui::Button("List All Password Instance"))
	{
		AppData.ShowPPI_ListAllPasswordInstance = true; //! AppData.ShowPPI_ListAllPasswordInstance;
		ImGui::SetWindowFocus("List All Password Instance");
	}

	if (ImGui::Button("Delete Password Instance By ID"))
	{
		AppData.ShowPPI_DeletePasswordInstance = true; //! AppData.ShowPPI_DeletePasswordInstance;
	}

	if (ImGui::Button("Delete All Password Instance"))
	{
		AppData.ShowPPI_ConfirmDeleteAllPasswordInstance = true; //! AppData.ShowPPI_ConfirmDeleteAllPasswordInstance;
		ImGui::SetWindowFocus("Delete All Password Instance");
	}

	if (ImGui::Button("List Password Instance By ID"))
	{
		AppData.ShowPPI_FindPasswordInstanceByID = true; //! AppData.ShowPPI_FindPasswordInstanceByID;
		                                                 // ImGui::SetWindowFocus("List Password Instance By ID");
	}

	if (ImGui::Button("List Password Instance By Description"))
	{
		AppData.ShowPPI_FindPasswordInstanceByDescription = true; //! AppData.ShowPPI_FindPasswordInstanceByDescription;
		                                                          // ImGui::SetWindowFocus("List Password Instance By Description");
	}

	if (ImGui::Button("Change UUID(Master Key Material) With\n System Password"))
	{
		AppData.ShowPPI_ChangeInstanceMasterKeyWithSystemPassword = true; //! AppData.ShowPPI_ChangeInstanceMasterKeyWithSystemPassword;
		ImGui::SetWindowFocus("Change Master Key With System Password");
	}

	if (ImGui::Button("Close All"))
	{
		// AppData.ShowGUI_PersonalFileInfo = true;
		// AppData.ShowGUI_PersonalPasswordInfo = false;

		AppData.ShowPPI_CreatePasswordInstance                    = false;
		AppData.ShowPPI_ChangePasswordInstance                    = false;
		AppData.ShowPPI_ListAllPasswordInstance                   = false;
		AppData.ShowPPI_DeletePasswordInstance                    = false;
		AppData.ShowPPI_ConfirmDeleteAllPasswordInstance          = false;
		AppData.ShowPPI_FindPasswordInstanceByID                  = false;
		AppData.ShowPPI_FindPasswordInstanceByDescription         = false;
		AppData.ShowPPI_ChangeInstanceMasterKeyWithSystemPassword = false;
	}

	ImGui::End();
}

inline void ShowGUI_PPI_CreatePasswordInstance(std::vector<char> &BufferLoginPassword, ApplicationData &AppData)
{
	static auto cleanup = [](std::vector<char> &BufferLoginPassword, ApplicationData &AppData)
	{
		AppData.ShowPPI_CreatePasswordInstance = false;

		// Clear Application GUI State Data
		std::fill(AppData.ShowPPI_NewPassword.begin(), AppData.ShowPPI_NewPassword.end(), 0x00);
		std::fill(AppData.ShowPPI_Description.begin(), AppData.ShowPPI_Description.end(), 0x00);
		AppData.ShowPPI_EncryptionAlgorithms.clear();
		AppData.ShowPPI_DecryptionAlgorithms.clear();
	};

	if (ImGui::Begin("Create Password Instance"))
	{
		bool condition = true;
		ImGui::Text("System Password:");
		ImGui::InputText("##System Password", BufferLoginPassword.data(), BufferLoginPassword.size(), ImGuiInputTextFlags_Password);
		// todo:
		// 把验证的操作移到Input框的编辑完成的回调函数中，或者减少调用频率，每0.5秒更新一次，仅仅是为了显示提示信息，然后在button中再验证一遍，保证逻辑正确，这需要使用static变量或者在AppData中创建新的成员
		const bool correct_password = VerifyPassword(BufferLoginPassword, AppData.UserKey, AppData.UserData);
		VerifyPasswordText(correct_password);
		condition &= correct_password;

		ImGui::Separator();
		ImGui::Dummy(ImVec2(0.f, 3.f));

		ImGui::Text("New Password Text:");
		ImGui::InputText("##New Password Text", AppData.ShowPPI_NewPassword.data(), AppData.ShowPPI_NewPassword.size(), ImGuiInputTextFlags_None);

		const bool new_password_not_all_zero = std::any_of(AppData.ShowPPI_NewPassword.begin(), AppData.ShowPPI_NewPassword.end(), [](char c) { return c != 0x00; });
		if (!new_password_not_all_zero)
			ImGui::TextColored(ImVec4(0.9f, 0.1f, 0.0f, 1.0f), "Password must not be empty");
		condition &= new_password_not_all_zero;

		ImGui::Separator();
		ImGui::Dummy(ImVec2(0.f, 3.f));

		ImGui::Text("New Description:");
		ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(20, 8));
		ImGui::InputTextMultiline(
		    "##New Description",
		    AppData.ShowPPI_Description.data(),
		    AppData.ShowPPI_Description.size(),
		    ImVec2(400, 300),
		    ImGuiInputTextFlags_CtrlEnterForNewLine);
		ImGui::PopStyleVar();

		const bool is_algorithm_selected = ShowEncryptionAlgorithmGroup(AppData);
		condition &= is_algorithm_selected;

		ImGui::Dummy(ImVec2(0.f, 6.f));
		ImGui::Separator();
		const float remaining_height = ImGui::GetContentRegionAvail().y - ImGui::GetFrameHeightWithSpacing();
		const float btn_bummy_height = remaining_height > 140 ? 20 : remaining_height;

		ImGui::Dummy(ImVec2(0.f, btn_bummy_height));

		if (ImGui::Button("Create and Encrypt Password"))
		{
			if (condition)
			{
				Do_CreatePasswordInstance(BufferLoginPassword, AppData);
			}
			else
			{
				ImGui::OpenPopup("Invalid Input Conditions");
			}
		}

		ImGui::SameLine();

		if (ImGui::Button("Cancel"))
		{
			cleanup(BufferLoginPassword, AppData);
		}

		if (ImGui::BeginPopupModal("Invalid Input Conditions", nullptr, ImGuiWindowFlags_AlwaysAutoResize))
		{
			ImGui::Text("Invalid Input Conditions");
			ImGui::Separator();
			ImGui::Text(
			    "Please ensure:\n- System password is correct\n- New password is not empty\n- At least one algorithm "
			    "is selected");
			ImGui::Dummy(ImVec2(0.f, 10.f));
			if (ImGui::Button("OK", ImVec2(120, 0)))
			{
				ImGui::CloseCurrentPopup();
			}
			ImGui::EndPopup();
		}
	}
	ImGui::End();
}

inline void ShowGUI_PPI_ChangePasswordInstance(std::vector<char> &BufferLoginPassword, ApplicationData &AppData)
{
	if (ImGui::Begin("Change Password Instance By ID"))
	{
		bool condition = true;
		BufferLoginPassword.resize(2048, 0x00); // 我不太明白这里的意图是什么, 是为了清空buffer吗？ resize相同长度应该不会清空吧
		// std::fill(BufferLoginPassword.begin(), BufferLoginPassword.end(),0x00);
		// //每帧进行这种操作太耗时了，建议如果要清空密码，在执行完任何任务之后调用清理
		ImGui::Text("System Password:");
		ImGui::InputText("##System Password", BufferLoginPassword.data(), BufferLoginPassword.size(), ImGuiInputTextFlags_Password);
		condition &= VerifyPassword(BufferLoginPassword, AppData.UserKey, AppData.UserData);
		VerifyPasswordText(condition);

		ImGui::Separator();
		ImGui::Dummy(ImVec2(0.f, 3.f));

		ImGui::Text("Select Password Instance ID:");
		ImGui::InputScalar("##Select Password Instance ID", ImGuiDataType_U64, &AppData.ShowPPI_SelectedPasswordInstanceID);
		ImGui::Checkbox("Change Encrypted Password", &AppData.ShowPPI_ChangeEncryptedPassword);

		ImGui::Separator();
		ImGui::Dummy(ImVec2(0.f, 3.f));

		ImGui::Text("Change Description:");
		ImGui::InputTextMultiline(
		    "##Change Description",
		    AppData.ShowPPI_Description.data(),
		    AppData.ShowPPI_Description.size(),
		    ImVec2(400, 300),
		    ImGuiInputTextFlags_CtrlEnterForNewLine);

		const bool is_algorithm_selected = ShowEncryptionAlgorithmGroup(AppData);
		condition &= is_algorithm_selected;

		ImGui::Dummy(ImVec2(0.f, 6.f));
		ImGui::Separator();
		ImGui::Dummy(ImVec2(0.f, 3.f));

		ImGui::Text("Change Password Text:");
		ImGui::InputText("##Change Password Text", AppData.ShowPPI_Password.data(), AppData.ShowPPI_Password.size(), ImGuiInputTextFlags_None);

		const bool new_password_not_all_zero = std::any_of(AppData.ShowPPI_Password.begin(), AppData.ShowPPI_Password.end(), [](char c) { return c != 0x00; });
		if (!new_password_not_all_zero)
			ImGui::TextColored(ImVec4(0.9f, 0.1f, 0.0f, 1.0f), "Password must not be empty");
		condition &= new_password_not_all_zero;

		ImGui::Dummy(ImVec2(0.f, 8.f));
		ImGui::Separator();
		const float remaining_height = ImGui::GetContentRegionAvail().y - ImGui::GetFrameHeightWithSpacing() - 30.f;
		const float btn_bummy_height = remaining_height > 180 ? 20 : remaining_height;

		ImGui::Dummy(ImVec2(0.f, btn_bummy_height));

		if (ImGui::Button("Flush Password Instance Description"))
		{
			AppData.ShowPPI_Description = AppData.PersonalPasswordInfo_.FindPasswordInstanceDescriptionByID(AppData.ShowPPI_SelectedPasswordInstanceID);
			AppData.ShowPPI_Description.resize(2048, 0x00);
		}

		if (ImGui::Button("Change Password Instance"))
		{
			if (condition)
			{
				Do_ChangePasswordInstance(BufferLoginPassword, AppData);
			}
			else
			{
				ImGui::OpenPopup("Invalid Input Conditions");
			}
		}

		ImGui::SameLine();

		if (ImGui::Button("Cancel"))
		{
			AppData.ShowPPI_ChangePasswordInstance = false;
			// cleanup(BufferLoginPassword, AppData);
		}

		if (ImGui::BeginPopupModal("Invalid Input Conditions", nullptr, ImGuiWindowFlags_AlwaysAutoResize))
		{
			ImGui::Text("Invalid Input Conditions");
			ImGui::Separator();
			ImGui::Text(
			    "Please ensure:\n- System password is correct\n- New password is not empty\n- At least one algorithm "
			    "is selected");
			ImGui::Dummy(ImVec2(0.f, 10.f));
			if (ImGui::Button("OK", ImVec2(120, 0)))
			{
				ImGui::CloseCurrentPopup();
			}
			ImGui::EndPopup();
		}
	}
	ImGui::End();

	if (AppData.ShowPPI_ChangePasswordInstanceSuccessful)
		ImGui::OpenPopup("Password Instance Is Changed");

	if (ImGui::BeginPopup("Password Instance Is Changed", ImGuiWindowFlags_AlwaysAutoResize))
	{
		ImGui::Text("Password Instance Changed Successfully!");
		if (ImGui::Button("OK"))
		{
			ImGui::CloseCurrentPopup();
			// AppData.ShowPPI_ChangePasswordInstance = false;
			AppData.ShowPPI_ChangePasswordInstanceSuccessful = false;
		}
		ImGui::EndPopup();
	}

	if (AppData.ShowPPI_ChangePasswordInstanceFailed)
		ImGui::OpenPopup("Password Instance Is Not Changed");
	if (ImGui::BeginPopup("Password Instance Is Not Changed", ImGuiWindowFlags_AlwaysAutoResize))
	{
		ImGui::Text("Failed to Change Password Instance");
		if (ImGui::Button("OK"))
		{
			ImGui::CloseCurrentPopup();
			// AppData.ShowPPI_ChangePasswordInstance = false;
			AppData.ShowPPI_ChangePasswordInstanceFailed = false;
		}
		ImGui::EndPopup();
	}
}

inline void ShowGUI_PPI_ListAllPasswordInstance(std::vector<char> &BufferLoginPassword, ApplicationData &AppData)
{
	if (ImGui::Begin("List All Password Instance"))
	{
		BufferLoginPassword.resize(2048, 0x00);
		ImGui::Text("System Password:");
		ImGui::InputText("##System Password", BufferLoginPassword.data(), BufferLoginPassword.size(), ImGuiInputTextFlags_Password);

		VerifyPasswordText(VerifyPassword(BufferLoginPassword, AppData.UserKey, AppData.UserData));

		ImGui::Checkbox("List All", &AppData.ShowPPI_ListAllPasswordInstanceData);

		if (ImGui::Button("Close"))
		{
			AppData.ShowPPI_ListAllPasswordInstance = false;
		}

		if (AppData.ShowPPI_ListAllPasswordInstanceData)
		{
			auto new_end = std::find_if(BufferLoginPassword.rbegin(), BufferLoginPassword.rend(), [](char character) { return character != '\x00'; });

			BufferLoginPassword.erase(new_end.base(), BufferLoginPassword.end());

			const bool ValidPassword = VerifyPassword(BufferLoginPassword, AppData.UserKey, AppData.UserData);

			if (!AppData.UserKey.RandomUUID.empty() && !BufferLoginPassword.empty() && ValidPassword)
			{
				if (!AppData.IsPasswordInfoTemporaryValid)
				{
					Do_DecryptionAllPasswordInstance(BufferLoginPassword, AppData);
				}

				AppData.IsPasswordInfoTemporaryValid = true;
				auto &PassswordInstances             = AppData.PersonalPasswordInfo_.GetPasswordInstances();

				// 循环遍历每个PersonalPasswordInstance并在UI中显示
				for (const auto &Instance : PassswordInstances)
				{
					ImGui::Text("ID: %lu", Instance.ID);
					ImGui::Text("New Description: %s", Instance.Description.data());
					ImGui::Text("Decrypted Password: %s", Instance.DecryptedPassword.data());

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
		// 关闭或隐藏GUI时清除解密的密码
		if (!AppData.ShowPPI_ListAllPasswordInstanceData)
		{
			auto &PassswordInstances = AppData.PersonalPasswordInfo_.GetPasswordInstances();

			for (auto &instance : PassswordInstances)
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

inline void ShowGUI_PPI_DeletePasswordInstance(std::vector<char> &BufferLoginPassword, ApplicationData &AppData)
{
	if (AppData.ShowPPI_DeletePasswordInstance)
		ImGui::OpenPopup("Delete Password Instance");

	if (ImGui::BeginPopupModal("Delete Password Instance", &AppData.ShowPPI_DeletePasswordInstance, ImGuiWindowFlags_AlwaysAutoResize))
	{
		// BufferLoginPassword.resize( 2048, 0x00 );
		std::fill(BufferLoginPassword.begin(), BufferLoginPassword.end(), 0x00);
		ImGui::Text("Password Instance ID:");
		ImGui::InputScalar("##Password Instance ID", ImGuiDataType_U64, &AppData.ShowPPI_SelectedPasswordInstanceID);

		ImGui::Text("Please enter system password to confirm:");
		ImGui::InputText("System Password", BufferLoginPassword.data(), BufferLoginPassword.size(), ImGuiInputTextFlags_Password);

		bool correct_password = false;

		if (ImGui::Button("Delete"))
		{
			correct_password = VerifyPassword(BufferLoginPassword, AppData.UserKey, AppData.UserData);

			if (AppData.PersonalPasswordInfo_.RemovePasswordInstance(AppData.ShowPPI_SelectedPasswordInstanceID))
			{
				AppData.PersonalPasswordInfo_.Serialization(AppData.PersonalPasswordInfoFilePath);
				AppData.IsPasswordInfoTemporaryValid = false;
				ImGui::CloseCurrentPopup();
				AppData.ShowPPI_DeletePasswordInstance = false;
			}
		}

		ImGui::SameLine();

		if (ImGui::Button("Cancel"))
		{
			AppData.ShowPPI_DeletePasswordInstance = false;
		}

		VerifyPasswordText(correct_password);

		ImGui::EndPopup();
	}
}

inline void ShowGUI_PPI_DeleteAllPasswordInstance(std::vector<char> &BufferLoginPassword, ApplicationData &AppData)
{
	if (AppData.ShowPPI_ConfirmDeleteAllPasswordInstance)
		ImGui::OpenPopup("Confirm Delete All Password Instance");

	if (ImGui::BeginPopupModal("Confirm Delete All Password Instance", &AppData.ShowPPI_ConfirmDeleteAllPasswordInstance, ImGuiWindowFlags_AlwaysAutoResize))
	{
		BufferLoginPassword.resize(2048, 0x00);

		ImGui::Text("Are you sure you want to delete all instances?");
		ImGui::Text("Please enter system password to confirm:");

		ImGui::InputText("System Password", BufferLoginPassword.data(), BufferLoginPassword.size(), ImGuiInputTextFlags_Password);

		bool correct_password = false;

		if (ImGui::Button("Delete All"))
		{
			correct_password = VerifyPassword(BufferLoginPassword, AppData.UserKey, AppData.UserData);

			AppData.PersonalPasswordInfo_.RemoveAllPasswordInstance();
			AppData.PersonalPasswordInfo_.Serialization(AppData.PersonalPasswordInfoFilePath);

			AppData.IsPasswordInfoTemporaryValid = false;
			ImGui::CloseCurrentPopup();
			AppData.ShowPPI_ConfirmDeleteAllPasswordInstance = false;
		}

		ImGui::SameLine();

		if (ImGui::Button("Cancel"))
		{
			AppData.ShowPPI_ConfirmDeleteAllPasswordInstance = false;
		}

		VerifyPasswordText(correct_password);

		ImGui::EndPopup();
	}
}

inline void ShowGUI_PPI_FindPasswordInstanceByID(std::vector<char> &BufferLoginPassword, ApplicationData &AppData)
{
	if (AppData.ShowPPI_FindPasswordInstanceByID)
	{
		ImGui::OpenPopup("List Password Instance By ID");
	}
	else if (AppData.BUFFER_ShowGUI_PPI_FindPasswordInstanceByID.size() > 0 && AppData.BUFFER_ShowGUI_PPI_FindPasswordInstanceByID[0] != 0x00)
	{
		std::fill(AppData.BUFFER_ShowGUI_PPI_FindPasswordInstanceByID.begin(), AppData.BUFFER_ShowGUI_PPI_FindPasswordInstanceByID.end(), 0x00);
	}

	if (ImGui::BeginPopupModal("List Password Instance By ID", &AppData.ShowPPI_FindPasswordInstanceByID, ImGuiWindowFlags_AlwaysAutoResize))
	{
		BufferLoginPassword.resize(2048, 0x00);
		ImGui::Text("System Password:");
		ImGui::InputText("##System Password", BufferLoginPassword.data(), BufferLoginPassword.size(), ImGuiInputTextFlags_Password);
		ImGui::Text("Password Instance ID:");
		ImGui::InputScalar("##Password Instance ID", ImGuiDataType_U64, &AppData.ShowPPI_SelectedPasswordInstanceID);

		const bool ValidPassword = VerifyPassword(BufferLoginPassword, AppData.UserKey, AppData.UserData);

		if (ImGui::Button("find") && AppData.ShowPPI_FindPasswordInstanceByID && ValidPassword)
		{
			Do_FindPasswordInstanceByID(BufferLoginPassword, AppData);
		}

		ImGui::SameLine();

		if (ImGui::Button("Hide"))
		{
			std::fill(AppData.BUFFER_ShowGUI_PPI_FindPasswordInstanceByID.begin(), AppData.BUFFER_ShowGUI_PPI_FindPasswordInstanceByID.end(), 0x00);
		}

		ImGui::SameLine();

		if (ImGui::Button("close"))
		{
			AppData.ShowPPI_FindPasswordInstanceByID = false;
			ImGui::CloseCurrentPopup();
		}

		if (!AppData.BUFFER_ShowGUI_PPI_FindPasswordInstanceByID.empty() && AppData.ShowPPI_FindPasswordInstanceByID && ValidPassword)
		{
			ImGui::TextUnformatted(AppData.BUFFER_ShowGUI_PPI_FindPasswordInstanceByID.data());
		}

		ImGui::EndPopup();
	}
}

inline void ShowGUI_PPI_FindPasswordInstanceByDescription(std::vector<char> &BufferLoginPassword, ApplicationData &AppData)
{
	if (AppData.ShowPPI_FindPasswordInstanceByDescription)
	{
		ImGui::OpenPopup("List Password Instance By Description");
	}
	else if (AppData.BUFFER_ShowGUI_PPI_FindPasswordInstanceByDescription.size() > 0 && AppData.BUFFER_ShowGUI_PPI_FindPasswordInstanceByDescription[0] != 0x00)
	{
		std::fill(AppData.BUFFER_ShowGUI_PPI_FindPasswordInstanceByDescription.begin(), AppData.BUFFER_ShowGUI_PPI_FindPasswordInstanceByDescription.end(), 0x00);
	}

	if (ImGui::BeginPopupModal("List Password Instance By Description", &AppData.ShowPPI_FindPasswordInstanceByDescription, ImGuiWindowFlags_AlwaysAutoResize))
	{
		BufferLoginPassword.resize(2048, 0x00);
		ImGui::Text("System Password:");
		ImGui::InputText("##System Password", BufferLoginPassword.data(), BufferLoginPassword.size(), ImGuiInputTextFlags_Password);

		AppData.ShowPPI_SelectedPasswordInstanceDescription.resize(2048, 0x00);

		ImGui::Text("Password Instance Description:");
		ImGui::InputTextMultiline(
		    "##Password Instance Description",
		    AppData.ShowPPI_SelectedPasswordInstanceDescription.data(),
		    AppData.ShowPPI_SelectedPasswordInstanceDescription.size(),
		    ImVec2(400, 400),
		    ImGuiInputTextFlags_CtrlEnterForNewLine);

		const bool ValidPassword = VerifyPassword(BufferLoginPassword, AppData.UserKey, AppData.UserData);

		if (ImGui::Button("find") && AppData.ShowPPI_FindPasswordInstanceByDescription && ValidPassword)
		{
			Do_FindPasswordInstanceByDescription(BufferLoginPassword, AppData);
		}

		ImGui::SameLine();

		if (ImGui::Button("Hide"))
		{
			std::fill(AppData.BUFFER_ShowGUI_PPI_FindPasswordInstanceByDescription.begin(), AppData.BUFFER_ShowGUI_PPI_FindPasswordInstanceByDescription.end(), 0x00);
		}

		ImGui::SameLine();

		if (ImGui::Button("close"))
		{
			AppData.ShowPPI_FindPasswordInstanceByDescription = false;
			ImGui::CloseCurrentPopup();
		}

		if (!AppData.BUFFER_ShowGUI_PPI_FindPasswordInstanceByDescription.empty() && AppData.ShowPPI_FindPasswordInstanceByDescription && ValidPassword)
		{
			ImGui::TextUnformatted(AppData.BUFFER_ShowGUI_PPI_FindPasswordInstanceByDescription.data());
		}

		ImGui::EndPopup();
	}
}

inline void ShowGUI_PPI_ChangeInstanceMasterKeyWithSystemPassword(std::vector<char> &BufferLoginPassword, ApplicationData &AppData)
{
	ImGui::Begin("Change Master Key With System Password");

	if (AppData.ShowPPI_ChangeInstanceMasterKeyWithSystemPassword)
	{
		// 密码输入框
		ImGui::Text("Old System Password:");
		ImGui::InputText("##System Old Password", BufferLoginPassword.data(), BufferLoginPassword.size(), ImGuiInputTextFlags_Password);
		ImGui::Text("Confirm Old System Password:");
		// FIXME: 这里不该使用 AppData.ShowPPI_Password 和 Change Password Text 重复了
		ImGui::InputText("##Confirm System Old Password", AppData.ShowPPI_Password.data(), AppData.ShowPPI_Password.size(), ImGuiInputTextFlags_Password);
		ImGui::Text("New System Password:");
		ImGui::InputText("##New System Password", AppData.ShowPPI_NewPassword.data(), AppData.ShowPPI_NewPassword.size(), ImGuiInputTextFlags_Password);

		bool correct_password = false;

		if (ImGui::Button("Change Password"))
		{
			correct_password = VerifyPassword(BufferLoginPassword, AppData.UserKey, AppData.UserData);

			Do_ChangeInstanceMasterKeyWithSystemPassword(BufferLoginPassword, AppData);

			BufferLoginPassword.resize(2048, 0x00);
			AppData.ShowPPI_ChangeInstanceMasterKeyWithSystemPassword = false;
		}

		ImGui::SameLine();

		if (ImGui::Button("Cancel"))
		{
			AppData.ShowPPI_ChangeInstanceMasterKeyWithSystemPassword = false;
		}

		VerifyPasswordText(correct_password);
	}

	ImGui::End();

	// Other Popup Logic for Success and Failure
	if (AppData.ShowPPI_SystemPasswordChangeSuccessful)
		ImGui::OpenPopup("Change System Password Successful");
	if (ImGui::BeginPopup("Change System Password Successful", ImGuiWindowFlags_AlwaysAutoResize))
	{
		ImGui::Text("System password has been changed successfully.");
		if (ImGui::Button("OK"))
		{
			ImGui::CloseCurrentPopup();
			AppData.ShowPPI_SystemPasswordChangeSuccessful            = false;
			AppData.ShowPPI_ChangeInstanceMasterKeyWithSystemPassword = false;
		}
		ImGui::EndPopup();
	}

	if (AppData.ShowPPI_SystemPasswordNotChange)
		ImGui::OpenPopup("System Password Not Changed");
	if (ImGui::BeginPopup("System Password Not Changed", ImGuiWindowFlags_AlwaysAutoResize))
	{
		ImGui::Text("New system password should be different from the old system password.");
		if (ImGui::Button("OK"))
		{
			ImGui::CloseCurrentPopup();
			AppData.ShowPPI_SystemPasswordNotChange                   = false;
			AppData.ShowPPI_ChangeInstanceMasterKeyWithSystemPassword = false;
		}
		ImGui::EndPopup();
	}

	if (AppData.ShowPPI_SystemPasswordChangeFailed)
		ImGui::OpenPopup("Change System Password Failed");
	if (ImGui::BeginPopup("Change System Password Failed", ImGuiWindowFlags_AlwaysAutoResize))
	{
		ImGui::Text("The old system password you entered is incorrect.");
		if (ImGui::Button("OK"))
		{
			ImGui::CloseCurrentPopup();
			AppData.ShowPPI_SystemPasswordChangeFailed                = false;
			AppData.ShowPPI_ChangeInstanceMasterKeyWithSystemPassword = false;
		}
		ImGui::EndPopup();
	}
}
