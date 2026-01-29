#pragma once

/* ShowGUI PersonalFileInfo Part */

inline std::string MakeTrimmedPasswordString( const std::vector<char>& BufferLoginPassword )
{
	std::string Password( BufferLoginPassword.begin(), BufferLoginPassword.end() );
	auto		new_end = std::find_if( Password.rbegin(), Password.rend(), []( char character ) { return character != '\x00'; } );
	Password.erase( new_end.base(), Password.end() );
	return Password;
}

inline std::filesystem::path WeaklyCanonicalOrNormalForUI( const std::filesystem::path& Path )
{
	std::error_code		  ErrorCode;
	std::filesystem::path CanonicalPath = std::filesystem::weakly_canonical( Path, ErrorCode );
	if ( ErrorCode )
	{
		return Path.lexically_normal();
	}

	return CanonicalPath.lexically_normal();
}

inline bool IsSameOrSubPathForUI( const std::filesystem::path& PossibleChildPath, const std::filesystem::path& PossibleParentPath )
{
	std::filesystem::path ChildPath = WeaklyCanonicalOrNormalForUI( PossibleChildPath );
	std::filesystem::path ParentPath = WeaklyCanonicalOrNormalForUI( PossibleParentPath );

	auto ChildIterator = ChildPath.begin();
	auto ParentIterator = ParentPath.begin();

	for ( ; ParentIterator != ParentPath.end(); ++ParentIterator, ++ChildIterator )
	{
		if ( ChildIterator == ChildPath.end() || *ChildIterator != *ParentIterator )
		{
			return false;
		}
	}

	return true;
}

inline std::string BuildFolderOperationInputError( bool CorrectPassword, const std::filesystem::path& SourceFolderPath, const std::filesystem::path& TargetFolderPath, const char* SourceFolderDescription )
{
	if ( !CorrectPassword )
	{
		return "System password is incorrect.";
	}

	if ( SourceFolderPath.empty() || TargetFolderPath.empty() )
	{
		return "Please select both source and target folders.";
	}

	if ( IsSameOrSubPathForUI( TargetFolderPath, SourceFolderPath ) )
	{
		return std::string( "Target folder must not be the same as or inside the " ) + SourceFolderDescription + ".";
	}

	return {};
}

inline void ShowPFI_FolderInputErrorPopup( const char* PopupTitle, std::string& Message )
{
	if ( Message.empty() )
	{
		return;
	}

	ImGui::SetNextWindowSizeConstraints( ImVec2( 560.0f, 0.0f ), ImVec2( 900.0f, 1000.0f ) );

	if ( ImGui::BeginPopupModal( PopupTitle, nullptr, ImGuiWindowFlags_AlwaysAutoResize ) )
	{
		ImGui::TextUnformatted( "Invalid Input Conditions" );
		ImGui::Separator();
		ImGui::PushTextWrapPos( ImGui::GetCursorPosX() + 520.0f );
		ImGui::TextUnformatted( Message.c_str() );
		ImGui::PopTextWrapPos();
		ImGui::Spacing();

		if ( ImGui::Button( "Ok" ) )
		{
			Message.clear();
			ImGui::CloseCurrentPopup();
		}

		ImGui::EndPopup();
	}
}

inline void ShowPFI_DirectoryOperationResultPopup( const char* PopupTitle, bool& PopupFlag, const PersonalFileInfo::DirectoryOperationResult& Result )
{
	if ( PopupFlag )
	{
		ImGui::OpenPopup( PopupTitle );
	}

	if ( ImGui::BeginPopupModal( PopupTitle, &PopupFlag, ImGuiWindowFlags_AlwaysAutoResize ) )
	{
		if ( !Result.Message.empty() )
		{
			ImGui::TextWrapped( "%s", Result.Message.c_str() );
			ImGui::Separator();
		}

		ImGui::Text( "Succeeded files: %llu", static_cast<unsigned long long>( Result.SucceededFiles ) );
		ImGui::Text( "Failed files: %llu", static_cast<unsigned long long>( Result.FailedFiles ) );
		ImGui::Text( "Skipped files: %llu", static_cast<unsigned long long>( Result.SkippedFiles ) );

		if ( !Result.FailedPaths.empty() )
		{
			ImGui::Separator();
			ImGui::TextUnformatted( "Failed path samples:" );
			for ( const auto& FailedPath : Result.FailedPaths )
			{
				ImGui::TextWrapped( "%s", FailedPath.c_str() );
			}
		}

		if ( !Result.SkippedPaths.empty() )
		{
			ImGui::Separator();
			ImGui::TextUnformatted( "Skipped path samples:" );
			for ( const auto& SkippedPath : Result.SkippedPaths )
			{
				ImGui::TextWrapped( "%s", SkippedPath.c_str() );
			}
		}

		if ( ImGui::Button( "Ok" ) )
		{
			PopupFlag = false;
			ImGui::CloseCurrentPopup();
		}

		ImGui::EndPopup();
	}
}

inline void QueuePFI_DirectoryOperation( ApplicationData& AppData, std::string Token, std::uint64_t FileInstanceID, std::filesystem::path SourceFolderPath, std::filesystem::path TargetFolderPath, bool Encrypt )
{
	static const auto task_directory_operation = []( ApplicationData& AppData, std::string Token, std::uint64_t FileInstanceID, std::filesystem::path SourceFolderPath, std::filesystem::path TargetFolderPath, bool Encrypt ) {
		SetProgressTarget( AppData, 0.0f, 0.05f );

		auto FileInstance = AppData.PersonalFileObject.GetFileInstanceByID( FileInstanceID );
		if ( !FileInstance.has_value() )
		{
			AppData.LastFileDirectoryOperationResult = PersonalFileInfo::DirectoryOperationResult {};
			AppData.LastFileDirectoryOperationResult.Message = "Invalid File Instance.";
			if ( Encrypt )
			{
				AppData.ShowPFI_EncryptFolderResultPopup = true;
			}
			else
			{
				AppData.ShowPFI_DecryptFolderResultPopup = true;
			}
			if ( !Token.empty() )
			{
				memory_set_no_optimize_function<0x00>( Token.data(), Token.size() * sizeof( char ) );
			}
			return;
		}

		SetProgressTarget( AppData, 0.05f, 0.90f );

		if ( Encrypt )
		{
			AppData.LastFileDirectoryOperationResult = AppData.PersonalFileObject.EncryptDirectory( Token, FileInstance.value().get(), SourceFolderPath, TargetFolderPath );
			AppData.ShowPFI_EncryptFolderResultPopup = true;
		}
		else
		{
			AppData.LastFileDirectoryOperationResult = AppData.PersonalFileObject.DecryptDirectory( Token, FileInstance.value().get(), SourceFolderPath, TargetFolderPath );
			AppData.ShowPFI_DecryptFolderResultPopup = true;
		}

		SetProgressTarget( AppData, 0.90f, 1.0f );
		if ( !Token.empty() )
		{
			memory_set_no_optimize_function<0x00>( Token.data(), Token.size() * sizeof( char ) );
		}
	};

	static const auto async_task = []( ApplicationData& AppData, std::string Token, std::uint64_t FileInstanceID, std::filesystem::path SourceFolderPath, std::filesystem::path TargetFolderPath, bool Encrypt, const std::source_location& loc ) {
		DropIfBusy( AppData.TaskInProgress, loc, task_directory_operation, std::ref( AppData ), std::move( Token ), FileInstanceID, std::move( SourceFolderPath ), std::move( TargetFolderPath ), Encrypt );
	};

	if ( !AppData.TaskInProgress )
	{
		std::scoped_lock lock( CurrentApplicationData.mutex_task );
		CurrentApplicationData.current_task = std::bind( async_task, std::ref( AppData ), std::move( Token ), FileInstanceID, std::move( SourceFolderPath ), std::move( TargetFolderPath ), Encrypt, std::source_location::current() );
	}
}

// FIXME: 处理创建成功，失败后的弹窗，处理文件实例覆盖的问题，需要创建一个模态框，向用户确认是否覆盖，目前ID是以插入的方式添加的，会导致后面的ID跟着漂移
inline void ShowGUI_PFI_CreateFileInstance( ApplicationData& AppData )
{
	if ( AppData.ShowPFI_CreateFileInstance )
	{
		if ( ImGui::Begin( "Create File Instance", &AppData.ShowPFI_CreateFileInstance, ImGuiWindowFlags_AlwaysAutoResize ) )
		{
			ImGui::Text( "File Instance ID:" );
			ImGui::InputScalar( "##File Instance ID", ImGuiDataType_U64, &AppData.ShowPFI_SelectedFileInstanceID );

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
				AppData.ShowPFI_DecryptionAlgorithms.resize( AppData.ShowPFI_EncryptionAlgorithms.size(), "" );
				std::reverse_copy( AppData.ShowPFI_EncryptionAlgorithms.begin(), AppData.ShowPFI_EncryptionAlgorithms.end(), AppData.ShowPFI_DecryptionAlgorithms.begin() );

				// 创建文件实例
				auto FileInstance = AppData.PersonalFileObject.CreateFileInstance( MakeTokenString( AppData.UserKey.RandomUUID, AppData.ShowPPI_Password ), AppData.ShowPFI_EncryptionAlgorithms, AppData.ShowPFI_DecryptionAlgorithms );

				AppData.PersonalFileObject.AppendFileInstance( FileInstance );
				AppData.PersonalFileObject.Serialization( AppData.PersonalDataInfoFilePath );

				//AppData.ShowPFI_CreateFileInstance = false;

				// 清除 GUI 状态数据
				AppData.ShowPFI_EncryptionAlgorithms.clear();
				AppData.ShowPFI_DecryptionAlgorithms.clear();
			}

			ImGui::SameLine();

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
	if ( ImGui::Begin( "List All File Instances" ) )
	{
		ImGui::Checkbox( "List All", &AppData.ShowPFI_ListAllFileInstanceData );

		if ( ImGui::Button( "Close" ) )
		{
			AppData.ShowPFI_ListAllFileInstance = false;
		}

		// 控制文件实例数据的显示
		if ( AppData.ShowPFI_ListAllFileInstanceData )
		{
			auto& FileInstances = AppData.PersonalFileObject.GetFileInstances();

			// 遍历每个 PersonalFileInstance 并显示相关信息
			for ( const auto& Instance : FileInstances )
			{
				ImGui::Text( "ID: %lu", Instance.ID );
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

inline void ShowGUI_PFI_DeleteFileInstance( ApplicationData& AppData )
{
	if ( AppData.ShowPFI_DeleteFileInstanceByID )
	{
		if ( ImGui::Begin( "Delete File Instance", &AppData.ShowPFI_DeleteFileInstanceByID, ImGuiWindowFlags_AlwaysAutoResize ) )
		{
			ImGui::Text( "File Instance ID to Delete" );
			ImGui::InputScalar( "##File Instance ID to Delete", ImGuiDataType_U64, &AppData.ShowPFI_SelectedFileInstanceID );

			if ( ImGui::Button( "Delete" ) )
			{
				if ( AppData.PersonalFileObject.RemoveFileInstance( AppData.ShowPFI_SelectedFileInstanceID ) )
				{
					AppData.PersonalFileObject.Serialization( AppData.PersonalDataInfoFilePath );
				}

				AppData.ShowPFI_DeleteFileInstanceByID = false;
			}

			ImGui::SameLine();

			if ( ImGui::Button( "Cancel" ) )
			{
				AppData.ShowPFI_DeleteFileInstanceByID = false;
			}
		}
		ImGui::End();
	}
}

inline void ShowGUI_PFI_ConfirmDeleteAllFileInstances( ApplicationData& AppData )
{
	if ( AppData.ShowPFI_ConfirmDeleteAllFileInstancesPopup )
	{
		ImGui::OpenPopup( "Confirm Delete All File Instances" );
	}
	if ( ImGui::BeginPopupModal( "Confirm Delete All File Instances", &AppData.ShowPFI_ConfirmDeleteAllFileInstancesPopup, ImGuiWindowFlags_AlwaysAutoResize ) )
	{
		ImGui::Text( "Are you sure you want to delete all file instances?" );

		if ( ImGui::Button( "Delete All" ) )
		{
			AppData.PersonalFileObject.RemoveAllFileInstances();
			AppData.PersonalFileObject.Serialization( AppData.PersonalDataInfoFilePath );
			AppData.ShowPFI_ConfirmDeleteAllFileInstancesPopup = false;
			ImGui::CloseCurrentPopup();
		}

		ImGui::SameLine();

		if ( ImGui::Button( "Cancel" ) )
		{
			AppData.ShowPFI_ConfirmDeleteAllFileInstancesPopup = false;
			ImGui::CloseCurrentPopup();
		}

		ImGui::EndPopup();
	}
}

inline void ShowGUI_PFI_EncryptFile( std::vector<char>& BufferLoginPassword, ApplicationData& AppData )
{
	if ( AppData.ShowPFI_EncryptFile )
	{
		if ( ImGui::Begin( "Encrypt File", &AppData.ShowPFI_EncryptFile, ImGuiWindowFlags_AlwaysAutoResize ) )
		{
			if ( BufferLoginPassword.size() != TEXT_BUFFER_CAPACITY )
			{
				//When you clean up sensitive data, you need to reset it to its original size because each time you clean up sensitive data, you will create a new single character buffer that is smaller than the original size and overwrite it.
				//So it needs to be reset to the original capacity size!!!! Otherwise there will be problems entering passwords here.
				BufferLoginPassword.resize( TEXT_BUFFER_CAPACITY, 0x00 );
			}

			ImGui::Text( "System Password:" );
			ImGui::InputText( "##System Password", BufferLoginPassword.data(), BufferLoginPassword.size(), ImGuiInputTextFlags_Password );
			// 选择文件实例
			ImGui::Text( "Select File Instance ID:" );
			ImGui::InputScalar( "##Select File Instance ID", ImGuiDataType_U64, &AppData.ShowPFI_SelectedFileInstanceID );

			const bool correct_password = VerifyPassword( BufferLoginPassword, AppData.UserKey, AppData.UserData );
			VerifyPasswordText( correct_password );

			//if (!AppData.IsSourceFileSelected)
			{
				// 选择源文件
				FileDialogCallback(
					"Select File to Encrypt", AppData.IsOriginalFileSelected, false,
					[]( const std::filesystem::path& in_path, std::filesystem::path& out_path, bool& result ) {
						out_path = in_path;
						result = !out_path.empty();
					},
					std::ref( AppData.SourceFilePath ), std::ref( AppData.IsOriginalFileSelected ) );
			}

			//if (!AppData.IsEncryptedFileSelected)
			{
				// 选择加密文件
				FileDialogCallback(
					"Save Encrypted File", AppData.IsTargetEncryptedFileSelected, true,
					[]( const std::filesystem::path& SelectedPath, std::filesystem::path& out_path, bool& result ) {
						out_path = SelectedPath;
						result = !out_path.empty();
					},
					std::ref( AppData.TargetEncryptedFilePath ), std::ref( AppData.IsTargetEncryptedFileSelected ) );
			}

			static bool Success = false;
			if ( ImGui::Button( "Encrypt" ) )
			{
				if ( !correct_password )
				{
					ImGui::OpenPopup( "Invalid Input Conditions" );
				}
				else if ( AppData.SourceFilePath.empty() || AppData.TargetEncryptedFilePath.empty() )
				{
					ImGui::OpenPopup( "Invalid Input Conditions" );
				}
				else
				{
					std::string Password = MakeTrimmedPasswordString( BufferLoginPassword );

					// 查找对应的文件实例
					auto FileInstance = AppData.PersonalFileObject.GetFileInstanceByID( AppData.ShowPFI_SelectedFileInstanceID );

					if ( FileInstance.has_value() )
					{
						Success = AppData.PersonalFileObject.EncryptFile( MakeTokenString( AppData.UserKey.RandomUUID, Password ), FileInstance.value().get(), AppData.SourceFilePath, AppData.TargetEncryptedFilePath );

						AppData.SourceFilePath.clear();
						AppData.TargetEncryptedFilePath.clear();
						AppData.ShowPFI_EncryptFileResultPopup = true;
					}
					else
					{
						ImGui::OpenPopup( "Invalid File Instance" );
					}

					if ( !Password.empty() )
					{
						memory_set_no_optimize_function<0x00>( Password.data(), Password.size() * sizeof( char ) );
					}
				}

				AppData.IsOriginalFileSelected = false;
				AppData.IsTargetEncryptedFileSelected = false;
			}

			if ( ImGui::BeginPopupModal( "Invalid Input Conditions", nullptr, ImGuiWindowFlags_AlwaysAutoResize ) )
			{
				ImGui::Text( "Invalid Input Conditions" );
				ImGui::Separator();
				ImGui::Text( "Please ensure the system password is correct and both file paths are selected." );
				if ( ImGui::Button( "Ok" ) )
				{
					ImGui::CloseCurrentPopup();
				}
				ImGui::EndPopup();
			}

			if ( ImGui::BeginPopupModal( "Invalid File Instance", nullptr, ImGuiWindowFlags_AlwaysAutoResize ) )
			{
				ImGui::Text( "Invalid File Instance" );

				if ( ImGui::Button( "Ok" ) )
				{
					ImGui::CloseCurrentPopup();
					AppData.IsOriginalFileSelected = false;
					AppData.IsDecryptedFileSelected = false;
				}
				ImGui::EndPopup();
			}

			if ( AppData.ShowPFI_EncryptFileResultPopup )
			{
				ImGui::OpenPopup( "Encrypt File Result" );
			}

			if ( ImGui::BeginPopupModal( "Encrypt File Result", &AppData.ShowPFI_EncryptFileResultPopup, ImGuiWindowFlags_AlwaysAutoResize ) )
			{

				ImGui::Text( Success ? "File encryption successfully." : "File encryption failed." );

				if ( ImGui::Button( "Ok" ) )
				{
					AppData.ShowPFI_EncryptFileResultPopup = false;
					Success = false;
					ImGui::CloseCurrentPopup();
				}
				ImGui::EndPopup();
				memory_set_no_optimize_function<0x00>( BufferLoginPassword.data(), BufferLoginPassword.size() );
				AppData.IsTargetEncryptedFileSelected = false;
				AppData.IsDecryptedFileSelected = false;
			}

			if ( ImGui::Button( "Close" ) )
			{
				memory_set_no_optimize_function<0x00>( BufferLoginPassword.data(), BufferLoginPassword.size() );
				AppData.ShowPFI_EncryptFile = false;

				AppData.IsOriginalFileSelected = false;
				AppData.IsDecryptedFileSelected = false;
			}
		}
		ImGui::End();
	}
}

inline void ShowGUI_PFI_DecryptFile( std::vector<char>& BufferLoginPassword, ApplicationData& AppData )
{
	if ( AppData.ShowPFI_DecryptFile )
	{
		if ( ImGui::Begin( "Decrypt File", &AppData.ShowPFI_DecryptFile, ImGuiWindowFlags_AlwaysAutoResize ) )
		{
			if ( BufferLoginPassword.size() != TEXT_BUFFER_CAPACITY )
			{
				//When you clean up sensitive data, you need to reset it to its original size because each time you clean up sensitive data, you will create a new single character buffer that is smaller than the original size and overwrite it.
				//So it needs to be reset to the original capacity size!!!! Otherwise there will be problems entering passwords here.
				BufferLoginPassword.resize( TEXT_BUFFER_CAPACITY, 0x00 );
			}

			ImGui::Text( "System Password:" );
			ImGui::InputText( "##System Password", BufferLoginPassword.data(), BufferLoginPassword.size(), ImGuiInputTextFlags_Password );
			// 选择文件实例
			ImGui::Text( "Select File Instance ID:" );
			ImGui::InputScalar( "##Select File Instance ID", ImGuiDataType_U64, &AppData.ShowPFI_SelectedFileInstanceID );

			const bool correct_password = VerifyPassword( BufferLoginPassword, AppData.UserKey, AppData.UserData );
			VerifyPasswordText( correct_password );

			//if (!AppData.IsEncryptedFileSelected)
			{
				// 选择加密文件
				FileDialogCallback(
					"Select Encrypted File to Decrypt", AppData.IsSourceEncryptedFileSelected, false,
					[]( const std::filesystem::path& in_path, std::filesystem::path& out_path, bool& result ) {
						out_path = in_path;
						result = !out_path.empty();
					},
					std::ref( AppData.SourceEncryptedFilePath ), std::ref( AppData.IsSourceEncryptedFileSelected ) );
			}

			//if (!AppData.IsDecryptedFileSelected)
			{
				// 选择解密文件
				FileDialogCallback(
					"Save Decrypted File", AppData.IsDecryptedFileSelected, true,
					[]( const std::filesystem::path& in_path, std::filesystem::path& out_path, bool& result ) {
						out_path = in_path;
						result = !out_path.empty();
					},
					std::ref( AppData.DecryptedFilePath ), std::ref( AppData.IsDecryptedFileSelected ) );
			}

			static bool Success = false;
			if ( ImGui::Button( "Decrypt" ) )
			{
				if ( !correct_password )
				{
					ImGui::OpenPopup( "Invalid Input Conditions" );
				}
				else if ( AppData.SourceEncryptedFilePath.empty() || AppData.DecryptedFilePath.empty() )
				{
					ImGui::OpenPopup( "Invalid Input Conditions" );
				}
				else
				{
					std::string Password = MakeTrimmedPasswordString( BufferLoginPassword );

					// 查找对应的文件实例
					auto FileInstance = AppData.PersonalFileObject.GetFileInstanceByID( AppData.ShowPFI_SelectedFileInstanceID );

					if ( FileInstance.has_value() )
					{
						Success = AppData.PersonalFileObject.DecryptFile( MakeTokenString( AppData.UserKey.RandomUUID, Password ), FileInstance.value().get(), AppData.SourceEncryptedFilePath, AppData.DecryptedFilePath );

						AppData.SourceEncryptedFilePath.clear();
						AppData.DecryptedFilePath.clear();
						AppData.ShowPFI_DecryptFileResultPopup = true;
					}
					else
					{
						ImGui::OpenPopup( "Invalid File Instance" );
					}

					if ( !Password.empty() )
					{
						memory_set_no_optimize_function<0x00>( Password.data(), Password.size() * sizeof( char ) );
					}
				}

				AppData.IsSourceEncryptedFileSelected = false;
				AppData.IsDecryptedFileSelected = false;
			}

			if ( ImGui::BeginPopupModal( "Invalid Input Conditions", nullptr, ImGuiWindowFlags_AlwaysAutoResize ) )
			{
				ImGui::Text( "Invalid Input Conditions" );
				ImGui::Separator();
				ImGui::Text( "Please ensure the system password is correct and both file paths are selected." );
				if ( ImGui::Button( "Ok" ) )
				{
					ImGui::CloseCurrentPopup();
				}
				ImGui::EndPopup();
			}

			if ( ImGui::BeginPopupModal( "Invalid File Instance", nullptr, ImGuiWindowFlags_AlwaysAutoResize ) )
			{
				ImGui::Text( "Invalid File Instance" );

				if ( ImGui::Button( "Ok" ) )
				{
					ImGui::CloseCurrentPopup();
					AppData.IsSourceEncryptedFileSelected = false;
					AppData.IsDecryptedFileSelected = false;
				}
				ImGui::EndPopup();
			}


			if ( AppData.ShowPFI_DecryptFileResultPopup )
			{
				ImGui::OpenPopup( "Decrypt File Result" );
			}

			if ( ImGui::BeginPopupModal( "Decrypt File Result", &AppData.ShowPFI_DecryptFileResultPopup, ImGuiWindowFlags_AlwaysAutoResize ) )
			{

				ImGui::Text( Success ? "File dencryption successfully." : "File dencryption failed." );

				if ( ImGui::Button( "Ok" ) )
				{
					AppData.ShowPFI_DecryptFileResultPopup = false;
					Success = false;
					ImGui::CloseCurrentPopup();
				}
				ImGui::EndPopup();
				memory_set_no_optimize_function<0x00>( BufferLoginPassword.data(), BufferLoginPassword.size() );

				AppData.IsSourceEncryptedFileSelected = false;
				AppData.IsDecryptedFileSelected = false;
			}
			if ( ImGui::Button( "Close" ) )
			{
				memory_set_no_optimize_function<0x00>( BufferLoginPassword.data(), BufferLoginPassword.size() );
				AppData.ShowPFI_DecryptFile = false;

				AppData.IsSourceEncryptedFileSelected = false;
				AppData.IsDecryptedFileSelected = false;
			}
		}
		ImGui::End();
	}
}

inline void ShowGUI_PFI_EncryptFolder( std::vector<char>& BufferLoginPassword, ApplicationData& AppData )
{
	if ( AppData.ShowPFI_EncryptFolder )
	{
		if ( ImGui::Begin( "Encrypt Folder", &AppData.ShowPFI_EncryptFolder, ImGuiWindowFlags_AlwaysAutoResize ) )
		{
			if ( BufferLoginPassword.size() != TEXT_BUFFER_CAPACITY )
			{
				BufferLoginPassword.resize( TEXT_BUFFER_CAPACITY, 0x00 );
			}

			ImGui::Text( "System Password:" );
			ImGui::InputText( "##Folder Encrypt System Password", BufferLoginPassword.data(), BufferLoginPassword.size(), ImGuiInputTextFlags_Password );
			ImGui::Text( "Select File Instance ID:" );
			ImGui::InputScalar( "##Folder Encrypt File Instance ID", ImGuiDataType_U64, &AppData.ShowPFI_SelectedFileInstanceID );

			const bool correct_password = VerifyPassword( BufferLoginPassword, AppData.UserKey, AppData.UserData );
			VerifyPasswordText( correct_password );

			DirectoryDialogCallback(
				"Select Folder to Encrypt", AppData.IsSourceFolderSelected,
				[]( const std::filesystem::path& in_path, std::filesystem::path& out_path, bool& result ) {
					out_path = in_path;
					result = !out_path.empty();
				},
				std::ref( AppData.SourceFolderPath ), std::ref( AppData.IsSourceFolderSelected ) );

			DirectoryDialogCallback(
				"Select Target Encrypted Folder", AppData.IsTargetEncryptedFolderSelected,
				[]( const std::filesystem::path& in_path, std::filesystem::path& out_path, bool& result ) {
					out_path = in_path;
					result = !out_path.empty();
				},
				std::ref( AppData.TargetEncryptedFolderPath ), std::ref( AppData.IsTargetEncryptedFolderSelected ) );

			if ( ImGui::Button( "Encrypt Folder" ) )
			{
				AppData.ShowPFI_FolderInputErrorMessage = BuildFolderOperationInputError( correct_password, AppData.SourceFolderPath, AppData.TargetEncryptedFolderPath, "source folder" );

				if ( !AppData.ShowPFI_FolderInputErrorMessage.empty() )
				{
					ImGui::OpenPopup( "Invalid Folder Encrypt Conditions" );
				}
				else
				{
					std::string Password = MakeTrimmedPasswordString( BufferLoginPassword );
					QueuePFI_DirectoryOperation( AppData, MakeTokenString( AppData.UserKey.RandomUUID, Password ), AppData.ShowPFI_SelectedFileInstanceID, AppData.SourceFolderPath, AppData.TargetEncryptedFolderPath, true );

					memory_set_no_optimize_function<0x00>( BufferLoginPassword.data(), BufferLoginPassword.size() );
					if ( !Password.empty() )
					{
						memory_set_no_optimize_function<0x00>( Password.data(), Password.size() * sizeof( char ) );
					}
					AppData.SourceFolderPath.clear();
					AppData.TargetEncryptedFolderPath.clear();
					AppData.IsSourceFolderSelected = false;
					AppData.IsTargetEncryptedFolderSelected = false;
				}
			}

			ShowPFI_FolderInputErrorPopup( "Invalid Folder Encrypt Conditions", AppData.ShowPFI_FolderInputErrorMessage );

			if ( ImGui::Button( "Close" ) )
			{
				memory_set_no_optimize_function<0x00>( BufferLoginPassword.data(), BufferLoginPassword.size() );
				AppData.ShowPFI_EncryptFolder = false;
				AppData.SourceFolderPath.clear();
				AppData.TargetEncryptedFolderPath.clear();
				AppData.IsSourceFolderSelected = false;
				AppData.IsTargetEncryptedFolderSelected = false;
				AppData.ShowPFI_FolderInputErrorMessage.clear();
			}
		}
		ImGui::End();
	}

	ShowPFI_DirectoryOperationResultPopup( "Encrypt Folder Result", AppData.ShowPFI_EncryptFolderResultPopup, AppData.LastFileDirectoryOperationResult );
}

inline void ShowGUI_PFI_DecryptFolder( std::vector<char>& BufferLoginPassword, ApplicationData& AppData )
{
	if ( AppData.ShowPFI_DecryptFolder )
	{
		if ( ImGui::Begin( "Decrypt Folder", &AppData.ShowPFI_DecryptFolder, ImGuiWindowFlags_AlwaysAutoResize ) )
		{
			if ( BufferLoginPassword.size() != TEXT_BUFFER_CAPACITY )
			{
				BufferLoginPassword.resize( TEXT_BUFFER_CAPACITY, 0x00 );
			}

			ImGui::Text( "System Password:" );
			ImGui::InputText( "##Folder Decrypt System Password", BufferLoginPassword.data(), BufferLoginPassword.size(), ImGuiInputTextFlags_Password );
			ImGui::Text( "Select File Instance ID:" );
			ImGui::InputScalar( "##Folder Decrypt File Instance ID", ImGuiDataType_U64, &AppData.ShowPFI_SelectedFileInstanceID );

			const bool correct_password = VerifyPassword( BufferLoginPassword, AppData.UserKey, AppData.UserData );
			VerifyPasswordText( correct_password );

			DirectoryDialogCallback(
				"Select Encrypted Folder to Decrypt", AppData.IsSourceEncryptedFolderSelected,
				[]( const std::filesystem::path& in_path, std::filesystem::path& out_path, bool& result ) {
					out_path = in_path;
					result = !out_path.empty();
				},
				std::ref( AppData.SourceEncryptedFolderPath ), std::ref( AppData.IsSourceEncryptedFolderSelected ) );

			DirectoryDialogCallback(
				"Select Target Decrypted Folder", AppData.IsDecryptedFolderSelected,
				[]( const std::filesystem::path& in_path, std::filesystem::path& out_path, bool& result ) {
					out_path = in_path;
					result = !out_path.empty();
				},
				std::ref( AppData.DecryptedFolderPath ), std::ref( AppData.IsDecryptedFolderSelected ) );

			if ( ImGui::Button( "Decrypt Folder" ) )
			{
				AppData.ShowPFI_FolderInputErrorMessage = BuildFolderOperationInputError( correct_password, AppData.SourceEncryptedFolderPath, AppData.DecryptedFolderPath, "source encrypted folder" );

				if ( !AppData.ShowPFI_FolderInputErrorMessage.empty() )
				{
					ImGui::OpenPopup( "Invalid Folder Decrypt Conditions" );
				}
				else
				{
					std::string Password = MakeTrimmedPasswordString( BufferLoginPassword );
					QueuePFI_DirectoryOperation( AppData, MakeTokenString( AppData.UserKey.RandomUUID, Password ), AppData.ShowPFI_SelectedFileInstanceID, AppData.SourceEncryptedFolderPath, AppData.DecryptedFolderPath, false );

					memory_set_no_optimize_function<0x00>( BufferLoginPassword.data(), BufferLoginPassword.size() );
					if ( !Password.empty() )
					{
						memory_set_no_optimize_function<0x00>( Password.data(), Password.size() * sizeof( char ) );
					}
					AppData.SourceEncryptedFolderPath.clear();
					AppData.DecryptedFolderPath.clear();
					AppData.IsSourceEncryptedFolderSelected = false;
					AppData.IsDecryptedFolderSelected = false;
				}
			}

			ShowPFI_FolderInputErrorPopup( "Invalid Folder Decrypt Conditions", AppData.ShowPFI_FolderInputErrorMessage );

			if ( ImGui::Button( "Close" ) )
			{
				memory_set_no_optimize_function<0x00>( BufferLoginPassword.data(), BufferLoginPassword.size() );
				AppData.ShowPFI_DecryptFolder = false;
				AppData.SourceEncryptedFolderPath.clear();
				AppData.DecryptedFolderPath.clear();
				AppData.IsSourceEncryptedFolderSelected = false;
				AppData.IsDecryptedFolderSelected = false;
				AppData.ShowPFI_FolderInputErrorMessage.clear();
			}
		}
		ImGui::End();
	}

	ShowPFI_DirectoryOperationResultPopup( "Decrypt Folder Result", AppData.ShowPFI_DecryptFolderResultPopup, AppData.LastFileDirectoryOperationResult );
}

// 显示 PersonalFileInfo 的 GUI
inline void ShowGUI_PersonalFileInfo( [[maybe_unused]] std::vector<char>& BufferLoginPassword, ApplicationData& AppData )
{
	ImGui::Begin( "Personal File Info" );

	if ( ImGui::Button( "Create File Instance" ) )
	{
		AppData.ShowPFI_CreateFileInstance = true;	//! AppData.ShowPFI_CreateFileInstance;
		ImGui::SetWindowFocus( "Create File Instance" );
	}

	if ( ImGui::Button( "List All File Instances" ) )
	{
		AppData.ShowPFI_ListAllFileInstance = true;	 //! AppData.ShowPFI_ListAllFileInstance;
		ImGui::SetWindowFocus( "List All File Instances" );
	}

	if ( ImGui::Button( "Delete File Instance By ID" ) )
	{
		AppData.ShowPFI_DeleteFileInstanceByID = true;	//! AppData.ShowPFI_DeleteFileInstanceByID;
		ImGui::SetWindowFocus( "Delete File Instance" );
	}

	if ( ImGui::Button( "Encrypt File" ) )
	{
		AppData.ShowPFI_EncryptFile = true;	 //! AppData.ShowPFI_EncryptFile;
		ImGui::SetWindowFocus( "Encrypt File" );
	}

	if ( ImGui::Button( "Decrypt File" ) )
	{
		AppData.ShowPFI_DecryptFile = true;	 //! AppData.ShowPFI_DecryptFile;
		ImGui::SetWindowFocus( "Decrypt File" );
	}

	if ( ImGui::Button( "Encrypt Folder" ) )
	{
		AppData.ShowPFI_EncryptFolder = true;
		ImGui::SetWindowFocus( "Encrypt Folder" );
	}

	if ( ImGui::Button( "Decrypt Folder" ) )
	{
		AppData.ShowPFI_DecryptFolder = true;
		ImGui::SetWindowFocus( "Decrypt Folder" );
	}

	if ( ImGui::Button( "Delete All File Instances" ) )
	{
		AppData.ShowPFI_ConfirmDeleteAllFileInstancesPopup = true;
	}

	if ( ImGui::Button( "Close All" ) )
	{
		// AppData.ShowGUI_PersonalPasswordInfo = true;
		// AppData.ShowGUI_PersonalFileInfo = false;

		AppData.ShowPFI_ListAllFileInstance = false;
		AppData.ShowPFI_CreateFileInstance = false;
		AppData.ShowPFI_DeleteFileInstanceByID = false;
		AppData.ShowPFI_EncryptFile = false;
		AppData.ShowPFI_DecryptFile = false;
		AppData.ShowPFI_EncryptFolder = false;
		AppData.ShowPFI_DecryptFolder = false;
		AppData.ShowPFI_EncryptFolderResultPopup = false;
		AppData.ShowPFI_DecryptFolderResultPopup = false;
		AppData.ShowPFI_ConfirmDeleteAllFileInstancesPopup = false;
		AppData.SourceFolderPath.clear();
		AppData.TargetEncryptedFolderPath.clear();
		AppData.SourceEncryptedFolderPath.clear();
		AppData.DecryptedFolderPath.clear();
		AppData.IsSourceFolderSelected = false;
		AppData.IsTargetEncryptedFolderSelected = false;
		AppData.IsSourceEncryptedFolderSelected = false;
		AppData.IsDecryptedFolderSelected = false;
		AppData.ShowPFI_FolderInputErrorMessage.clear();
	}

	ImGui::End();
}
