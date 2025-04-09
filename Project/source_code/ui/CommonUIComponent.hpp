#pragma once

#include "../core/application_data.hpp"

inline void Show_ProgressBar(ApplicationData &AppData)
{
	if (AppData.TaskInProgress)
	{
		AppData.progress_life_time = 1.0f;
	}
	else
	{
		AppData.progress_life_time -= 0.02f;
		AppData.progress        = 1.0f;
		AppData.progress_target = 1.0f;
	}
	if (AppData.progress_life_time < 0.1f)
	{
		return;
	}

	const float distance     = AppData.progress_target - AppData.progress;
	const float min_speed    = 0.0f;
	const float max_speed    = 0.05f;
	const float speed_factor = std::clamp(0.05f * distance * distance, min_speed, max_speed);
	AppData.progress += speed_factor;
	AppData.progress = std::clamp(AppData.progress, 0.0f, 1.0f);
	ImGui::Begin("Progress", nullptr, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoDocking | ImGuiWindowFlags_NoCollapse);
	ImGui::ProgressBar(AppData.progress, ImVec2(120.0f, 18.0f));
	ImGui::Text("Task in progress...");
	ImGui::End();
}

inline void SetProgressTarget(ApplicationData &AppData, float progress, float target)
{

	AppData.progress        = std::clamp(progress, 0.0f, 1.0f);
	AppData.progress_target = std::clamp(target, 0.0f, 1.0f);
}

inline void VerifyPasswordText(bool condition)
{
	if (condition)
	{
		ImGui::TextColored(ImVec4(0.2f, 0.7f, 0.1f, 1.0f), "System password is correct.");
	}
	else
	{
		ImGui::TextColored(ImVec4(0.9f, 0.1f, 0.0f, 1.0f), "Incorrect system password.");
	}
}

inline bool ShowEncryptionAlgorithmGroup(ApplicationData &AppData)
{
	bool atLeastOneSelected = false;

	if (ImGui::GetContentRegionAvail().x >= 700)
	{
		ImGui::SameLine();
		ImGui::Dummy(ImVec2(2.f, 0.f));
		ImGui::SameLine();
	}
	else
	{
		ImGui::Dummy(ImVec2(0.f, 4.f));
		ImGui::Separator();
	}
	ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(0.f, 6.f));
	ImGui::BeginGroup();
	{

		ImGui::Text("Encryption Algorithm:");
		ImGui::Dummy(ImVec2(4.f, 0.0f));
		ImGui::SameLine();
		ImGui::BeginGroup();
		{
			ImGui::Dummy(ImVec2(0.0f, 2.0f));
			ImGui::Checkbox("Need AES", &AppData.ShowPPI_NeedAES);
			ImGui::Checkbox("Need RC6", &AppData.ShowPPI_NeedRC6);
			ImGui::Checkbox("Need SM4", &AppData.ShowPPI_NeedSM4);
			ImGui::Checkbox("Need Twofish", &AppData.ShowPPI_NeedTwofish);
			ImGui::Checkbox("Need Serpent", &AppData.ShowPPI_NeedSerpent);
		}
		ImGui::EndGroup();

		atLeastOneSelected = AppData.ShowPPI_NeedAES || AppData.ShowPPI_NeedRC6 || AppData.ShowPPI_NeedSM4 || AppData.ShowPPI_NeedTwofish || AppData.ShowPPI_NeedSerpent;

		if (!atLeastOneSelected)
		{
			ImGui::Dummy(ImVec2(0.0f, 3.0f));
			ImGui::TextColored(ImVec4(0.9f, 0.1f, 0.0f, 1.f), "At least one algorithm must be selected");
		}
	}
	ImGui::EndGroup();
	ImGui::PopStyleVar();

	return atLeastOneSelected;
}

template <typename Callback_t, typename... Args>
    requires std::invocable<Callback_t, std::filesystem::path, Args...>
auto FileDialogCallback(const char *dialog_title, bool disable, bool confirm_overwrite, Callback_t &&callback, Args &&...args) -> std::conditional_t<
    std::is_void_v<std::invoke_result_t<Callback_t, std::filesystem::path, Args &&...>>,
    void,
    std::optional<std::invoke_result_t<Callback_t, std::filesystem::path, Args &&...>>>
{
	using CallBackReturnType = std::invoke_result_t<Callback_t, std::filesystem::path, Args &&...>;
	ImGui::BeginDisabled(disable);
	if (ImGui::Button(dialog_title))
	{
		IGFD::FileDialogConfig FDConfig{};
		FDConfig.path  = ".";
		FDConfig.flags = ImGuiFileDialogFlags_Modal;
		if (confirm_overwrite)
			FDConfig.flags |= ImGuiFileDialogFlags_ConfirmOverwrite;
		ImGuiFileDialog::Instance()->OpenDialog(
		    dialog_title, //"ChooseFileDialogKey",
		    dialog_title,
		    ".*", // 文件后缀名过滤器  (".*") (nullptr)
		    FDConfig);
	}
	ImGui::EndDisabled();

	if (ImGuiFileDialog::Instance()->Display(
	        dialog_title, //"ChooseFileDialogKey",
	        ImGuiWindowFlags_NoCollapse,
	        ImVec2(800, 600),
	        ImVec2(1200, 800)))
	{
		if (ImGuiFileDialog::Instance()->IsOk())
		{
			auto SelectedPath = ImGuiFileDialog::Instance()->GetFilePathName();
			ImGuiFileDialog::Instance()->Close();

			if constexpr (std::is_void_v<CallBackReturnType>)
			{
				std::forward<Callback_t>(callback)(SelectedPath, std::forward<Args>(args)...);
				return;
			}
			else
			{
				return std::forward<Callback_t>(callback)(SelectedPath, std::forward<Args>(args)...);
			}
		}
		ImGuiFileDialog::Instance()->Close();
	}
	if constexpr (!std::is_void_v<CallBackReturnType>)
		return std::nullopt;
}
