# PasswordManagerGUI

[English](#english-version) | [中文说明](#中文说明)

---

## English Version

### Introduction
**PasswordManagerGUI** is a utility GUI program built on the my **TDOM-EncryptOrDecryptFile-Reborn** codebase, designed to protect and manage passwords and file data locally. 
This C++ application uses the **IMGUI** library to provide a modern, lightweight graphical interface. 
Additionally, it employs the **nlohmann/json** library for handling text-based data storage, serialization, and deserialization.  
Please note that this project is still under active development.

### Features
- **Local Login/Logout Management**: Securely manages user sessions without external dependencies.
- **Secure Data Storage**: Protects password texts and file data through robust encryption.
- **Efficient Encryption/Decryption**: Leverages the TDOM-EncryptOrDecryptFile-Reborn codebase for effective cryptographic operations.
- **User-Friendly GUI**: Built with IMGUI for an intuitive and responsive interface.
- **Text Data Handling**: Uses nlohmann/json to manage serialization and deserialization of information stored in text format.
- **Offline Operation**: Designed for local, offline use ensuring maximum security.

### Requirements
- **C++20 or higher**: This project requires a compiler supporting the C++20 standard or above.
- **IMGUI** library for GUI rendering.
- **nlohmann/json** library for text data storage and JSON serialization/deserialization.
- **TDOM-EncryptOrDecryptFile-Reborn** utility codebase (must be integrated within your project).

### Status
This project is currently under active development. Detailed instructions on usage and compilation will be provided in future updates.

---

## 中文说明

### 简介
**PasswordManagerGUI** 是一个基于 我的 **TDOM-EncryptOrDecryptFile-Reborn** 工具库的实用图形界面程序，旨在本地保护和管理密码及文件数据。
该 C++ 应用程序采用 **IMGUI** 库构建，提供现代化、轻量级的图形用户界面。
同时，项目还引入了 **nlohmann/json** 库，用于处理文本存储信息，并负责数据的序列化与反序列化。  
请注意，此项目目前仍在积极开发中。

### 功能特性
- **本地登录/注销管理**：无需外部依赖，安全管理用户会话。
- **安全数据存储**：通过强加密机制保护密码文本和文件数据。
- **高效加解密**：利用 TDOM-EncryptOrDecryptFile-Reborn 工具库实现高效加密与解密操作。
- **友好的图形界面**：基于 IMGUI 构建，界面直观、响应迅速。
- **文本数据处理**：使用 nlohmann/json 库实现信息的序列化与反序列化，便于以文本形式存储数据。
- **离线操作**：专为本地离线使用设计，确保最大程度的安全性。

### 环境需求
- **C++20 或更高版本**：本项目需要支持 C++20 标准或更高版本的编译器。
- 用于图形界面渲染的 **IMGUI** 库。
- 用于文本数据存储及 JSON 序列化/反序列化的 **nlohmann/json** 库。
- **TDOM-EncryptOrDecryptFile-Reborn** 工具库（需集成于项目中）。

### 状态说明
本项目目前正处于开发阶段，详细的使用说明和编译指南将在后续更新中提供。
