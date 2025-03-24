#pragma once

#include "nlohmann/json.hpp"

//Twilight-Dream's Cryptography Library Base Support

/* Priority Level 1 */
#include "Support+Library/Support-Library.hpp"

#include "raii_tool.hpp"
#include "logger.hpp"

// System User data structure
struct PasswordManagerUserData
{
	//系统用户名，生成全局唯一身份标识的材料之一。
	//System username, one of the materials used to generate a globally unique identifiers.
	std::string UserName;

	// 经过散列加盐和 Base64 编码的系统密码
	// Hash-salted and Base64-encoded system passwords
	std::string HashedPassword;

	std::string PersonalPasswordInfoFileName = "";
	std::string PersonalInfoFileName = "";

	bool IsFirstLogin = true;
};

// System User key structure
struct PasswordManagerUserKey
{
	//全局唯一身份标识，是用户个人密码管理器的主密钥数据的生成材料。
	//A globally unique identifier that is the material from which the master key data for the user's personal password manager is generated.
	std::string RandomUUID;
	
	//关于系统用户名的盐值，生成全局唯一身份标识的材料之一。生成一次之后不会更改。
	//Salt value about the system username, one of the materials for generating a globally unique identifier.
	//It will not be changed after it is generated once.
	std::string RandomSalt;
	
	//关于系统密码的盐值，验证密码时会使用。生成一次之后不会更改。
	//Salt value about the system password, which will be used when verifying the password.
	//It will not be changed after it is generated once.
	std::string RandomPasswordSalt;

	//注册时间戳，生成全局唯一身份标识的材料之一。
	//Registration timestamp, one of the materials for generating globally unique identifiers.
	uint64_t RegistrationTime = 0;
};

const std::vector<std::string> CryptoCipherAlgorithmNames{"AES", "RC6", "SM4", "Twofish", "Serpent"};

class PersonalPasswordInfo
{
private:
	struct PersonalPasswordInstance
	{
		//表示这是第几个 PersonalPasswordInstance
		std::uint64_t ID = 0;
		std::string Description = "";
		std::string EncryptedPassword = "";
		std::string DecryptedPassword = "";
		std::vector<std::string> EncryptionAlgorithmNames{};
		std::vector<std::string> DecryptionAlgorithmNames{};
		std::uint64_t HashMapID = 0; //For access HashMap_EncryptedSymmetricKey and HashMap_DecryptedSymmetricKey_Hashed

		PersonalPasswordInstance() = default;

		PersonalPasswordInstance(const PersonalPasswordInstance& Other)
			:
			ID(Other.ID), Description(Other.Description),
			EncryptedPassword(Other.EncryptedPassword), DecryptedPassword(Other.DecryptedPassword),
			EncryptionAlgorithmNames(Other.EncryptionAlgorithmNames), DecryptionAlgorithmNames(Other.DecryptionAlgorithmNames),
			HashMapID(Other.HashMapID)
		{

		}

		~PersonalPasswordInstance() = default;
	};
	std::vector<PersonalPasswordInstance> Instances;

	void RecomputeEncryptedPassword(const std::string& NewInstancePassword, const std::string& Token, PersonalPasswordInstance& Instance);
	void RecomputeDecryptedPassword(const std::string& Token, PersonalPasswordInstance& Instance);

public:

	PersonalPasswordInfo() = default;

	explicit PersonalPasswordInfo(const PersonalPasswordInfo& Other)
		:
		Instances(Other.Instances),
		HashMap_EncryptedSymmetricKey(Other.HashMap_EncryptedSymmetricKey),
		HashMap_DecryptedSymmetricKey_Hashed(Other.HashMap_DecryptedSymmetricKey_Hashed)
	{

	}

	~PersonalPasswordInfo() = default;

	std::unordered_map<std::uint64_t, std::vector<std::uint8_t>> HashMap_EncryptedSymmetricKey; // {HashMapID, EncryptedSymmetricKey}
	std::unordered_map<std::uint64_t, std::string> HashMap_DecryptedSymmetricKey_Hashed; // {HashMapID, DecryptedSymmetricKey_Hashed}

	void Serialization(const std::filesystem::path& FilePath);
	void Deserialization(const std::filesystem::path& FilePath);

	// 新建个人密码信息的实例并且加密
	PersonalPasswordInstance CreatePasswordInstance
	(
		const std::string& Token,
		const std::string& ShowPPI_Description,
		const std::string& Password,
		const std::vector<std::string>& EncryptionAlgorithms,
		const std::vector<std::string>& DecryptionAlgorithms
	);

	// 追加个人密码信息的实例
	void AppendPasswordInstance(const PersonalPasswordInfo::PersonalPasswordInstance& instance);

	// 更改个人密码信息的实例
	bool ChangePasswordInstance
	(
		std::uint64_t ID,
		const std::string& NewDescription,
		const std::string& NewPassword,
		const std::vector<std::string>& NewEncryptionAlgorithms,
		const std::vector<std::string>& NewDecryptionAlgorithms,
		const std::string& Token,
		bool ChangeEncryptedPassword
	);

	std::vector<PersonalPasswordInstance>& GetPassswordInstances();

	// 列出个人密码信息的实例并且解密
	void ListAllPasswordInstance
	(
		const std::string& Token
	);

	// 删除个人密码信息的实例，根据ID
	bool RemovePasswordInstance(std::uint64_t id);

	void RemoveAllPasswordInstance();

	// 根据ID查找个人密码信息的实例并且解密
	std::optional<PersonalPasswordInstance> FindPasswordInstanceByID(const std::string& Token, std::uint64_t ID);

	// 根据ID查找个人密码信息的实例的描述
	std::string FindPasswordInstanceDescriptionByID(std::uint64_t ID);

	// 根据Description查找个人密码信息的实例并且解密
	std::optional<PersonalPasswordInstance> FindPasswordInstanceByDescription(const std::string& Token, const std::string& Description);

	void ChangeInstanceMasterKeyWithSystemPassword
	(
		const std::filesystem::path& FilePath,
		const std::string& Token,
		const std::string& NewToken
	);

	/**
	* 加密指定的文件并将加密后的内容保存到目标路径。
	*
	* @param Token 用于生成主密钥的令牌字符串。
	* @param Instance 要使用的密码实例。
	* @param SourceFilePath 要加密的源文件路径。
	* @param EncryptedFilePath 加密后文件的保存路径。
	* @return 如果加密成功则返回 true，否则返回 false。
	*/
	bool EncryptFile(const std::string& Token, PersonalPasswordInstance& Instance, const std::filesystem::path& SourceFilePath, const std::filesystem::path& EncryptedFilePath);

	/**
	 * 解密指定的加密文件并将解密后的内容保存到目标路径。
	 *
	 * @param Token 用于生成主密钥的令牌字符串。
	 * @param Instance 要使用的密码实例。
	 * @param EncryptedFilePath 要解密的源加密文件路径。
	 * @param DecryptedFilePath 解密后文件的保存路径。
	 * @return 如果解密成功则返回 true，否则返回 false。
	 */
	bool DecryptFile(const std::string& Token, PersonalPasswordInstance& Instance, const std::filesystem::path& EncryptedFilePath, const std::filesystem::path& DecryptedFilePath);
};

// PersonalFileInfo 类用于管理文件实例
class PersonalFileInfo
{
private:
	// PersonalFileInstance 结构体定义
	struct PersonalFileInstance
	{
		std::uint64_t ID = 0;
		std::vector<std::string> EncryptionAlgorithmNames;
		std::vector<std::string> DecryptionAlgorithmNames;

		PersonalFileInstance() = default;

		PersonalFileInstance(const PersonalFileInstance& Other)
			: ID(Other.ID),
			EncryptionAlgorithmNames(Other.EncryptionAlgorithmNames),
			DecryptionAlgorithmNames(Other.DecryptionAlgorithmNames)
		{
		}

		~PersonalFileInstance() = default;
	};

	std::vector<PersonalFileInstance> Instances;

	// 序列化和反序列化辅助函数
	void SerializeInstances(nlohmann::json& jsonData) const;
	void DeserializeInstances(const nlohmann::json& jsonData);

public:
	PersonalFileInfo() = default;

	explicit PersonalFileInfo(const PersonalFileInfo& Other)
		: Instances(Other.Instances)
	{
	}

	~PersonalFileInfo() = default;

	// 序列化和反序列化函数
	void Serialization(const std::filesystem::path& FilePath);
	void Deserialization(const std::filesystem::path& FilePath);

	// 创建新的文件实例
	PersonalFileInstance CreateFileInstance(
		const std::string& Token,
		const std::vector<std::string>& EncryptionAlgorithms,
		const std::vector<std::string>& DecryptionAlgorithms
	);

	// 追加文件实例
	void AppendFileInstance(const PersonalFileInstance& instance);

	// 删除文件实例
	bool RemoveFileInstance(std::uint64_t ID);

	// 删除所有文件实例
	void RemoveAllFileInstances();

	// 通过ID获取文件实例
	PersonalFileInstance& GetFileInstanceByID(uint64_t ID);

	// 加密文件
	bool EncryptFile(const std::string& Token, const PersonalFileInstance& Instance, const std::filesystem::path& SourceFilePath, const std::filesystem::path& EncryptedFilePath);

	// 解密文件
	bool DecryptFile(const std::string& Token, const PersonalFileInstance& Instance, const std::filesystem::path& EncryptedFilePath, const std::filesystem::path& DecryptedFilePath);
};

// Function to generate a unique user ID
extern inline void GenerateUUID(std::vector<char> UserName, const std::string& RandomSalt, uint64_t& RegistrationTime, std::string& UUID);

// Function to generate a random salt
extern inline void GenerateRandomSalt(std::string& RandomSalt);

// Function to SHA1 hash reduction on the data array
extern std::vector<unsigned char> HashUUID(const std::vector<unsigned char>& data, size_t size_limit);

// Function to Unique user ID hash to Unique file name
extern inline std::string GenerateStringFileUUIDFromStringUUID(const std::string& UUID);

// Function to generate a random key (256 bit)
extern inline std::vector<uint8_t> GenerateRandomKey();

// Function to regenerate a mater key and password instance key
extern inline void RegenerateMasterKey(const std::filesystem::path& FilePath, PersonalPasswordInfo& PersonalPasswordInfo, const std::string& Token);

// Function to save user data to a JSON file
extern inline void SavePasswordManagerUser(const std::pair<PasswordManagerUserKey, PasswordManagerUserData>& NewUserData);

extern inline bool LoadPasswordManagerUUID(PasswordManagerUserKey& CurrentUserKey);

// Function to load user data from a JSON file by UserKey UUID
extern inline void LoadPasswordManagerUser(const PasswordManagerUserKey& CurrentUserKey, PasswordManagerUserData& EmptyUserData);

extern inline std::string PasswordAndHash(const std::vector<char>& Password, std::string RandomSalt);
extern inline std::string PasswordAndHash(const std::string& Password, std::string RandomSalt);

// Function to verify UUID
extern inline bool VerifyUUID(const std::vector<char>& Username, const std::string& RandomSalt, uint64_t& RegistrationTime, const PasswordManagerUserKey& CurrentUserKey);

// Function to verify the password
extern inline bool VerifyPassword(const std::vector<char>& Password, const PasswordManagerUserKey& CurrentUserKey, const PasswordManagerUserData& CurrentUserData);

//UUID string Concatenation Login/Registration Password string = Token String
extern inline std::string MakeTokenString(const std::string& UUID, const std::vector<char>& BufferLoginPassword);
extern inline std::string MakeTokenString(const std::string& UUID, const std::string& BufferLoginPassword);

extern inline std::vector<std::uint8_t> GenerateMasterBytesKeyFromToken(const std::string& Token);

extern inline void MakePersonalPasswordDataFile(const std::string& UniqueFileName, const std::string& Token);

extern void FirstLoginLogic(const std::vector<char>& BufferLoginPassword, const PasswordManagerUserKey& CurrentUserKey, PasswordManagerUserData& CurrentUserData);