#include "application_functional.hpp"

//Twilight-Dream's Cryptography Library

/* Priority Level 2 */
#include "UtilTools/UtilTools.hpp"
#include "CommonToolkit/CommonToolkit.hpp"
#include "CommonToolkit/BytesExchangeInteger.hpp"

/* Priority Level 3 */
//#include "ThreadingToolkit/Pool/Version1/ThreadPool.hpp"
//#include "ThreadingToolkit/Pool/Version2/ThreadPool.hpp"
//#include "ThreadingToolkit/Pool/Version3/ThreadPool.hpp"
//#include "ThreadingToolkit/Time/TimedThreadExecutor.hpp"
//#include "ThreadingToolkit/Wrapper/AsyncTaskWrapper.hpp"

/* Priority Level 4 */
#include "CommonSecurity/CommonSecurity.hpp"
#include "CommonSecurity/SecureRandomUtilLibrary.hpp"

/* Priority Level 5 */
#include "CommonSecurity/BlockDataCryption.hpp"
#include "CommonSecurity/BlockCiphers/AlgorithmCorrectedBlockTEA.hpp"
#include "CommonSecurity/BlockCiphers/AlgorithmAES.hpp"
#include "CommonSecurity/BlockCiphers/AlgorithmTripleDES.hpp"
#include "CommonSecurity/BlockCiphers/AlgorithmRC6.hpp"
#include "CommonSecurity/BlockCiphers/AlgorithmChinaShangYongMiMa4.hpp"
#include "CommonSecurity/BlockCiphers/AlgorithmTwofish.hpp"
#include "CommonSecurity/BlockCiphers/AlgorithmThreefish.hpp"
#include "CommonSecurity/BlockCiphers/AlgorithmSerpent.hpp"
#include "CommonSecurity/StreamDataCryption.hpp"

/* Priority Level 6 */
#include "CommonSecurity/SecureHashProvider/Hasher.hpp"
#include "CommonSecurity/KeyDerivationFunction/AlgorithmHMAC.hpp"
#include "CommonSecurity/KeyDerivationFunction/AlgorithmArgon2.hpp"
#include "CommonSecurity/KeyDerivationFunction/AlgorithmScrypt.hpp"
#include "CommonSecurity/DeterministicRandomBitGenerator/BasedAlgorithmHMAC.hpp"

/* Priority Level 7  */
#include "CustomSecurity/ByteSubstitutionBoxToolkit.hpp"
#include "CustomSecurity/DataObfuscator.hpp"

/* Priority Level 8 */
#include "CommonSecurity/DataHashingWrapper.hpp"
#include "CommonSecurity/AEAD_Cascaded.hpp"
//#include "CommonSecurity/Shamir's-SecretSharing.hpp"



/***** Implementation of Application Core Internal Functions *****/

inline void GenerateUUID(std::vector<char> UserName, const std::string& RandomSalt, uint64_t& RegistrationTime, std::string& UUID)
{
	std::string Name = std::string(UserName.begin(), UserName.end());

	auto new_end = std::find_if
	(
		Name.rbegin(), Name.rend(), 
		[](char character)
		{
			return character != '\x00';
		}
	);

	Name.erase(new_end.base(), Name.end());

	// Get the current timestamp
	auto Timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
	RegistrationTime = Timestamp;

	CommonSecurity::DataHashingWrapper::HashersAssistantParameters HAP_ObjectArgument {};
	HAP_ObjectArgument.hash_mode = CommonSecurity::SHA::Hasher::WORKER_MODE::CHINA_SHANG_YONG_MI_MA3;
	HAP_ObjectArgument.generate_hash_bit_size = 512;
	HAP_ObjectArgument.whether_use_hash_extension_bit_mode = false;
	HAP_ObjectArgument.inputDataString = "";
	HAP_ObjectArgument.outputHashedHexadecimalString = "";

	std::string HMAC_String = CommonSecurity::DataHashingWrapper::HMAC_FunctionObject(HAP_ObjectArgument, Name, 512 / 8, RandomSalt + std::to_string(RegistrationTime));

	for(int count = 0; count < 7; count++)
	{
		HMAC_String.append(CommonSecurity::DataHashingWrapper::HMAC_FunctionObject(HAP_ObjectArgument, HMAC_String, 512 / 8, RandomSalt + std::to_string(RegistrationTime)));
	}

	auto HMAC_BytesData = UtilTools::DataFormating::ASCII_Hexadecimal::hexadecimalString2ByteArray(HMAC_String);

	UUID = UtilTools::DataFormating::Base64Coder::Author1::encode(HMAC_BytesData);
}

inline void GenerateRandomSalt(std::string& RandomSalt)
{
	// Get the current timestamp
	auto Timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();

	std::mt19937_64 PRNG_ByRandomSeed(static_cast<long long>(std::random_device{}()) + Timestamp);
	CommonSecurity::RND::UniformIntegerDistribution<std::uint64_t> PRG(std::numeric_limits<std::uint64_t>::min(), std::numeric_limits<std::uint64_t>::max());
	
	RandomSalt.resize(64, 0x00);
	size_t ByteCounter = 0;
	while(ByteCounter < 64)
	{
		std::uint64_t RandomNumber = PRG(PRNG_ByRandomSeed);
		::memcpy(&RandomSalt[ByteCounter], &RandomNumber, sizeof(std::uint64_t));

		ByteCounter += sizeof(std::uint64_t);
	}

	UtilTools::DataFormating::Base64Coder::Author2::Base64 Coder;
	RandomSalt = Coder.base64_encode(RandomSalt, false);
}

inline std::vector<uint8_t> GenerateRandomKey()
{
	using CommonSecurity::DRBG::HMAC::WorkerBasedHAMC;

	CommonSecurity::DataHashingWrapper::HashersAssistantParameters HAP_ObjectArgument {};
	HAP_ObjectArgument.hash_mode = CommonSecurity::SHA::Hasher::WORKER_MODE::SHA3_512;
	HAP_ObjectArgument.generate_hash_bit_size = 512;
	HAP_ObjectArgument.whether_use_hash_extension_bit_mode = false;
	HAP_ObjectArgument.inputDataString = "";
	HAP_ObjectArgument.outputHashedHexadecimalString = "";

	WorkerBasedHAMC RandomKeyGenerator(HAP_ObjectArgument);

	std::vector<uint8_t> RandomKeyData(256 / 8, 0x00);

	RandomKeyGenerator.instantiate_state();

	RandomKeyGenerator.generate_bytes(RandomKeyData);

	return RandomKeyData;
}

inline void RegenerateMasterKey(PersonalPasswordInfo& PersonalPasswordInfo, const std::string& Token)
{
	std::vector<uint8_t> MasterKey = GenerateMasterBytesKeyFromToken(Token);

	using namespace CommonSecurity::SHA;
	CommonSecurity::DataHashingWrapper::HashersAssistantParameters HAP_ObjectArgument {};
	HAP_ObjectArgument.hash_mode = CommonSecurity::SHA::Hasher::WORKER_MODE::SHA2_512;
	HAP_ObjectArgument.generate_hash_bit_size = 512;
	HAP_ObjectArgument.whether_use_hash_extension_bit_mode = false;

	CommonSecurity::ChinaShangYongMiMa4::DataWorker256 SM4_128_256;
	std::vector<uint8_t> EncryptedInstanceKey(256 / 8, 0x00);

	std::vector<uint8_t> InstanceKey;
	for(size_t HashMapID = 0; HashMapID < 16; ++HashMapID)
	{
		InstanceKey = GenerateRandomKey();

		HAP_ObjectArgument.inputDataString = UtilTools::DataFormating::ASCII_Hexadecimal::byteArray2HexadecimalString(InstanceKey);
		CommonSecurity::DataHashingWrapper::HashersAssistant::SELECT_HASH_FUNCTION(HAP_ObjectArgument);

		//SM4 With Block Cipher Counter Mode
		SM4_128_256.CTR_StreamModeBasedEncryptFunction(InstanceKey, MasterKey, EncryptedInstanceKey);

		//Build HashMap Content
		PersonalPasswordInfo.HashMap_EncryptedSymmetricKey.try_emplace(HashMapID, EncryptedInstanceKey);
		PersonalPasswordInfo.HashMap_DecryptedSymmetricKey_Hashed.try_emplace(HashMapID, HAP_ObjectArgument.outputHashedHexadecimalString);

		// Securely wipe the sensitive keys by setting them to all zeroes.
		memory_set_no_optimize_function<0x00>(InstanceKey.data(), InstanceKey.size() * sizeof(uint8_t));
	}
	// Securely wipe the sensitive keys by setting them to all zeroes.
	memory_set_no_optimize_function<0x00>(MasterKey.data(), MasterKey.size() * sizeof(uint8_t));
	memory_set_no_optimize_function<0x00>(EncryptedInstanceKey.data(), EncryptedInstanceKey.size() * sizeof(uint8_t));
}

// SHA-1 Main processing function for a 512-bit block
static void SHA1ProcessBlock(const std::vector<unsigned char>& block, std::array<uint32_t, 5>& H)
{
	// SHA-1 Constants
	constexpr std::array<uint32_t, 4> K
	{
		0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6
	};

	// Initialize message schedule
	uint32_t W[80] = {};

	for (size_t t = 0; t < 16; t++)
	{
		W[t] = (block[t * 4] << 24) | (block[t * 4 + 1] << 16) | (block[t * 4 + 2] << 8) | block[t * 4 + 3];
	}

	for (size_t t = 16; t < 80; t++)
	{
		W[t] = std::rotl(W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16], 1);
	}

	// Initialize hash values for this block
	uint32_t a = H[0];
	uint32_t b = H[1];
	uint32_t c = H[2];
	uint32_t d = H[3];
	uint32_t e = H[4];

	// Main loop
	for (int t = 0; t < 80; t++)
	{
		uint32_t temp = std::rotl(a, 5) + K[t / 20] + e + W[t];
		if (t < 20)
		{
			temp += ((b & c) | ((~b) & d)) + 0x5A827999;
		}
		else if (t < 40)
		{
			temp += (b ^ c ^ d) + 0x6ED9EBA1;
		}
		else if (t < 60)
		{
			temp += ((b & c) | (b & d) | (c & d)) + 0x8F1BBCDC;
		}
		else
		{
			temp += (b ^ c ^ d) + 0xCA62C1D6;
		}

		e = d;
		d = c;
		c = std::rotl(b, 30);
		b = a;
		a = temp;
	}

	// Update hash values for this block
	H[0] += a;
	H[1] += b;
	H[2] += c;
	H[3] += d;
	H[4] += e;
}

inline std::vector<unsigned char> HashUUID( const std::vector<unsigned char>& data, size_t size_limit )
{
	std::vector<unsigned char> result = data;

	while ( result.size() > size_limit )
	{
		std::vector<unsigned char> new_result;

		// Process independent 512-bit (64-byte) blocks
		for ( size_t i = 0; i < result.size(); i += 64 )
		{
			// Extract current block, padding with 0 if less than 64 bytes
			std::vector<unsigned char> block( 64, 0 );
			for ( size_t j = 0; j < 64 && i + j < result.size(); j++ )
			{
				block[ j ] = result[ i + j ];
			}

			// Reinitialize the SHA-1 initial state for the current block
			std::array<uint32_t, 5> H =
			{
				0x67452301,
				0xEFCDAB89,
				0x98BADCFE,
				0x10325476,
				0xC3D2E1F0
			};

			// Process the current block using SHA-1
			SHA1ProcessBlock( block, H );

			// Unpack the hash into a byte array (20 bytes from 5 32-bit words)
			auto unpacked_hash = CommonToolkit::MessageUnpacking<std::uint32_t, std::uint8_t>( H.data(), H.size() );
			new_result.insert( new_result.end(), unpacked_hash.begin(), unpacked_hash.end() );
		}

		// Replace result with the newly computed hash values
		result = std::move( new_result );
	}

	return result;
}

inline std::string GenerateStringFileUUIDFromStringUUID(const std::string& UUID)
{
	//20 Bytes == 160 Bits
	std::vector<std::uint8_t> TruncatedUUIDBytes = HashUUID(UtilTools::DataFormating::Base64Coder::Author1::decode(UUID), 20);

	std::string UniqueFileName = UtilTools::DataFormating::ASCII_Hexadecimal::byteArray2HexadecimalString(TruncatedUUIDBytes);

	Logger::Instance().Debug().Log("File UUID: {}", UniqueFileName);

	return UniqueFileName;
}

inline void SavePasswordManagerUser(const std::pair<PasswordManagerUserKey, PasswordManagerUserData>& NewUserData)
{
	nlohmann::json AllUserData;

	// Load existing all user data (if any)
	try
	{
		std::ifstream file("all_userdata.json");
		if (file.is_open())
		{
			file >> AllUserData;
			file.close();
		}
	}
	catch (const nlohmann::json::exception& e)
	{
		Logger::Instance().Error().Log("Loading existing user all data json: {}", e.what());
		return;
	}

	bool UserExists = false;

	// Search for the existing user data with the same RandomSalt and RandomPasswordSalt
	for (auto& UserData : AllUserData)
	{
		if (UserData["RandomSalt"] == NewUserData.first.RandomSalt && UserData["RandomPasswordSalt"] == NewUserData.first.RandomPasswordSalt)
		{
			// Update the existing user data
			UserData["RandomSalt"] = NewUserData.first.RandomSalt;
			UserData["RandomPasswordSalt"] = NewUserData.first.RandomPasswordSalt;
			UserData["RegistrationTime"] = NewUserData.first.RegistrationTime;
			
			UserData["UserDetails"]["UserName"] = NewUserData.second.UserName;
			UserData["UserDetails"]["HashedPassword"] = NewUserData.second.HashedPassword;
			UserData["UserDetails"]["IsFirstLogin"] = NewUserData.second.IsFirstLogin;
			UserData["UserDetails"]["PersonalPasswordInfoFileName"] = NewUserData.second.PersonalPasswordInfoFileName;

			UserExists = true;
			break;
		}
	}

	if (!UserExists)
	{
		// Create a JSON object for the new user data
		nlohmann::json UserData;
		UserData["UUID"] = NewUserData.first.RandomUUID;
		UserData["RandomSalt"] = NewUserData.first.RandomSalt;
		UserData["RandomPasswordSalt"] = NewUserData.first.RandomPasswordSalt;
		UserData["RegistrationTime"] = NewUserData.first.RegistrationTime;
		
		// Create a nested JSON object for user details
		nlohmann::json UserDataDetails;
		UserDataDetails["UserName"] = NewUserData.second.UserName;
		UserDataDetails["HashedPassword"] = NewUserData.second.HashedPassword;
		UserDataDetails["IsFirstLogin"] = NewUserData.second.IsFirstLogin;
		UserDataDetails["PersonalPasswordInfoFileName"] = NewUserData.second.PersonalPasswordInfoFileName;
		
		UserData["UserDetails"] = UserDataDetails;

		// Add the new user data
		AllUserData.push_back(UserData);

		nlohmann::json CurrentUUID;

		CurrentUUID["UUID"] = NewUserData.first.RandomUUID;

		std::ofstream current_uuid_file("current_uuid.json", std::ios::trunc);
		if (current_uuid_file.is_open())
			current_uuid_file << CurrentUUID.dump(4);
		current_uuid_file.close();
	}

	// Save the updated user data to the file
	std::ofstream userdata_file("all_userdata.json", std::ios::trunc);
	if (userdata_file.is_open())
		userdata_file << AllUserData.dump(4);
	userdata_file.close();
}

inline bool LoadPasswordManagerUUID(PasswordManagerUserKey& CurrentUserKey)
{
	nlohmann::json CurrentUUID;

	// Load existing current uuid (if any)
	std::ifstream file("current_uuid.json");
	if (file.is_open())
	{
		file >> CurrentUUID;

		file.close();

		CurrentUserKey.RandomUUID = CurrentUUID["UUID"];

		std::ifstream all_userdata_file("all_userdata.json");
		if (all_userdata_file.is_open())
		{
			nlohmann::json AllUserData;

			all_userdata_file >> AllUserData;

			all_userdata_file.close();

			// Find the user data by UUID
			for (const auto& UserData : AllUserData)
			{
				if (UserData["UUID"] == CurrentUserKey.RandomUUID)
				{
					CurrentUserKey.RandomSalt = UserData["RandomSalt"];
					CurrentUserKey.RandomPasswordSalt = UserData["RandomPasswordSalt"];
					CurrentUserKey.RegistrationTime = UserData["RegistrationTime"];
					break;
				}
			}
		}
		else
		{
			Logger::Instance().Error().Log("Loading file all_userdata.json");
		}

		return true;
	}
	else
	{
		Logger::Instance().Error().Log("Loading file current_uuid.json");
	}

	return false;
}

inline void LoadPasswordManagerUser(const PasswordManagerUserKey& CurrentUserKey, PasswordManagerUserData& EmptyUserData)
{
	// Load existing all user data
	nlohmann::json AllUserData;
	try
	{
		std::ifstream file("all_userdata.json");
		if (file.is_open())
		{
			file >> AllUserData;

			file.close();
		}
	}
	catch (const nlohmann::json::exception& e)
	{
		Logger::Instance().Error().Log("Loading existing user all data json: {}", e.what());
		return;
	}

	// Find the user data by UUID
	for (const auto& UserData : AllUserData)
	{
		if (UserData["UUID"] == CurrentUserKey.RandomUUID)
		{
			EmptyUserData.UserName = UserData["UserDetails"]["UserName"];
			EmptyUserData.HashedPassword = UserData["UserDetails"]["HashedPassword"];
			EmptyUserData.IsFirstLogin = UserData["UserDetails"]["IsFirstLogin"];
			EmptyUserData.PersonalPasswordInfoFileName = UserData["UserDetails"]["PersonalPasswordInfoFileName"];
			break;
		}
	}
}

inline std::string PasswordAndHash(const std::vector<char>& Password, std::string RandomSalt)
{
	std::string PasswordString(Password.begin(), Password.end());

	auto new_end = std::find_if
	(
		PasswordString.rbegin(), PasswordString.rend(), 
		[](char character)
		{
			return character != '\x00';
		}
	);

	PasswordString.erase(new_end.base(), PasswordString.end());

	CommonSecurity::SHA::Hasher::HasherTools MainHasher;
	//auto optionalHashedHexadecimalString = MainHasher.GenerateBlake2Hashed(Blake2HashedMessage, true, 2048);
	auto OptionalHashedHexadecimalString = MainHasher.GenerateBlake2Hashed(PasswordString + RandomSalt, false, 512);
	if(OptionalHashedHexadecimalString.has_value())
		return OptionalHashedHexadecimalString.value();
	else
		throw std::invalid_argument("If the size of the source string message is zero, then it cannot be transformed into the target hash digest message! ");

	return "";
}

inline std::string PasswordAndHash(const std::string& Password, std::string RandomSalt)
{
	std::string PasswordString(Password.begin(), Password.end());

	auto new_end = std::find_if
	(
		PasswordString.rbegin(), PasswordString.rend(), 
		[](char character)
		{
			return character != '\x00';
		}
	);

	CommonSecurity::SHA::Hasher::HasherTools MainHasher;
	//auto optionalHashedHexadecimalString = MainHasher.GenerateBlake2Hashed(Blake2HashedMessage, true, 2048);
	auto OptionalHashedHexadecimalString = MainHasher.GenerateBlake2Hashed(PasswordString + RandomSalt, false, 512);
	if (OptionalHashedHexadecimalString.has_value())
	{
		return OptionalHashedHexadecimalString.value();
	}
	else
	{
		Logger::Instance().Fatal().Log("If the size of the source string message is zero, then it cannot be transformed into the target hash digest message! ");
		//todo: logger::Instance().WaitAll()
		std::terminate();
	}
}

inline bool VerifyUUID(const std::vector<char>& Username, const std::string& RandomSalt, uint64_t& RegistrationTime, const PasswordManagerUserKey& CurrentUserKey)
{
	// Load existing all user data
	nlohmann::json CurrentUUID;

	std::ifstream file("current_uuid.json");
	if (file.is_open())
	{
		file >> CurrentUUID;

		file.close();
	}
	else
	{
		Logger::Instance().Error().Log("Loading existing all user data");
	}

	CommonSecurity::DataHashingWrapper::HashersAssistantParameters HAP_ObjectArgument {};
	HAP_ObjectArgument.hash_mode = CommonSecurity::SHA::Hasher::WORKER_MODE::CHINA_SHANG_YONG_MI_MA3;
	HAP_ObjectArgument.generate_hash_bit_size = 512;
	HAP_ObjectArgument.whether_use_hash_extension_bit_mode = false;
	HAP_ObjectArgument.inputDataString = "";
	HAP_ObjectArgument.outputHashedHexadecimalString = "";

	std::string HMAC_String = CommonSecurity::DataHashingWrapper::HMAC_FunctionObject(HAP_ObjectArgument, std::string(Username.begin(), Username.end()), 512 / 8, RandomSalt + std::to_string(RegistrationTime));

	for(int count = 0; count < 7; count++)
	{
		HMAC_String.append(CommonSecurity::DataHashingWrapper::HMAC_FunctionObject(HAP_ObjectArgument, HMAC_String, 512 / 8, RandomSalt + std::to_string(RegistrationTime)));
	}

	auto HMAC_BytesData = UtilTools::DataFormating::ASCII_Hexadecimal::hexadecimalString2ByteArray(HMAC_String);

	std::string UUID = UtilTools::DataFormating::Base64Coder::Author1::encode(HMAC_BytesData);

	if(CurrentUUID["UUID"] != UUID)
	{
		Logger::Instance().Debug().Log("UUID Authentication has failed.");
		return false;
	}

	Logger::Instance().Debug().Log("UUID Authentication has successful!");

	return true;
}

inline bool VerifyPassword(const std::vector<char>& Password, const PasswordManagerUserKey& CurrentUserKey, const PasswordManagerUserData& CurrentUserData)
{
	// Hash the password with the stored salt
	std::string HashedPassword = PasswordAndHash(Password, CurrentUserKey.RandomPasswordSalt);

	if(HashedPassword.size() != CurrentUserData.HashedPassword.size())
		return false;

	//Secure Compare the hashed passwords
	bool isSame = true;

	for(size_t Index = 0; Index < HashedPassword.size(); ++Index)
	{
		isSame &= ~static_cast<bool>(HashedPassword[Index] ^ CurrentUserData.HashedPassword[Index]);
	}

	return isSame;
}

inline std::string MakeTokenString(const std::string& UUID, const std::vector<char>& BufferLoginPassword)
{
	std::string PasswordString = std::string(BufferLoginPassword.begin(), BufferLoginPassword.end());

	// 使用std::find_if函数从末尾开始查找第一个非零的字符，并返回它的迭代器
	auto new_end = std::find_if
	(
		PasswordString.rbegin(), PasswordString.rend(),
		[](char character)
		{
			return character != '\x00';
		}
	);

	// 使用std::string的erase方法删除末尾的元素
	PasswordString.erase(new_end.base(), PasswordString.end());

	return UUID + PasswordString;
}

inline std::string MakeTokenString(const std::string& UUID, const std::string& BufferLoginPassword)
{
	std::string PasswordString = std::string(BufferLoginPassword.begin(), BufferLoginPassword.end());

	// 使用std::find_if函数从末尾开始查找第一个非零的字符，并返回它的迭代器
	auto new_end = std::find_if
	(
		PasswordString.rbegin(), PasswordString.rend(),
		[](char character)
		{
			return character != '\x00';
		}
	);

	// 使用std::string的erase方法删除末尾的元素
	PasswordString.erase(new_end.base(), PasswordString.end());

	return UUID + PasswordString;
}

inline std::vector<std::uint8_t> GenerateMasterBytesKeyFromToken(const std::string& Token)
{
	using namespace CommonSecurity::SHA;

	std::vector<std::string> UUID_Parts;
	size_t PartSize = Token.size() / 4;

	for (size_t i = 0; i < 4; ++i)
	{
		UUID_Parts.push_back(Token.substr(i * PartSize, PartSize));
	}

	//256 Bits / 8 Bits = 32 Bytes
	std::size_t NeedKeyStreamSize = 32;

	CommonSecurity::DataHashingWrapper::HashTokenForDataParameters HashToken_Parameters {};
	HashToken_Parameters.HashersAssistantParameters_Instance.hash_mode = Hasher::WORKER_MODE::BLAKE3;
	HashToken_Parameters.HashersAssistantParameters_Instance.whether_use_hash_extension_bit_mode = true;
	HashToken_Parameters.HashersAssistantParameters_Instance.generate_hash_bit_size = 1024;
	HashToken_Parameters.OriginalPasswordStrings =  UUID_Parts;
	HashToken_Parameters.NeedHashByteTokenSize = NeedKeyStreamSize;

	//Block size is 256 bit
	std::optional<std::deque<std::vector<std::uint8_t>>> HaveKeyStream = BuildingKeyStream<256>(HashToken_Parameters);

	return HaveKeyStream.value()[0];
}

inline void MakePersonalFiles(const std::filesystem::path& UniquePathName_Password, const std::filesystem::path& UniquePathName_File, const std::string& Token)
{
	std::filesystem::path UniqueParentPathName_Password = UniquePathName_Password.parent_path();
	std::filesystem::path UniqueParentPathName_File = UniquePathName_File.parent_path();

	if(!std::filesystem::is_directory(UniqueParentPathName_Password))
	{
		if (!std::filesystem::create_directories(UniqueParentPathName_Password))
		{
			Logger::Instance().Fatal().Log("Failed to create directory. Password:{0}", UniqueParentPathName_Password.string());
			Logger::Instance().StopAndWaitAll();
			std::terminate();
			return;
		}
	}

	if(!std::filesystem::is_directory(UniqueParentPathName_File))
	{
		if (!std::filesystem::create_directories(UniqueParentPathName_File))
		{
			Logger::Instance().Fatal().Log("Failed to create directory. Directory:{0}", UniqueParentPathName_File.string());
			Logger::Instance().StopAndWaitAll();
			std::terminate();
			return;
		}
	}

	if (std::filesystem::exists(UniquePathName_Password))
	{
		Logger::Instance().Error().Log("File already exists. FilePath: {0}", UniquePathName_Password.string());
		return;
	}
	else
	{
		
		#ifdef _WIN32
			std::ofstream file(UniquePathName_Password.string(), std::ios::trunc);
		#else
			std::ofstream file(UniquePathName_Password.c_str(), std::ios::trunc);
		#endif

		if (file.is_open())
		{
			file.close();
			Logger::Instance().Info().Log("Personal password data file created: {0}", UniquePathName_Password.string());
		}
		else
		{
			Logger::Instance().Fatal().Log("Failed to create the personal password data file. FilePath: {0}", UniquePathName_Password.string());
			Logger::Instance().StopAndWaitAll();
			std::terminate();
		}
	}

	if (std::filesystem::exists(UniquePathName_File))
	{
		Logger::Instance().Error().Log("File already exists. FilePath: {0}", UniquePathName_File.string());
		return;
	}
	else
	{
		#ifdef _WIN32
			std::ofstream file(UniquePathName_File.string(), std::ios::trunc);
		#else
			std::ofstream file(UniquePathName_File.c_str(), std::ios::trunc);
		#endif

		if (file.is_open())
		{
			file.close();
			Logger::Instance().Info().Log("Personal data file created : {0}", UniquePathName_File.string());
		}
		else
		{
			Logger::Instance().Fatal().Log("Failed to create the personal data file. FilePath: {0}", UniquePathName_File.string());
			Logger::Instance().StopAndWaitAll();
			std::terminate();
		}
	}
	
	PersonalPasswordInfo PersonalPasswordInfo;
	
	RegenerateMasterKey(PersonalPasswordInfo, Token);

	PersonalPasswordInfo.Serialization(UniquePathName_Password);

	PersonalFileInfo PersonalFileInfo;

	PersonalFileInfo.Serialization(UniquePathName_File);
}

inline void FirstLoginLogic(const std::vector<char>& BufferLoginPassword, const PasswordManagerUserKey& CurrentUserKey, PasswordManagerUserData& CurrentUserData)
{
	std::string UniqueFileName = GenerateStringFileUUIDFromStringUUID(CurrentUserKey.RandomUUID);
	std::string Token = MakeTokenString(CurrentUserKey.RandomUUID, BufferLoginPassword);

	CurrentUserData.PersonalPasswordInfoFileName = "Passwords_" + UniqueFileName + ".json";
	CurrentUserData.PersonalDataInfoFileName = "Files_" + UniqueFileName + ".json";

	CurrentUserData.PersonalPasswordInfoFileName = "Passwords_" + UniqueFileName + ".json";
	CurrentUserData.PersonalDataInfoFileName = "Files_" + UniqueFileName + ".json";

	std::filesystem::path CurrentPath = std::filesystem::current_path();

	std::filesystem::path FullPath = CurrentPath / "PersonalPasswordData" / CurrentUserData.PersonalPasswordInfoFileName;
	std::filesystem::path FullPath2 = CurrentPath / "PersonalFileData" / CurrentUserData.PersonalDataInfoFileName;

	MakePersonalFiles
	(
		FullPath,
		FullPath2,
		Token
	);

	CurrentUserData.IsFirstLogin = false;

	SavePasswordManagerUser({CurrentUserKey, CurrentUserData});
}


/***** PersonaPasswordInfo Functions *****/

void PersonalPasswordInfo::Serialization(const std::filesystem::path& FilePath)
{
	// Serialize the JSON data
	nlohmann::json PersonalPasswordInfo_JSON;

	PersonalPasswordInfo_JSON["HashMap_EncryptedSymmetricKey"] = HashMap_EncryptedSymmetricKey;

	PersonalPasswordInfo_JSON["HashMap_DecryptedSymmetricKey_Hashed"] = HashMap_DecryptedSymmetricKey_Hashed;

	nlohmann::json PasswordInstances;

	for (PersonalPasswordInstance& PasswordInstance : this->Instances)
	{
		nlohmann::json JsonObject;
		JsonObject["ID"] = PasswordInstance.ID;

		auto new_end = std::find_if
		(
			PasswordInstance.Description.rbegin(), PasswordInstance.Description.rend(), 
			[](char character)
			{
				return character != '\x00';
			}
		);
		PasswordInstance.Description.erase(new_end.base(), PasswordInstance.Description.end());
		JsonObject["Description"] = PasswordInstance.Description;

		JsonObject["EncryptedPassword"] = PasswordInstance.EncryptedPassword;
		JsonObject["EncryptionAlgorithmNames"] = PasswordInstance.EncryptionAlgorithmNames;
		JsonObject["DecryptionAlgorithmNames"] = PasswordInstance.DecryptionAlgorithmNames;
		JsonObject["HashMapID"] = PasswordInstance.HashMapID;
		PasswordInstances.push_back(JsonObject);
	}

	PersonalPasswordInfo_JSON["PasswordInstances"] = PasswordInstances;

	// Write the JSON file
	#ifdef _WIN32
		std::ofstream file(FilePath.string());
	#else
		std::ofstream file(FilePath.c_str());
	#endif

	if (file.is_open())
	{
		file << PersonalPasswordInfo_JSON.dump(4);
		file.close();
		Logger::Instance().Info().Log("Serialization completed to {0}", FilePath.string());
	}
	else
	{
		Logger::Instance().Error().Log("Failed to open the file for writing. FilePath: {0}", FilePath.string());
	}
}

void PersonalPasswordInfo::Deserialization(const std::filesystem::path& FilePath)
{
	nlohmann::json PersonalPasswordInfo_JSON;

	// Read the JSON file
	#ifdef _WIN32
		std::ifstream file(FilePath.string());
	#else
		std::ifstream file(FilePath.c_str());
	#endif

	if (!file.is_open())
	{
		Logger::Instance().Fatal().Log("Failed to open the file for reading. FilePath: {0}", FilePath.string());
		Logger::Instance().StopAndWaitAll();
		std::terminate();
	}
	else
	{
		file >> PersonalPasswordInfo_JSON;
		file.close();
	}

	// Deserialize the JSON data
	if (PersonalPasswordInfo_JSON.is_object())
	{
		if (PersonalPasswordInfo_JSON.contains("HashMap_EncryptedSymmetricKey"))
		{
			HashMap_EncryptedSymmetricKey = PersonalPasswordInfo_JSON["HashMap_EncryptedSymmetricKey"];
		}

		if (PersonalPasswordInfo_JSON.contains("HashMap_DecryptedSymmetricKey_Hashed"))
		{
			HashMap_DecryptedSymmetricKey_Hashed = PersonalPasswordInfo_JSON["HashMap_DecryptedSymmetricKey_Hashed"];
		}

		if (PersonalPasswordInfo_JSON.contains("PasswordInstances") && PersonalPasswordInfo_JSON["PasswordInstances"].is_array())
		{
			Instances.clear();
			for (const nlohmann::json& JsonObject : PersonalPasswordInfo_JSON["PasswordInstances"])
			{
				if (JsonObject.is_object())
				{
					PersonalPasswordInstance PasswordInstance;
					if (JsonObject.contains("ID"))
						PasswordInstance.ID = JsonObject["ID"];
					if (JsonObject.contains("Description"))
						PasswordInstance.Description = JsonObject["Description"];
					if (JsonObject.contains("EncryptedPassword"))
						PasswordInstance.EncryptedPassword = JsonObject["EncryptedPassword"];
					if (JsonObject.contains("EncryptionAlgorithmNames"))
						PasswordInstance.EncryptionAlgorithmNames = JsonObject["EncryptionAlgorithmNames"];
					if (JsonObject.contains("DecryptionAlgorithmNames"))
						PasswordInstance.DecryptionAlgorithmNames = JsonObject["DecryptionAlgorithmNames"];
					if (JsonObject.contains("HashMapID"))
						PasswordInstance.HashMapID = JsonObject["HashMapID"];
					Instances.push_back(PasswordInstance);
				}
			}
		}

		Logger::Instance().Info().Log("Deserialization completed from {0}", FilePath.string());
	}
}

/**
 * Recomputes the encrypted password for a personal password instance using a new master key and encryption algorithms.
 *
 * @param NewInstancePassword The new password to be encrypted.
 * @param Token The token used to generate the master key.
 * @param Instance The personal password instance to update with the new encrypted password.
 */
void PersonalPasswordInfo::RecomputeEncryptedPassword(const std::string& NewInstancePassword, const std::string& Token, PersonalPasswordInstance& Instance)
{
	// Generate the master key from the provided token.
	std::vector<uint8_t> MasterKey = GenerateMasterBytesKeyFromToken(Token);

	// Retrieve the encrypted symmetric key and its hash for the specified instance.
	std::vector<uint8_t> EncryptedInstanceKey = this->HashMap_EncryptedSymmetricKey[Instance.HashMapID];
	const std::string InstanceKeyHash = this->HashMap_DecryptedSymmetricKey_Hashed[Instance.HashMapID];
	// Initialize an SM4 encryption object for data manipulation.
	CommonSecurity::ChinaShangYongMiMa4::DataWorker256 SM4_128_256;

	// Initialize a buffer for the decrypted instance key.
	std::vector<uint8_t> DecryptedInstanceKey(256 / 8, 0x00);

	// Decrypt the instance key using SM4 with Block Cipher Counter Mode.
	SM4_128_256.CTR_StreamModeBasedEncryptFunction(EncryptedInstanceKey, MasterKey, DecryptedInstanceKey);

	// Initialize hashing parameters for SHA-512.
	using namespace CommonSecurity::SHA;
	CommonSecurity::DataHashingWrapper::HashersAssistantParameters HAP_ObjectArgument {};
	HAP_ObjectArgument.hash_mode = CommonSecurity::SHA::Hasher::WORKER_MODE::SHA2_512;
	HAP_ObjectArgument.generate_hash_bit_size = 512;
	HAP_ObjectArgument.whether_use_hash_extension_bit_mode = false;

	// Calculate the hash of the decrypted instance key.
	HAP_ObjectArgument.inputDataString = UtilTools::DataFormating::ASCII_Hexadecimal::byteArray2HexadecimalString(DecryptedInstanceKey);
	CommonSecurity::DataHashingWrapper::HashersAssistant::SELECT_HASH_FUNCTION(HAP_ObjectArgument);
	
	// Check if the calculated hash matches the stored instance key hash.
	if(HAP_ObjectArgument.outputHashedHexadecimalString != InstanceKeyHash)
	{
		Logger::Instance().Debug().Log("UUID generation of the master key gives unexpectedly different results, check if the algorithm used is correct or if the algorithm is deterministic!");
		throw std::logic_error("");
	}

	// Initialize a buffer for the encrypt password data
	std::vector<uint8_t> PasswordBytes(NewInstancePassword.size(), 0x00);
	::memcpy(PasswordBytes.data(), NewInstancePassword.data(), NewInstancePassword.size() * sizeof(uint8_t));

	// Encrypt the new password using the specified decryption algorithms with block cipher counter mode.
	for (const auto& Algorithm : Instance.EncryptionAlgorithmNames)
	{
		if (Algorithm == CryptoCipherAlgorithmNames[0])
		{
			CommonSecurity::AES::DataWorker256 AES_128_256;
			AES_128_256.CTR_StreamModeBasedDecryptFunction(PasswordBytes, DecryptedInstanceKey, PasswordBytes);
		}
		if (Algorithm == CryptoCipherAlgorithmNames[1])
		{
			CommonSecurity::RC6::DataWorker128_256 RC6_128_256;
			RC6_128_256.CTR_StreamModeBasedDecryptFunction(PasswordBytes, DecryptedInstanceKey, PasswordBytes);
		}
		if (Algorithm == CryptoCipherAlgorithmNames[2])
		{
			SM4_128_256.CTR_StreamModeBasedDecryptFunction(PasswordBytes, DecryptedInstanceKey, PasswordBytes);
		}
		if (Algorithm == CryptoCipherAlgorithmNames[3])
		{
			CommonSecurity::Twofish::DataWorker256 Twofish_128_256;
			Twofish_128_256.CTR_StreamModeBasedDecryptFunction(PasswordBytes, DecryptedInstanceKey, PasswordBytes);
		}
		if (Algorithm == CryptoCipherAlgorithmNames[4])
		{
			CommonSecurity::Serpent::DataWorker256 Serpent_128_256;
			Serpent_128_256.CTR_StreamModeBasedDecryptFunction(PasswordBytes, DecryptedInstanceKey, PasswordBytes);
		}
	}

	// Encode the encrypted password in Base64 format.
	Instance.EncryptedPassword = UtilTools::DataFormating::Base64Coder::Author1::encode(PasswordBytes);

	// Securely wipe the sensitive keys by setting them to all zeroes.
	memory_set_no_optimize_function<0x00>(MasterKey.data(), MasterKey.size() * sizeof(uint8_t));
	memory_set_no_optimize_function<0x00>(DecryptedInstanceKey.data(), DecryptedInstanceKey.size() * sizeof(uint8_t));
	memory_set_no_optimize_function<0x00>(EncryptedInstanceKey.data(), EncryptedInstanceKey.size() * sizeof(uint8_t));
}

/**
 * Recomputes the decrypted password for a personal password instance using a old master key and decryption algorithms.
 *
 * @param Token The token used to generate the master key.
 * @param Instance The personal password instance to update with the old decrypted password.
 */
void PersonalPasswordInfo::RecomputeDecryptedPassword(const std::string& Token, PersonalPasswordInstance& Instance)
{
	// Generate the master key from the provided token.
	std::vector<uint8_t> MasterKey = GenerateMasterBytesKeyFromToken(Token);

	// Retrieve the encrypted symmetric key and its hash for the specified instance.
	std::vector<uint8_t> EncryptedInstanceKey = this->HashMap_EncryptedSymmetricKey[Instance.HashMapID];
	const std::string InstanceKeyHash = this->HashMap_DecryptedSymmetricKey_Hashed[Instance.HashMapID];
	// Initialize an SM4 encryption object for data manipulation.
	CommonSecurity::ChinaShangYongMiMa4::DataWorker256 SM4_128_256;

	// Initialize a buffer for the decrypted instance key.
	std::vector<uint8_t> DecryptedInstanceKey(256 / 8, 0x00);

	// Decrypt the instance key using SM4 with Block Cipher Counter Mode.
	SM4_128_256.CTR_StreamModeBasedEncryptFunction(EncryptedInstanceKey, MasterKey, DecryptedInstanceKey);

	// Initialize hashing parameters for SHA-512.
	using namespace CommonSecurity::SHA;
	CommonSecurity::DataHashingWrapper::HashersAssistantParameters HAP_ObjectArgument {};
	HAP_ObjectArgument.hash_mode = CommonSecurity::SHA::Hasher::WORKER_MODE::SHA2_512;
	HAP_ObjectArgument.generate_hash_bit_size = 512;
	HAP_ObjectArgument.whether_use_hash_extension_bit_mode = false;

	// Calculate the hash of the decrypted instance key.
	HAP_ObjectArgument.inputDataString = UtilTools::DataFormating::ASCII_Hexadecimal::byteArray2HexadecimalString(DecryptedInstanceKey);
	CommonSecurity::DataHashingWrapper::HashersAssistant::SELECT_HASH_FUNCTION(HAP_ObjectArgument);
	
	// Check if the calculated hash matches the stored instance key hash.
	if(HAP_ObjectArgument.outputHashedHexadecimalString != InstanceKeyHash)
	{
		Logger::Instance().Debug().Log("UUID generation of the master key gives unexpectedly different results, check if the algorithm used is correct or if the algorithm is deterministic!");
		throw std::logic_error("");
	}

	// Initialize a buffer for the decrypt password data
	// Decode the encrypted password in Base64 format.
	std::vector<uint8_t> PasswordBytes = UtilTools::DataFormating::Base64Coder::Author1::decode(Instance.EncryptedPassword);

	// Decrypt the old password using the specified decryption algorithms with block cipher counter mode.
	for(const auto& Algorithm : Instance.DecryptionAlgorithmNames)
	{
		if(Algorithm == CryptoCipherAlgorithmNames[0])
		{
			CommonSecurity::AES::DataWorker256 AES_128_256;
			AES_128_256.CTR_StreamModeBasedDecryptFunction(PasswordBytes, DecryptedInstanceKey, PasswordBytes);
		}
		if(Algorithm == CryptoCipherAlgorithmNames[1])
		{
			CommonSecurity::RC6::DataWorker128_256 RC6_128_256;
			RC6_128_256.CTR_StreamModeBasedDecryptFunction(PasswordBytes, DecryptedInstanceKey, PasswordBytes);
		}
		if(Algorithm == CryptoCipherAlgorithmNames[2])
		{
			SM4_128_256.CTR_StreamModeBasedDecryptFunction(PasswordBytes, DecryptedInstanceKey, PasswordBytes);
		}
		if(Algorithm == CryptoCipherAlgorithmNames[3])
		{
			CommonSecurity::Twofish::DataWorker256 Twofish_128_256;
			Twofish_128_256.CTR_StreamModeBasedDecryptFunction(PasswordBytes, DecryptedInstanceKey, PasswordBytes);
		}
		if(Algorithm == CryptoCipherAlgorithmNames[4])
		{
			CommonSecurity::Serpent::DataWorker256 Serpent_128_256;
			Serpent_128_256.CTR_StreamModeBasedDecryptFunction(PasswordBytes, DecryptedInstanceKey, PasswordBytes);
		}
	}

	auto new_end = std::find_if
	(
		PasswordBytes.rbegin(), PasswordBytes.rend(), 
		[](char character)
		{
			return character != '\x00';
		}
	);

	// 使用std::string的erase方法删除末尾的元素
	PasswordBytes.erase(new_end.base(), PasswordBytes.end());

	Instance.DecryptedPassword.resize(PasswordBytes.size(), 0x00);
	::memcpy(Instance.DecryptedPassword.data(), PasswordBytes.data(), PasswordBytes.size() * sizeof(uint8_t));

	// Securely wipe the sensitive keys by setting them to all zeroes.
	memory_set_no_optimize_function<0x00>(MasterKey.data(), MasterKey.size() * sizeof(uint8_t));
	memory_set_no_optimize_function<0x00>(DecryptedInstanceKey.data(), DecryptedInstanceKey.size() * sizeof(uint8_t));
	memory_set_no_optimize_function<0x00>(EncryptedInstanceKey.data(), EncryptedInstanceKey.size() * sizeof(uint8_t));
}

PersonalPasswordInfo::PersonalPasswordInstance PersonalPasswordInfo::CreatePasswordInstance
(
	const std::string& Token,
	const std::string& ShowPPI_Description,
	const std::string& Password,
	const std::vector<std::string>& EncryptionAlgorithms,
	const std::vector<std::string>& DecryptionAlgorithms
)
{
	PersonalPasswordInfo::PersonalPasswordInstance instance;

	instance.ID = this->Instances.empty() ? 0 : (this->Instances.back().ID + 1);
	instance.Description = ShowPPI_Description;
	instance.EncryptedPassword = "";
	instance.EncryptionAlgorithmNames = EncryptionAlgorithms;
	instance.DecryptionAlgorithmNames = DecryptionAlgorithms;

	if(this->HashMap_EncryptedSymmetricKey.empty())
	{
		Logger::Instance().Fatal().Log("HashMap_EncryptedSymmetricKey is empty!");
		Logger::Instance().StopAndWaitAll();
		std::terminate();
	}

	instance.HashMapID = std::random_device{}() % this->HashMap_EncryptedSymmetricKey.size();

	this->RecomputeEncryptedPassword(Password, Token, instance);

	return instance;
}

void PersonalPasswordInfo::AppendPasswordInstance(const PersonalPasswordInfo::PersonalPasswordInstance& instance)
{
	this->Instances.push_back(instance);
}

bool PersonalPasswordInfo::ChangePasswordInstance
(
	std::uint64_t ID,
	const std::string& NewDescription,
	const std::string& NewPassword,
	const std::vector<std::string>& NewEncryptionAlgorithms,
	const std::vector<std::string>& NewDecryptionAlgorithms,
	const std::string& Token,
	bool ChangeEncryptedPassword
)
{
	// Find the instance by ID
	auto it = std::find_if
	(
		Instances.begin(), Instances.end(),
		[ID](const PersonalPasswordInstance& instance)
		{
			return instance.ID == ID;
		}
	);

	if (it == Instances.end())
	{
		// Instance with the given ID not found
		return false;
	}

	PersonalPasswordInstance& instance = *it;

	// Update the password instance fields
	instance.Description = NewDescription;
	if(!NewEncryptionAlgorithms.empty() && instance.EncryptionAlgorithmNames != NewEncryptionAlgorithms)
		instance.EncryptionAlgorithmNames = NewEncryptionAlgorithms;
	if(!NewDecryptionAlgorithms.empty() && instance.DecryptionAlgorithmNames != NewDecryptionAlgorithms)
		instance.DecryptionAlgorithmNames = NewDecryptionAlgorithms;

	if (ChangeEncryptedPassword)
	{
		// Recompute the encrypted password
		RecomputeEncryptedPassword(NewPassword, Token, instance);
	}

	return true;
}

std::vector<PersonalPasswordInfo::PersonalPasswordInstance>& PersonalPasswordInfo::GetPassswordInstances()
{
	return this->Instances;
}

void PersonalPasswordInfo::ListAllPasswordInstance
(
	const std::string& Token
)
{
	for(std::uint64_t ID = 0; ID < this->Instances.size(); ID++)
	{
		PersonalPasswordInfo::PersonalPasswordInstance instance(Instances[ID]);
		this->RecomputeDecryptedPassword(Token, instance);
		this->Instances[ID].DecryptedPassword = instance.DecryptedPassword;
	}
}

void PersonalPasswordInfo::RemoveAllPasswordInstance()
{
	this->Instances.clear();
	this->Instances.shrink_to_fit();
}

bool PersonalPasswordInfo::RemovePasswordInstance(std::uint64_t ID)
{
	auto it = std::remove_if
	(
		Instances.begin(), Instances.end(),
		[ID](const PersonalPasswordInstance& instance)
		{
			return instance.ID == ID;
		}
	);

	if (it != Instances.end())
	{
		Instances.erase(it);
		for(std::uint64_t ID = 0; ID < this->Instances.size(); ID++)
		{
			Instances[ID].ID = ID;
		}
		return true;
	}

	return false;
}

std::optional<PersonalPasswordInfo::PersonalPasswordInstance> PersonalPasswordInfo::FindPasswordInstanceByID(const std::string& Token, std::uint64_t ID)
{
	auto it = std::find_if
	(
		Instances.begin(), Instances.end(),
		[ID](const PersonalPasswordInstance& instance)
		{
			return instance.ID == ID;
		}
	);

	if (it != Instances.end())
	{
		PersonalPasswordInfo::PersonalPasswordInstance instance(*it);
		this->RecomputeDecryptedPassword(Token, instance);
		return instance;
	}

	return std::nullopt;
}

std::string PersonalPasswordInfo::FindPasswordInstanceDescriptionByID(std::uint64_t ID)
{
	auto it = std::find_if
	(
		Instances.begin(), Instances.end(),
		[ID](const PersonalPasswordInstance& instance)
		{
			return instance.ID == ID;
		}
	);

	if (it != Instances.end())
	{
		return (*it).Description;
	}

	return "";
}

std::optional<PersonalPasswordInfo::PersonalPasswordInstance> PersonalPasswordInfo::FindPasswordInstanceByDescription(const std::string& Token, const std::string& Description)
{
	auto it = std::find_if
	(
		Instances.begin(), Instances.end(),
		[Description](const PersonalPasswordInstance& instance)
		{
			return instance.Description == Description;
		}
	);

	if (it != Instances.end())
	{
		PersonalPasswordInfo::PersonalPasswordInstance instance(*it);
		this->RecomputeDecryptedPassword(Token, instance);
		return instance;
	}

	// 如果没有找到，可以返回一个默认值或抛出异常
	return std::nullopt;
}

void PersonalPasswordInfo::ChangeInstanceMasterKeyWithSystemPassword(const std::filesystem::path& FilePath, const std::string& Token, const std::string& NewToken)
{
	if (!std::filesystem::exists(FilePath))
		return;

	if(Token == NewToken)
		return;

	this->Deserialization(FilePath);

	std::vector<std::string> DecryptedPasswordText(this->Instances.size());
	std::vector<std::string> InstanceDescriptions(this->Instances.size());
	std::unordered_map<uint64_t, std::vector<std::string>> InstanceEncryptionAlgorithmNames {};
	std::unordered_map<uint64_t, std::vector<std::string>> InstanceDecryptionAlgorithmNames {};

	for (std::uint64_t ID = 0; ID < this->Instances.size(); ID++)
	{
		this->RecomputeDecryptedPassword(Token, this->Instances[ID]);
		DecryptedPasswordText[ID] = this->Instances[ID].DecryptedPassword;
		InstanceDescriptions[ID] = this->Instances[ID].Description;
		InstanceEncryptionAlgorithmNames[ID] = this->Instances[ID].EncryptionAlgorithmNames;
		InstanceDecryptionAlgorithmNames[ID] = this->Instances[ID].DecryptionAlgorithmNames;

		// Securely wipe the sensitive keys by setting them to all zeroes.
		memory_set_no_optimize_function<0x00>(this->Instances[ID].DecryptedPassword.data(), this->Instances[ID].DecryptedPassword.size() * sizeof(char));
		this->Instances[ID].DecryptedPassword.clear();
	}

	this->RemoveAllPasswordInstance();
	this->HashMap_EncryptedSymmetricKey.clear();
	this->HashMap_DecryptedSymmetricKey_Hashed.clear();

	PersonalPasswordInfo NewPersonalPasswordInfo;
	RegenerateMasterKey(NewPersonalPasswordInfo, NewToken);
	this->HashMap_EncryptedSymmetricKey = NewPersonalPasswordInfo.HashMap_EncryptedSymmetricKey;
	this->HashMap_DecryptedSymmetricKey_Hashed = NewPersonalPasswordInfo.HashMap_DecryptedSymmetricKey_Hashed;

	this->Serialization(FilePath);

	this->Deserialization(FilePath);

	for (std::uint64_t ID = 0; ID < DecryptedPasswordText.size(); ID++)
	{
		auto PersonalPasswordInstance = this->CreatePasswordInstance
		(
			NewToken, InstanceDescriptions[ID], DecryptedPasswordText[ID],
			InstanceEncryptionAlgorithmNames[ID], InstanceDecryptionAlgorithmNames[ID]
		);
		this->Instances.push_back(PersonalPasswordInstance);

		// Securely wipe the sensitive keys by setting them to all zeroes.
		memory_set_no_optimize_function<0x00>(DecryptedPasswordText[ID].data(), DecryptedPasswordText[ID].size() * sizeof(char));
	}

	this->Serialization(FilePath);
}


/***** PersonalFileInfo Functions *****/

// PersonalFileInfo 类的序列化辅助函数
void PersonalFileInfo::SerializeInstances(nlohmann::json& jsonData) const
{
	nlohmann::json FileInstancesJSON;

	for (const PersonalFileInstance& FileInstance : this->Instances)
	{
		nlohmann::json JsonObject;
		JsonObject["ID"] = FileInstance.ID;
		JsonObject["EncryptionAlgorithmNames"] = FileInstance.EncryptionAlgorithmNames;
		JsonObject["DecryptionAlgorithmNames"] = FileInstance.DecryptionAlgorithmNames;
		FileInstancesJSON.push_back(JsonObject);
	}

	jsonData["FileInstances"] = FileInstancesJSON;
}

// PersonalFileInfo 类的反序列化辅助函数
void PersonalFileInfo::DeserializeInstances(const nlohmann::json& jsonData)
{
	if (jsonData.contains("FileInstances") && jsonData["FileInstances"].is_array())
	{
		Instances.clear();
		for (const auto& JsonObject : jsonData["FileInstances"])
		{
			if (JsonObject.is_object())
			{
				PersonalFileInstance FileInstance;
				if (JsonObject.contains("ID"))
					FileInstance.ID = JsonObject["ID"];
				if (JsonObject.contains("EncryptionAlgorithmNames"))
					FileInstance.EncryptionAlgorithmNames = JsonObject["EncryptionAlgorithmNames"];
				if (JsonObject.contains("DecryptionAlgorithmNames"))
					FileInstance.DecryptionAlgorithmNames = JsonObject["DecryptionAlgorithmNames"];
				Instances.push_back(FileInstance);
			}
		}
	}
}

// 序列化函数
void PersonalFileInfo::Serialization(const std::filesystem::path& FilePath)
{
	nlohmann::json PersonalFileInfo_JSON;

	SerializeInstances(PersonalFileInfo_JSON);

	#ifdef _WIN32
		std::ofstream file(FilePath.string());
	#else
		std::ofstream file(FilePath.c_str());
	#endif

	if (file.is_open())
	{
		file << PersonalFileInfo_JSON.dump(4);
		file.close();
		Logger::Instance().Info().Log("PersonalFileInfo Serialization completed to {0}", FilePath.string());
	}
	else
	{
		Logger::Instance().Info().Log("Error: Failed to open the file for writing: {0}", FilePath.string());
	}
}

// 反序列化函数
void PersonalFileInfo::Deserialization(const std::filesystem::path& FilePath)
{
	nlohmann::json PersonalFileInfo_JSON;

	#ifdef _WIN32
		std::ifstream file(FilePath.string());
	#else
		std::ifstream file(FilePath.c_str());
	#endif

	if (!file.is_open())
	{
		Logger::Instance().Info().Log("Failed to open the file for reading: {0}", FilePath.string());
		return;
	}
	else
	{
		file >> PersonalFileInfo_JSON;
		file.close();
	}

	// 反序列化 JSON 数据
	if (PersonalFileInfo_JSON.is_object())
	{
		DeserializeInstances(PersonalFileInfo_JSON);
		Logger::Instance().Info().Log("PersonalFileInfo Deserialization completed from {0}", FilePath.string());
	}
}

// 创建新的文件实例
PersonalFileInfo::PersonalFileInstance PersonalFileInfo::CreateFileInstance(
	const std::string& Token,
	const std::vector<std::string>& EncryptionAlgorithms,
	const std::vector<std::string>& DecryptionAlgorithms
)
{
	PersonalFileInstance instance;

	instance.ID = this->Instances.empty() ? 0 : (this->Instances.back().ID + 1);
	instance.EncryptionAlgorithmNames = EncryptionAlgorithms;
	instance.DecryptionAlgorithmNames = DecryptionAlgorithms;

	return instance;
}

// 追加文件实例
void PersonalFileInfo::AppendFileInstance(const PersonalFileInstance& instance)
{
	this->Instances.push_back(instance);
}

// 删除文件实例
bool PersonalFileInfo::RemoveFileInstance(std::uint64_t ID)
{
	auto it = std::remove_if
	(
		Instances.begin(), Instances.end(),
		[ID](const PersonalFileInstance& instance)
		{
			return instance.ID == ID;
		}
	);

	if (it != Instances.end())
	{
		Instances.erase(it, Instances.end());
		return true;
	}

	return false;
}

// 删除所有文件实例
void PersonalFileInfo::RemoveAllFileInstances()
{
	this->Instances.clear();
	this->Instances.shrink_to_fit();
}

// 获取所有文件实例
PersonalFileInfo::PersonalFileInstance& PersonalFileInfo::GetFileInstanceByID(uint64_t ID)
{
	if(this->Instances.empty())
	{
		Logger::Instance().Error().Log("Error: PersonalFileInfo is empty.");
		my_cpp2020_assert(false, "File Instance ID not found.", std::source_location::current());
	}

	return this->Instances[ID];
}

std::vector<PersonalFileInfo::PersonalFileInstance>& PersonalFileInfo::GetFileInstances()
{
	return this->Instances;
}

//FIXME: 同样的参数生成的子密钥却不一致，原因未知。
inline std::deque<std::vector<std::uint8_t>> PersonalFileInfo::GenerateFileMultipleSubKeys( const PersonalFileInstance& Instance, const std::vector<uint8_t>& MasterKey )
{
	using namespace CommonSecurity::SHA;
	using namespace CommonSecurity::DataHashingWrapper;
	using namespace UtilTools;

	HashersAssistantParameters HAP_ObjectArgument;
	HAP_ObjectArgument.hash_mode = Hasher::WORKER_MODE::CHINA_SHANG_YONG_MI_MA3;
	HAP_ObjectArgument.whether_use_hash_extension_bit_mode = false;
	HAP_ObjectArgument.generate_hash_bit_size = 512;

	std::string MasterKey_Base64 = DataFormating::Base64Coder::Author1::encode( MasterKey );

	if ( Instance.EncryptionAlgorithmNames.size() <= 4 && Instance.DecryptionAlgorithmNames.size() <= 4 )
	{
		// Splitting MasterKey_Base64 into 4 strings
		std::vector<std::string> FourMasterKeyStrings;
		size_t					 PartLength = MasterKey_Base64.size() / 4;
		size_t					 CharacterOffset = 0;
		for ( int i = 0; i < 4; i++ )
		{
			// Add remainder to the last substring
			size_t CharacterOffsetEnd = PartLength;
			if ( i == 3 )
			{
				CharacterOffsetEnd += MasterKey_Base64.size() % 4;
			}
			FourMasterKeyStrings.push_back( MasterKey_Base64.substr( CharacterOffset, CharacterOffsetEnd ) );
			CharacterOffset += PartLength;
		}

		HashTokenForDataParameters HTDP_ObjectArgument {};
		HTDP_ObjectArgument.HashersAssistantParameters_Instance = HAP_ObjectArgument;

		// Generate key stream hash token using 4 parts of master key
		HTDP_ObjectArgument.OriginalPasswordStrings = FourMasterKeyStrings;

		HTDP_ObjectArgument.NeedHashByteTokenSize = ( 256 / std::numeric_limits<uint8_t>::digits ) * Instance.DecryptionAlgorithmNames.size();
		auto MultipleSubKeys = BuildingKeyStream<256>( HTDP_ObjectArgument );

		if ( !MultipleSubKeys.has_value() )
		{
			Logger::Instance().Error().Log("Failed to generate multiple subkeys.");
		}

		return MultipleSubKeys.value();
	}
	else
	{
		// NOTE: Special case requires special handling. 
		// This implementation ensures that all generated bytes are of equal length, but the exact number of bytes remains unspecified.

		// # NEED TEST #

		CommonSecurity::DRBG::HMAC::WorkerBasedHAMC DRBG_HMAC( HAP_ObjectArgument );

		std::deque<std::vector<std::uint8_t>> MultipleSubKeys;
		for ( uint32_t i = 0; i < Instance.DecryptionAlgorithmNames.size(); i++ )
		{
			MultipleSubKeys.push_back( std::vector<uint8_t>( 256 / std::numeric_limits<uint8_t>::digits, 0x00 ) );
		}

		DRBG_HMAC.instantiate_state( MasterKey_Base64 );

		for ( auto& Subkey : MultipleSubKeys )
		{
			DRBG_HMAC.generate_bytes( Subkey );
		}

		return MultipleSubKeys;
	}
}

bool PersonalFileInfo::EncryptFile( const std::string& Token, const PersonalFileInstance& Instance, const std::filesystem::path& SourceFilePath, const std::filesystem::path& EncryptedFilePath )
{
	using namespace CommonSecurity::SHA;
	using namespace UtilTools;

	// Check if the source file exists
	if ( !std::filesystem::is_regular_file( SourceFilePath ) )
	{
		Logger::Instance().Error().Log("Error: Source file does not exist: {0}", SourceFilePath.string());
		return false;
	}

	// Check if encryption and decryption algorithm names are set
	if ( Instance.EncryptionAlgorithmNames.empty() || Instance.DecryptionAlgorithmNames.empty() )
	{
		Logger::Instance().Error().Log("Error: Encryption algorithm is not set.\n""Error: Decryption algorithm is not set.");
		return false;
	}

	// Ensure that encryption and decryption algorithms are of the same size
	if ( Instance.EncryptionAlgorithmNames.size() != Instance.DecryptionAlgorithmNames.size() )
	{
		Logger::Instance().Warning().Log("Warning: Encryption algorithms and Decryption algorithms are not the same size.");
		return false;
	}

	// Read the content of the source file
	std::ifstream InputFile( SourceFilePath, std::ios::binary );
	if ( !InputFile.is_open() )
	{
		Logger::Instance().Error().Log("Failed to open source file for reading: {0}", SourceFilePath.string());
		return false;
	}

	std::vector<uint8_t> FileByteData( ( std::istreambuf_iterator<char>( InputFile ) ), std::istreambuf_iterator<char>() );
	InputFile.close();

	// Compute the hash of the source file
	Hasher::HasherTools MainHasher;
	std::optional<std::string>				 optionalSourceHash = MainHasher.GenerateHashed( Hasher::WORKER_MODE::SHA3_512, DataFormating::ASCII_Hexadecimal::byteArray2HexadecimalString( FileByteData ) );
	if ( !optionalSourceHash.has_value() )
	{
		Logger::Instance().Fatal().Log("Failed to compute source file hash.");
		Logger::Instance().StopAndWaitAll();
		std::terminate();
		return false;
	}
	std::string			 SourceHashHex = optionalSourceHash.value();
	std::vector<uint8_t> SourceHashBytes = DataFormating::ASCII_Hexadecimal::hexadecimalString2ByteArray( SourceHashHex );
	if ( SourceHashBytes.size() != 64 )	 // SHA-512 is 64 bytes
	{
		Logger::Instance().Fatal().Log("Invalid source hash size.");
		Logger::Instance().StopAndWaitAll();
		std::terminate();
		return false;
	}

	// Generate the master key
	std::vector<uint8_t> MasterKey = GenerateMasterBytesKeyFromToken( Token );

	// Generate the encryption subkeys
	std::deque<std::vector<std::uint8_t>> MultipleSubKeys = this->GenerateFileMultipleSubKeys( Instance, MasterKey );

	//0 ~ N
	uint32_t KeyIndex = 0;

	// Block cipher using stream processing counter mode
	// Perform multiple encryption
	for ( const auto& Algorithm : Instance.EncryptionAlgorithmNames )
	{
		auto& EncryptionKey = MultipleSubKeys[ KeyIndex % Instance.EncryptionAlgorithmNames.size() ];

		if ( Algorithm == CryptoCipherAlgorithmNames[ 0 ] )	 // AES
		{
			CommonSecurity::AES::DataWorker256 AES_128_256 {};
			AES_128_256.CTR_StreamModeBasedEncryptFunction( FileByteData, EncryptionKey, FileByteData );
		}
		else if ( Algorithm == CryptoCipherAlgorithmNames[ 1 ] )  // RC6
		{
			CommonSecurity::RC6::DataWorker128_256 RC6_128_256 {};
			RC6_128_256.CTR_StreamModeBasedDecryptFunction( FileByteData, EncryptionKey, FileByteData );
		}
		else if ( Algorithm == CryptoCipherAlgorithmNames[ 2 ] )  // SM4
		{
			CommonSecurity::ChinaShangYongMiMa4::DataWorker256 SM4_128_256 {};
			SM4_128_256.CTR_StreamModeBasedEncryptFunction( FileByteData, EncryptionKey, FileByteData );
		}
		else if ( Algorithm == CryptoCipherAlgorithmNames[ 3 ] )  // Twofish
		{
			CommonSecurity::Twofish::DataWorker256 Twofish_128_256 {};
			Twofish_128_256.CTR_StreamModeBasedDecryptFunction( FileByteData, EncryptionKey, FileByteData );
		}
		else if ( Algorithm == CryptoCipherAlgorithmNames[ 4 ] )  // Serpent
		{
			CommonSecurity::Serpent::DataWorker256 Serpent_128_256 {};
			Serpent_128_256.CTR_StreamModeBasedEncryptFunction( FileByteData, EncryptionKey, FileByteData );
		}
		else
		{
			Logger::Instance().Error().Log("Unsupported encryption algorithm: {0}", Algorithm);
			return false;
		}

		KeyIndex++;
	}

	// Compute the hash of the encrypted data
	std::optional<std::string> optionalEncryptedHash = MainHasher.GenerateHashed( Hasher::WORKER_MODE::SHA3_512, DataFormating::ASCII_Hexadecimal::byteArray2HexadecimalString( FileByteData ) );
	if ( !optionalEncryptedHash.has_value() )
	{
		Logger::Instance().Fatal().Log("Failed to compute encrypted data hash.");
		Logger::Instance().StopAndWaitAll();
		std::terminate();
		return false;
	}

	std::vector<uint8_t> EncryptedHashBytes = DataFormating::ASCII_Hexadecimal::hexadecimalString2ByteArray( optionalEncryptedHash.value() );
	if ( EncryptedHashBytes.size() != 64 )	// SHA-512 is 64 bytes
	{
		Logger::Instance().Fatal().Log("Invalid encrypted data hash size.");
		Logger::Instance().StopAndWaitAll();
		std::terminate();
		return false;
	}

	// Write the encrypted data to the output file
	std::ofstream OutputFile( EncryptedFilePath, std::ios::binary | std::ios::trunc );
	if ( !OutputFile.is_open() )
	{
		Logger::Instance().Error().Log("Failed to open encrypted file for writing: {0}", EncryptedFilePath.string());
		return false;
	}

	// Write source file hash
	OutputFile.write( reinterpret_cast<const char*>( SourceHashBytes.data() ), SourceHashBytes.size() );

	// Write encrypted data
	OutputFile.write( reinterpret_cast<const char*>( FileByteData.data() ), FileByteData.size() );

	// Write encrypted data hash
	OutputFile.write( reinterpret_cast<const char*>( EncryptedHashBytes.data() ), EncryptedHashBytes.size() );

	OutputFile.close();

	// Clear sensitive data from memory
	memory_set_no_optimize_function<0x00>( MasterKey.data(), MasterKey.size() * sizeof( uint8_t ) );
	for ( auto& Key : MultipleSubKeys )
	{
		memory_set_no_optimize_function<0x00>( Key.data(), Key.size() * sizeof( uint8_t ) );
	}

	Logger::Instance().Info().Log("File encrypted successfully: {0}", EncryptedFilePath.string());

	return true;
}

bool PersonalFileInfo::DecryptFile( const std::string& Token, const PersonalFileInstance& Instance, const std::filesystem::path& EncryptedFilePath, const std::filesystem::path& DecryptedFilePath )
{
	using namespace CommonSecurity::SHA;
	using namespace UtilTools;

	// Check if the encrypted file exists
	if ( !std::filesystem::is_regular_file( EncryptedFilePath ) )
	{
		Logger::Instance().Error().Log("Encrypted file does not exist: {0}", EncryptedFilePath.string());
		return false;
	}

	// Check if encryption and decryption algorithm names are set
	if ( Instance.EncryptionAlgorithmNames.empty() || Instance.DecryptionAlgorithmNames.empty() )
	{
		Logger::Instance().Error().Log("Error: Encryption algorithm is not set.\n""Error: Decryption algorithm is not set.");
		return false;
	}

	// Ensure that encryption and decryption algorithms are of the same size
	if ( Instance.EncryptionAlgorithmNames.size() != Instance.DecryptionAlgorithmNames.size() )
	{
		Logger::Instance().Warning().Log("Warning: Encryption algorithms and Decryption algorithms are not the same size.");
		return false;
	}

	std::ifstream InputFile(EncryptedFilePath, std::ios::binary);
	if (!InputFile.is_open())
	{
		Logger::Instance().Error().Log("Failed to open encrypted file for reading: {0}", EncryptedFilePath.string());
		return false;
	}

	// Get the total file size
	InputFile.seekg(0, std::ios::end);
	std::streampos FileByteSize = InputFile.tellg();

	if (FileByteSize < 128)  // File must at least contain two SHA-512 hashes (64 bytes each)
	{
		Logger::Instance().Error().Log("Encrypted file is too small to contain necessary hashes:  {0}", EncryptedFilePath.string());
		InputFile.close();
		return false;
	}

	// Create buffers for the three parts: header hash, file data, and tail hash
	std::vector<uint8_t> SourceHashBytes(64, 0x00);
	std::vector<uint8_t> FileByteData(static_cast<std::size_t>(FileByteSize) - 128, 0x00);
	std::vector<uint8_t> EncryptedHashBytes(64, 0x00);

	// Read the header hash (first 64 bytes)
	InputFile.seekg(0, std::ios::beg);
	InputFile.read(reinterpret_cast<char*>(SourceHashBytes.data()), 64);

	// Read the file data (from offset 64 to FileByteSize - 64)
	InputFile.seekg(64, std::ios::beg);
	InputFile.read(reinterpret_cast<char*>(FileByteData.data()), FileByteData.size());

	// Read the tail hash (last 64 bytes)
	InputFile.seekg(static_cast<std::streamoff>(FileByteSize) - 64, std::ios::beg);
	InputFile.read(reinterpret_cast<char*>(EncryptedHashBytes.data()), 64);

	InputFile.close();

	// Compute and verify the hash of the encrypted data
	Hasher::HasherTools MainHasher;
	std::optional<std::string>				 optionalComputedEncryptedHash = MainHasher.GenerateHashed( Hasher::WORKER_MODE::SHA3_512, DataFormating::ASCII_Hexadecimal::byteArray2HexadecimalString( FileByteData ) );
	if ( !optionalComputedEncryptedHash.has_value() )
	{
		Logger::Instance().Fatal().Log("Failed to compute encrypted data hash.");
		Logger::Instance().StopAndWaitAll();
		std::terminate();
		return false;
	}
	std::string			 computedEncryptedHashHex = optionalComputedEncryptedHash.value();
	std::vector<uint8_t> computedEncryptedHashBytes = DataFormating::ASCII_Hexadecimal::hexadecimalString2ByteArray( computedEncryptedHashHex );
	if ( computedEncryptedHashBytes.size() != 64 )
	{
		Logger::Instance().Fatal().Log("Invalid computed encrypted data hash size.");
		Logger::Instance().StopAndWaitAll();
		std::terminate();
		return false;
	}

	// Compare the encrypted data hash
	if ( computedEncryptedHashBytes != EncryptedHashBytes )
	{
		Logger::Instance().Error().Log("Encrypted data hash mismatch. The file may be corrupted or tampered with.");
		return false;
	}

	// Generate the master key
	std::vector<uint8_t> MasterKey = GenerateMasterBytesKeyFromToken( Token );

	// Generate the decryption subkeys
	std::deque<std::vector<std::uint8_t>> MultipleSubKeys = this->GenerateFileMultipleSubKeys( Instance, MasterKey );

	//N ~ 0
	uint32_t KeyIndex = Instance.DecryptionAlgorithmNames.size();

	// Block cipher using stream processing counter mode
	// Perform multiple decryption (reverse order)
	for (const auto& Algorithm : Instance.DecryptionAlgorithmNames )
	{
		auto& DecryptionKey = MultipleSubKeys[ (KeyIndex - 1) % Instance.DecryptionAlgorithmNames.size() ];

		if ( Algorithm == CryptoCipherAlgorithmNames[ 0 ] )	 // AES
		{
			CommonSecurity::AES::DataWorker256 AES_128_256 {};
			AES_128_256.CTR_StreamModeBasedEncryptFunction( FileByteData, DecryptionKey, FileByteData );
		}
		else if ( Algorithm == CryptoCipherAlgorithmNames[ 1 ] )  // RC6
		{
			CommonSecurity::RC6::DataWorker128_256 RC6_128_256 {};
			RC6_128_256.CTR_StreamModeBasedDecryptFunction( FileByteData, DecryptionKey, FileByteData );
		}
		else if ( Algorithm == CryptoCipherAlgorithmNames[ 2 ] )  // SM4
		{
			CommonSecurity::ChinaShangYongMiMa4::DataWorker256 SM4_128_256 {};
			SM4_128_256.CTR_StreamModeBasedEncryptFunction( FileByteData, DecryptionKey, FileByteData );
		}
		else if ( Algorithm == CryptoCipherAlgorithmNames[ 3 ] )  // Twofish
		{
			CommonSecurity::Twofish::DataWorker256 Twofish_128_256 {};
			Twofish_128_256.CTR_StreamModeBasedDecryptFunction( FileByteData, DecryptionKey, FileByteData );
		}
		else if ( Algorithm == CryptoCipherAlgorithmNames[ 4 ] )  // Serpent
		{
			CommonSecurity::Serpent::DataWorker256 Serpent_128_256 {};
			Serpent_128_256.CTR_StreamModeBasedEncryptFunction( FileByteData, DecryptionKey, FileByteData );
		}
		else
		{
			Logger::Instance().Error().Log("Unsupported decryption algorithm: {0}", Algorithm);
			return false;
		}

		KeyIndex--;
	}

	// Compute and verify the hash of the decrypted data
	std::optional<std::string> optionalDecryptedHash = MainHasher.GenerateHashed( Hasher::WORKER_MODE::SHA3_512, DataFormating::ASCII_Hexadecimal::byteArray2HexadecimalString( FileByteData ) );
	if ( !optionalDecryptedHash.has_value() )
	{
		Logger::Instance().Fatal().Log("Failed to compute decrypted data hash.");
		Logger::Instance().StopAndWaitAll();
		std::terminate();

		return false;
	}

	std::vector<uint8_t> DecryptedHashBytes = DataFormating::ASCII_Hexadecimal::hexadecimalString2ByteArray( optionalDecryptedHash.value() );
	if ( DecryptedHashBytes.size() != 64 )
	{
		Logger::Instance().Fatal().Log("Invalid decrypted data hash size.");
		Logger::Instance().StopAndWaitAll();
		std::terminate();

		return false;
	}

	// Compare the decrypted data hash
	if ( DecryptedHashBytes != SourceHashBytes )
	{
		Logger::Instance().Error().Log("Decrypted data hash mismatch. Decryption failed or data is corrupted.");

		return false;
	}

	// Write the decrypted data to the output file
	std::ofstream OutputFile( DecryptedFilePath, std::ios::binary | std::ios::trunc );
	if ( !OutputFile.is_open() )
	{
		Logger::Instance().Error().Log("Failed to open decrypted file for writing: {0}", DecryptedFilePath.string());

		return false;
	}

	std::copy(FileByteData.begin(), FileByteData.end(), std::ostreambuf_iterator<char>(OutputFile));
	OutputFile.close();

	// Clear sensitive data from memory
	memory_set_no_optimize_function<0x00>( MasterKey.data(), MasterKey.size() * sizeof( uint8_t ) );
	for ( auto& Key : MultipleSubKeys )
	{
		memory_set_no_optimize_function<0x00>( Key.data(), Key.size() * sizeof( uint8_t ) );
	}

	Logger::Instance().Info().Log("File decrypted successfully: {0}", DecryptedFilePath.string());

	return true;
}
