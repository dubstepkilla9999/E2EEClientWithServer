#include "KeyManager.h"
#include <iostream>

EVP_PKEY* KeyManager::GenerateRSAKeypair(int key_bits)
{
	std::cout << "Generating RSA key of " << key_bits << " modulus size with EVP_RSA_gen()..." << std::endl;
	EVP_PKEY* PKey = EVP_RSA_gen(key_bits);

	if (!PKey)
	{
		throw std::runtime_error("Failed generating RSA keys..");
	}
	std::cout << "RSA key generated." << std::endl;
    return PKey;
}

void KeyManager::SavePrivateKeyToFile(const EVP_PKEY* pkey, const std::string& filename)
{
    FILE* FilePtr;
    if (fopen_s(&FilePtr, filename.c_str(), "wb") != 0)
    {
        throw std::runtime_error("Can't open or create file:" + filename);
    }
    if (!FilePtr)
    {
        throw std::runtime_error("Can't open or create file:" + filename);
    }

    if (PEM_write_PrivateKey(FilePtr, pkey, NULL, NULL, 0, NULL, NULL) != 1)
    {
        fclose(FilePtr);
        throw std::runtime_error("Failed writing key into file: " + filename);
    }
    fclose(FilePtr);
    std::cout << "Created private key: " << filename << std::endl;
}

void KeyManager::SavePublicKeyToFile(EVP_PKEY* pkey, const std::string& filename)
{
    FILE* FilePtr;
    if (fopen_s(&FilePtr, filename.c_str(), "wb") != 0)
    {
        throw std::runtime_error("Can't open file:" + filename);
    }
    if (!FilePtr)
    {
        throw std::runtime_error("Can't open or create file:" + filename);
    }

    if (PEM_write_PUBKEY(FilePtr, pkey) != 1)
    {
        fclose(FilePtr);
        throw std::runtime_error("Failed writing key into file: " + filename);
    }
    fclose(FilePtr);
    std::cout << "Created public key: " << filename << std::endl;
}

KeyManager::KeyManager(const std::string& login_username)
{
    if (const auto PrivPKey = AttemptRetrievePrivateKeyFromFile(login_username + "_private.pem"))
    {
        if (const auto PubPKey = AttemptRetrievePublicKeyFromFile(login_username + "_public.pem"))
        {
            UserPrivateKey = PrivPKey;
            UserPublicKey = ConvertPublicPKEYToRawStringKey(PubPKey);
            std::cout << "Found username's keys, logging in" << std::endl;
            return;
        }
    }
    std::cout << "Couldn't find username's keys, registering..." << std::endl;
    GenerateAndSaveKeypair(login_username);
    std::cout << "Registration complete" << std::endl;
}

void KeyManager::GenerateAndSaveKeypair(const std::string& user_name, int key_bits)
{
	EVP_PKEY* PKey = GenerateRSAKeypair(key_bits);
    try
    {
        SavePrivateKeyToFile(PKey, user_name + "_private.pem");
 
        SavePublicKeyToFile(PKey, user_name + "_public.pem");

        std::cout << "Keys for " << user_name << " were created and saved!" << std::endl;

        UserPrivateKey = PKey;
        UserPublicKey = ConvertPublicPKEYToRawStringKey(PKey);
    }
    catch (...)
    {
        EVP_PKEY_free(PKey);
        throw;
    }
}
EVP_PKEY* KeyManager::AttemptRetrievePublicKeyFromFile(const std::string& filename)
{
    FILE* FilePtr;
    if (fopen_s(&FilePtr, filename.c_str(), "rb") != 0)
    {
        return nullptr;
    }
    if (FilePtr)
    {
        EVP_PKEY* RetrievedKey = PEM_read_PUBKEY(FilePtr, NULL, NULL, NULL);
        fclose(FilePtr);
        if (RetrievedKey)
        {
            return RetrievedKey;
        }
    }
    return nullptr;
}
EVP_PKEY* KeyManager::AttemptRetrievePrivateKeyFromFile(const std::string& filename)
{
    FILE* FilePtr;
    if (fopen_s(&FilePtr, filename.c_str(), "rb") != 0)
    {
        return nullptr;
    }
    if (FilePtr)
    {
        EVP_PKEY* RetrievedKey = PEM_read_PrivateKey(FilePtr, NULL, NULL, NULL);
        fclose(FilePtr);
        if (RetrievedKey)
        {
            return RetrievedKey;
        }
    }
    return nullptr;
}
EVP_PKEY* KeyManager::AttempLoadContactPKey(const std::string& username)
{
    if (ContactsInRAM.find(username) != ContactsInRAM.end())
    {
        return ContactsInRAM[username];
    }
    //Not found in RAM, trying to find and load a corresponding file
    std::string Filename = username + "_public.pem";
    if (EVP_PKEY* RetrievedKey = AttemptRetrievePublicKeyFromFile(Filename))
    {
        ContactsInRAM[username] = RetrievedKey;
        return RetrievedKey;
    }
    return nullptr; //public key has never been received from this username
}
EVP_PKEY* KeyManager::ConvertRawStringPublicKeyToPKEY(const std::string& pem_key_string)
{
    //BIO = "Basic Input/Output"
    BIO* lBIO = BIO_new_mem_buf(pem_key_string.c_str(), pem_key_string.length());
    if (!lBIO)
    {
        std::cerr << "Error creating memory BIO." << std::endl;
        return nullptr;
    }

    EVP_PKEY* PKey = nullptr;
    PKey = PEM_read_bio_PUBKEY(lBIO, &PKey, nullptr, nullptr);
    if (!PKey)
    {
        std::cerr << "Error reading public key from PEM string." << std::endl;
        BIO_free(lBIO);
        return nullptr;
    }

    BIO_free(lBIO);
    return PKey;
}

const std::string KeyManager::ConvertPublicPKEYToRawStringKey(const EVP_PKEY* pkey)
{
    //does not support rsa, change to 
    BIO* lBIO = BIO_new(BIO_s_mem());
    if (!lBIO)
    {
        throw std::runtime_error("Error creating BIO");
    }
    
    // Writing PEM key into memory
    if (PEM_write_bio_PUBKEY(lBIO, const_cast<EVP_PKEY*>(pkey)) != 1)
    {
        BIO_free(lBIO);
        throw std::runtime_error("Error writing public key to BIO");
    }
    
    // Retrieving data from BIO
    char* Data = nullptr;
    long Length = BIO_get_mem_data(lBIO, &Data);
    
    if (Length <= 0 || !Data) {
        BIO_free(lBIO);
        throw std::runtime_error("Error getting data from BIO");
    }
    
    std::string Result(Data, Length);
    BIO_free(lBIO);
    
    return Result;
}

void KeyManager::RegisterNewContact(const std::string& username, const std::string& public_key)
{
    EVP_PKEY* NewPublicKey = ConvertRawStringPublicKeyToPKEY(public_key);
    ContactsInRAM[username] = NewPublicKey;
    SavePublicKeyToFile(NewPublicKey, username + "_public.pem");
}

std::vector<unsigned char> KeyManager::EncryptForContact(const std::string& username, const std::string& text_to_encrypt)
{
    if (EVP_PKEY* ContactPKey = AttempLoadContactPKey(username))
    {
        EVP_PKEY_CTX* Context = EVP_PKEY_CTX_new(ContactPKey, NULL);
        if (!Context)
        {
            throw std::runtime_error("Error creating context");
        }

        try
        {
            if (EVP_PKEY_encrypt_init(Context) <= 0)
            {
                throw std::runtime_error("Error initializing encrypt");
            }

            size_t EncryptedTextLength;
            //getting size (buffer is NULL)
            if (EVP_PKEY_encrypt(Context, NULL, &EncryptedTextLength, (const unsigned char*)text_to_encrypt.c_str(),
                text_to_encrypt.size()) <= 0)
            {
                throw std::runtime_error("Error getting size of the cypher");
            }
            //real encryption
            std::vector<unsigned char> EncryptedText(EncryptedTextLength);
            if (EVP_PKEY_encrypt(Context, EncryptedText.data(), &EncryptedTextLength,
                (const unsigned char*)text_to_encrypt.c_str(), text_to_encrypt.size()) <= 0)
            {
                throw std::runtime_error("Encryption error");
            }
            if (EncryptedTextLength != EncryptedText.size())
            {
                EncryptedText.resize(EncryptedTextLength);
            }
            std::cout << "Message encrypted for " << username
                << " (" << EncryptedText.size() << " bytes)" << std::endl;
            return EncryptedText;
        }
        catch(...)
        {
            EVP_PKEY_CTX_free(Context);
            throw;
        }
    }
    throw std::logic_error("Encrypting for unregistered contact!");
}

std::string KeyManager::Decrypt(const std::vector<unsigned char>& encrypted_text)
{
    EVP_PKEY_CTX* Context = EVP_PKEY_CTX_new(UserPrivateKey, NULL);
    std::vector<unsigned char> DecryptedText;
    if (!Context)
    {
        throw std::runtime_error("Error creating context.");
    }
    try
    {
        if (EVP_PKEY_decrypt_init(Context) <= 0)
        {
            throw std::runtime_error("Error initializing decrypt");
        }

        //Getting length of decrypted text
        size_t DecryptedTextLength;
        if (EVP_PKEY_decrypt(Context, NULL, &DecryptedTextLength, encrypted_text.data(), encrypted_text.size()) <= 0)
        {
            throw std::runtime_error("Error getting decrypted text size");
        }

        //Decrypting
        DecryptedText.resize(DecryptedTextLength);
        if (EVP_PKEY_decrypt(Context, DecryptedText.data(), &DecryptedTextLength, encrypted_text.data(), encrypted_text.size()) <= 0)
        {
            throw std::runtime_error("Decryption error");
        }
        if (DecryptedText.size() != DecryptedTextLength)
        {
            DecryptedText.resize(DecryptedTextLength);
        }

        std::cout << "Message decrypted: " << DecryptedText.size() << " bytes." << std::endl;

    }
    catch (...)
    {
        EVP_PKEY_CTX_free(Context);
        throw;
    }
    EVP_PKEY_CTX_free(Context);
    return std::string(DecryptedText.begin(), DecryptedText.end());
}

const std::string KeyManager::GetPublicKey()
{
    return UserPublicKey;
}
