#pragma once

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <string>
#include <unordered_map>

class KeyManager
{
    std::unordered_map<std::string, EVP_PKEY*> ContactsInRAM;
    EVP_PKEY* UserPrivateKey;//Current user's decryption key
    std::string UserPublicKey;//Current user's encryption key
private:
    EVP_PKEY* GenerateRSAKeypair(int key_bits = 2048 /*Essentially size of the key*/);
    void SavePrivateKeyToFile(const EVP_PKEY* pkey, const std::string& filename);
    EVP_PKEY* AttemptRetrievePublicKeyFromFile(const std::string& filename);//can be null
    EVP_PKEY* AttemptRetrievePrivateKeyFromFile(const std::string& filename);//can be null
    EVP_PKEY* ConvertRawStringPublicKeyToPKEY(const std::string& pem_key_string);
    const std::string ConvertPublicPKEYToRawStringKey(const EVP_PKEY* pkey);
    void GenerateAndSaveKeypair(const std::string& UserName, int key_bits = 2048);
    void SavePublicKeyToFile(EVP_PKEY* pkey, const std::string& filename);
public:
    KeyManager() = delete;
    KeyManager(const std::string& login_username);
    
    EVP_PKEY* AttempLoadContactPKey(const std::string& username); //can be null
    void RegisterNewContact(const std::string& username, const std::string& public_key);
    std::vector<unsigned char> EncryptForContact(const std::string& username, const std::string& text_to_encrypt);
    std::string Decrypt(const std::vector<unsigned char>& encrypted_text);
    const std::string GetPublicKey();
};