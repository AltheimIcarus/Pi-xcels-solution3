#include <iostream>
#include <string>

// encryption algorithm
#include <openssl/sha.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/buffer.h> // Needed for BIO_mem functions

// download file from URL
#include <curl/curl.h>

// JSON parsing
#include <nlohmann/json.hpp>

/** directive to suppress warning in console,
 * 1 = No warning,
 * 0 = Show warning
 */
#define SUPPRESS_WARNING 0

/** Compile cmdlet
 * 
 * g++ -o hasher hasher.cpp -lcurl -lssl -lcrypto -I/usr/include/nlohmann
 */

using json = nlohmann::json;

// Function to hash an input c string using SHA256
std::string hashSHA256(const char *input) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, input, strlen(input));
    SHA256_Final(hash, &sha256);

    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }

    return ss.str();
}

// Callback function to write fetched data to a string
size_t writeCallback(void *contents, size_t size, size_t nmemb, std::string *output) {
    size_t totalSize = size * nmemb;
    output->append((char*)contents, totalSize);
    return totalSize;
}

// Function to fetch public key in JSON from a URL
std::string downloadJWKS(const std::string& url) {
    CURL *curl = curl_easy_init();
    std::string jsonData;

    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &jsonData);

        CURLcode res = curl_easy_perform(curl);

        if (res != CURLE_OK) {
#if SUPPRESS_WARNING==0
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
#endif
            jsonData = "";
        }

        curl_easy_cleanup(curl);
    }

    if (jsonData.empty()) {
        return "";
    }

    return jsonData;
}

// Function to base64 decode a string and return as std::string
std::string base64_decode(const std::string& encoded_string) {
    // Initialize BIO objects for base64 URL-safe decoding
    BIO *bio, *b64, *bio_out;
    bio = BIO_new(BIO_s_mem());
    b64 = BIO_new(BIO_f_base64_url());
    bio_out = BIO_new(BIO_s_mem());

    // Chain bio and b64 for decoding
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); // Disable newline encoding

    // Write encoded string to BIO
    BIO_write(bio, encoded_string.c_str(), encoded_string.length());

    // Perform base64 URL-safe decoding
    BIO_flush(bio);
    BIO_read(bio_out, bio, BIO_pending(bio));

    // Read decoded data from BIO
    char* buffer;
    long length = BIO_get_mem_data(bio_out, &buffer);
    std::string decoded_string(buffer, length);

    // Clean up BIO objects
    BIO_free_all(bio_out);

    return decoded_string;
}

// Function to parse JWKS and extract RSA public key
RSA* jwksToRSAPublicKey(const std::string& jwks) {
    json jwksJson = json::parse(jwks);

    // Find the key with matching keyId
    for (const auto& key : jwksJson["keys"]) {
        if (key["kty"] == "RSA") {
            std::string n = key["n"];
            std::string e = key["e"];
            std::cout << "n: " << n << "\ne: " << e << std::endl;
            std::string n64 = base64_decode(n);
            std::string e64 = base64_decode(e);
            std::cout << "n64: " << n64 << "\ne64: " << e64 << std::endl;


            RSA* rsa = RSA_new();
            BIGNUM* bignumN = BN_new();
            BIGNUM* bignumE = BN_new();

            // Set RSA parameters
            BN_bin2bn((const unsigned char*)n64.c_str(), n64.length(), bignumN);
            BN_bin2bn((const unsigned char*)e64.c_str(), e64.length(), bignumE);
            RSA_set0_key(rsa, bignumN, bignumE, NULL);

            return rsa;
        }
    }

    // Assume the JWKS has an array of keys (typically "keys" array)
    auto keys = jwksJson["keys"];
    if (keys.empty()) {
#if SUPPRESS_WARNING==0
        std::cerr << "JWKS does not contain any keys." << std::endl;
#endif
        return nullptr;
    }

    return nullptr;
}

std::string encryptWithPublicKey(const std::string& data, RSA* rsa) {
    // Determine the RSA key size
    int keySize = RSA_size(rsa);
    std::cout << "RSA_len: " << keySize << std::endl;

    // Allocate memory for the encrypted data
    unsigned char* encrypted = (unsigned char*)malloc(keySize);

    // Perform encryption
    int encryptSize = RSA_public_encrypt(data.length(), reinterpret_cast<const unsigned char*>(data.c_str()),
                                         encrypted, rsa, RSA_PKCS1_PADDING);

    if (encryptSize == -1) {
#if SUPPRESS_WARNING==0
        std::cerr << "Encryption failed: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
#endif
        return "";
    }

    // Resize the encrypted string to the actual size
    std::string encryptedDataStr(reinterpret_cast<char*>(encrypted), encryptSize);
    free(encrypted);

    return encryptedDataStr;
}

// main body of native c++ code
int main() {
    std::string test = "abcdefg";
    const char *inputChars = test.c_str();

    // 2. Hash the input string
    std::string hashedStr = hashSHA256(inputChars);
    std::cout << "hash: " << hashedStr << std::endl;
    

    // 3. Download the public key using cURL
    std::string publicKeyJWKS = downloadJWKS("https://demo.api.piperks.com/.well-known/pi-xcels.json");
    if (publicKeyJWKS.empty())
        return 0;
    std::cout << "PK: " << publicKeyJWKS << std::endl;


    // 4. Encrypt the hash using OpenSSL - RSA
    RSA *rsaPublicKey = jwksToRSAPublicKey(publicKeyJWKS);
    std::string encryptedHash = encryptWithPublicKey(hashedStr, rsaPublicKey);

    // 5. Return the hash
    std::cout << "encrypted: " << encryptedHash << std::endl;

    // free memory
    RSA_free(rsaPublicKey);

    return 0;
}



