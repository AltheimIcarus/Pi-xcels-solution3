#include <jni.h>
#include "NativeHasher.h" // JNI generated header
#include <string>

// encryption algorithm
#include <openssl/sha.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>

// download file from URL
#include <curl/curl.h>

// JSON parsing
#include <nlohmann/json.hpp>

/** directive to suppress warning in console,
 * 1 = No warning,
 * 0 = Show warning
 */
#define SUPPRESS_WARNING 1

/** Compile cmdlet
 * 
 * g++ -shared -fPIC -o libnativeHasher.so NativeHasher.cpp -I${JAVA_HOME}/include -I${JAVA_HOME}/include/linux -lcurl -lssl -lcrypto -lnlohmann_json
 * g++ -shared -fPIC -o libnativeHasher.so NativeHasher.cpp -I${JAVA_HOME}/include -I${JAVA_HOME}/include/linux -lcurl -lssl -lcrypto -I/usr/include/nlohmann
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
std::string downloadPublicKey(const std::string& url) {
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

    try {
        // Parse the JSON data
        json parsedJson = json::parse(jsonData);

        // Access the "n" value
        std::string nValue = parsedJson["keys"][0]["n"];

        return "-----BEGIN PUBLIC KEY-----\n" + nValue + "\n-----END PUBLIC KEY-----\n";
    } catch (const json::exception& e) {
#if SUPPRESS_WARNING==0
        std::cerr << "Error parsing JSON: " << e.what() << std::endl;
#endif
        return "";
    }

    return jsonData;
}

std::string encryptWithPublicKey(const std::string& data, const std::string& publicKey) {
    RSA* rsa = nullptr;
    BIO* keyBio = nullptr;
    EVP_PKEY* evpKey = nullptr;
    int keySize = 0;

    // Load public key from string
    keyBio = BIO_new_mem_buf(publicKey.c_str(), -1);
    if (keyBio == nullptr) {
#if SUPPRESS_WARNING==0
        std::cerr << "Failed to create key BIO" << std::endl;
#endif
        return "";
    }

    rsa = PEM_read_bio_RSA_PUBKEY(keyBio, &rsa, nullptr, nullptr);
    if (rsa == nullptr) {
#if SUPPRESS_WARNING==0
        std::cerr << "Failed to load RSA public key" << std::endl;
#endif
        BIO_free(keyBio);
        return "";
    }

    // Determine the RSA key size
    keySize = RSA_size(rsa);

    // Allocate memory for the encrypted data
    std::string encrypted(keySize, '\0');

    // Perform encryption
    int encryptSize = RSA_public_encrypt(data.length(), reinterpret_cast<const unsigned char*>(data.c_str()),
                                         reinterpret_cast<unsigned char*>(const_cast<char*>(encrypted.data())), rsa, RSA_PKCS1_PADDING);

    if (encryptSize == -1) {
#if SUPPRESS_WARNING==0
        std::cerr << "Encryption failed: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
#endif
        RSA_free(rsa);
        BIO_free(keyBio);
        return "";
    }

    RSA_free(rsa);
    BIO_free(keyBio);

    // Resize the encrypted string to the actual size
    encrypted.resize(encryptSize);

    return encrypted;
}

// main body of native c++ code
extern "C" JNIEXPORT jstring JNICALL
Java_com_pixcels_solution_MainActivity_encryptStringNative(
        JNIEnv* env,
        jobject /* this */,
        jstring input) {
    const char *inputChars = env->GetStringUTFChars(input, nullptr);

    // 2. Hash the input string
    std::string hashedStr = hashSHA256(inputChars);
    env->ReleaseStringUTFChars(input, inputChars);
    

    // 3. Download the public key using cURL
    std::string publicKey = downloadPublicKey("https://demo.api.piperks.com/.well-known/pi-xcels.json");
    if (publicKey.empty())
        return env->NewStringUTF("");


    // 4. Encrypt the hash using OpenSSL - RSA
    std::string encryptedHash = encryptWithPublicKey(hashedStr, publicKey);

    // 5. Return the hash
    return env->NewStringUTF(encryptedHash.c_str());
}



