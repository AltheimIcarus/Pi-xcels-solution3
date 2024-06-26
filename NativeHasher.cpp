#include <jni.h>
#include "NativeHasher.h" // JNI generated header
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
#include <openssl/param_build.h>

// download file from URL
#include <curl/curl.h>

// base64 encoding
#include <cppcodec/base64_default_url_unpadded.hpp>

// JSON parsing
#include <nlohmann/json.hpp>

/** directive to suppress warning in console,
 * 1 = No warning,
 * 0 = Show warning
 */
#define SUPPRESS_WARNING 0
//const std::string jwksURL = "https://demo.api.piperks.com/.well-known/pi-xcels.json";
const std::string jwksURL = "https://raw.githubusercontent.com/AltheimIcarus/Pi-xcels-solution3/main/jwks_rsa_public_key.json";

/** Compile cmdlet
 * 
 * g++ -shared -fPIC -o libnativeHasher.so NativeHasher.cpp -I${JAVA_HOME}/include -I${JAVA_HOME}/include/linux -lcurl -lssl -lcrypto -lnlohmann_json
 * g++ -shared -fPIC -o libnativeHasher.so NativeHasher.cpp -I${JAVA_HOME}/include -I${JAVA_HOME}/include/linux -lcurl -lssl -lcrypto -I/usr/include/nlohmann -I/usr/include/cppcodec
 */

using json = nlohmann::json;

/**
 * Function to hash an input c string using SHA256
 * @param input Input text in c_str.
 * @return hashed std::string
 */
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

/**
 * Callback function to write fetched data to a string
 */
size_t writeCallback(void *contents, size_t size, size_t nmemb, std::string *output) {
    size_t totalSize = size * nmemb;
    output->append((char*)contents, totalSize);
    return totalSize;
}

/**
 * Function to fetch public key in JSON from a URL
 * @param url URL of the JWKS json file.
 * @return string of parsed JWKS json
 */
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

/**
 * Function to parse JWKS and extract RSA public key
 * @param jwks string of parsed JWKS json
 * @return EVP_PKEY* handler to OpenSSL EVP function
 */
EVP_PKEY* jwksToRSAPublicKey(const std::string& jwks) {
    json jwksJson = json::parse(jwks);

    // Find the key with matching keyId
    for (const auto& key : jwksJson["keys"]) {
        if (key["kty"] == "RSA") {
            std::string n = key["n"];
            std::string e = key["e"];
            //std::cout << "n: " << n << "\ne: " << e << std::endl;
            std::vector<unsigned char> nBin = cppcodec::base64_url_unpadded::decode(n);
            std::vector<unsigned char> eBin = cppcodec::base64_url_unpadded::decode(e);

            BIGNUM* bignumN = BN_new();
            BIGNUM* bignumE = BN_new();

            // Set RSA parameters
            BN_bin2bn(nBin.data(), n.size(), bignumN);
            BN_bin2bn(eBin.data(), e.size(), bignumE);

            // Build params to create PARAM array
            OSSL_PARAM_BLD* params_build = OSSL_PARAM_BLD_new();

            OSSL_PARAM_BLD_push_BN(params_build, "n", bignumN);
            OSSL_PARAM_BLD_push_BN(params_build, "e", bignumE);
            OSSL_PARAM_BLD_push_BN(params_build, "d", nullptr);
            
            // create parameters
            OSSL_PARAM* params = OSSL_PARAM_BLD_to_param(params_build);

            // free memory
            OSSL_PARAM_BLD_free(params_build);
            BN_free(bignumN);
            BN_free(bignumE);
            
            // create RSA key
            EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr);
            EVP_PKEY_fromdata_init(ctx);
            EVP_PKEY *rsa = nullptr;
            
            EVP_PKEY_fromdata(ctx, &rsa, EVP_PKEY_KEYPAIR, params);

            // free memory
            OSSL_PARAM_free(params);
            EVP_PKEY_CTX_free(ctx);

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

/**
 * Function to encrypt string with public key
 * @param data Plain text to encrypt
 * @param rsa RSA public key handler
 * @return encrypted std::string
 */
std::string encryptWithPublicKey(const std::string& data, EVP_PKEY* rsa) {
    // Determine the RSA key size
    int keySize = (EVP_PKEY_get_bits(rsa) + 7) / 8;
    //std::cout << "RSA_len: " << keySize << std::endl;

    // Allocate memory for the encrypted data
    unsigned char* encrypted = (unsigned char*)malloc(keySize);

    // initialize encryption
    EVP_PKEY_CTX* enc_ctx = EVP_PKEY_CTX_new(rsa, nullptr);
    EVP_PKEY_encrypt_init(enc_ctx);
    EVP_PKEY_CTX_set_rsa_padding(enc_ctx, RSA_NO_PADDING);

    // Perform encryption
    size_t encryptSize = keySize;
    int result = EVP_PKEY_encrypt(enc_ctx, encrypted, &encryptSize, reinterpret_cast<const unsigned char*>(data.c_str()),
                                         keySize);

    if (result != 1 || encryptSize != keySize) {
#if SUPPRESS_WARNING==0
        std::cerr << "Encryption failed: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
#endif
        return "";
    }

    // Resize the encrypted string to the actual size
    std::string encryptedDataStr(reinterpret_cast<char*>(encrypted), encryptSize);
    free(encrypted);

    // Free memory
    EVP_PKEY_CTX_free(enc_ctx);

    return encryptedDataStr;
}

// main body of native c++ code
extern "C" JNIEXPORT jstring JNICALL
Java_NativeHasher_encryptStringNative(
        JNIEnv* env,
        jobject /* this */,
        jstring input) {
    const char *inputChars = env->GetStringUTFChars(input, nullptr);

    // 2. Hash the input string
    std::string hashedStr = hashSHA256(inputChars);
    env->ReleaseStringUTFChars(input, inputChars);
    

    // 3. Download the public key using cURL
    std::string publicKeyJWKS = downloadJWKS(jwksURL);
    if (publicKeyJWKS.empty())
        return env->NewStringUTF("");


    // 4. Encrypt the hash using OpenSSL - RSA
    EVP_PKEY* rsaPublicKey = jwksToRSAPublicKey(publicKeyJWKS);
    std::string encryptedHash = encryptWithPublicKey(hashedStr, rsaPublicKey);

    // free memory
    EVP_PKEY_free(rsaPublicKey);

    // 5. Return the hash
    return env->NewStringUTF(encryptedHash.c_str());
}



