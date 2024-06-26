/**
 * C++ codes to generate a public key in JWKS json without header.
 */

#include <iostream>

// For file operations
#include <fstream>

// encryption algorithm
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/rand.h>

// JSON parsing
#include <nlohmann/json.hpp>

// base64 encoding
#include <cppcodec/base64_default_url_unpadded.hpp>

/** Compile cmdlet
 * 
 * g++ -o genPubKey genPubKey.cpp -lssl -lcrypto -I/usr/include/cppcodec -I/usr/include/nlohmann
 */

using json = nlohmann::json;

/**
 * Generates a RSA public key in JWKS json.
 * @param rsa RSA handler of OpenSSL.
 * @return JWKS json
 */
json generateJWKS_RSAPublicKey(RSA *rsa) {
    // Create a JSON object for the RSA public key in JWKS format
    json jwks;
    jwks["kty"] = "RSA";
    
    // Extract RSA components: modulus and exponent
    const BIGNUM *n, *e;
    RSA_get0_key(rsa, &n, &e, NULL);
    
    // Convert modulus to base64url format
    int modulusLen = BN_num_bytes(n);
    unsigned char *modulusBin = (unsigned char *)malloc(modulusLen);
    BN_bn2bin(n, modulusBin);
    std::string modulusBase64Url = cppcodec::base64_url_unpadded::encode(modulusBin, modulusLen);
    jwks["n"] = modulusBase64Url;
    
    // Convert exponent to base64url format
    int exponentLen = BN_num_bytes(e);
    unsigned char *exponentBin = (unsigned char *)malloc(exponentLen);
    BN_bn2bin(e, exponentBin);
    std::string exponentBase64Url = cppcodec::base64_url_unpadded::encode(exponentBin, exponentLen);
    jwks["e"] = exponentBase64Url;
    
    // Cleanup
    free(modulusBin);
    free(exponentBin);
    
    return jwks;
}

int main() {
    // Generate RSA key pair
    RSA *rsa = RSA_new();
    BIGNUM *e = BN_new();
    BN_set_word(e, RSA_F4);  // RSA exponent
    RSA_generate_key_ex(rsa, 2048, e, NULL);
    BN_free(e);
    
    // Generate JWKS JSON format RSA public key
    json jwksRSAPublicKey = generateJWKS_RSAPublicKey(rsa);
    
    // Cleanup
    RSA_free(rsa);
    
    // Write JWKS JSON format RSA public key to a file
    std::ofstream outFile("jwks_rsa_public_key.json");
    outFile << std::setw(4) << jwksRSAPublicKey << std::endl;
    outFile.close();
    
    std::cout << "JWKS JSON format RSA public key saved to jwks_rsa_public_key.json" << std::endl;
    
    return 0;
}
