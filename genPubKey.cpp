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

/** Compile cmdlet
 * 
 * g++ -o genPubKey genPubKey.cpp -lssl -lcrypto -I/usr/include/nlohmann
 */

using json = nlohmann::json;

std::string base64_encode(const unsigned char *input, int length) {
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO *mem = BIO_new(BIO_s_mem());
    BIO_push(b64, mem);
    BIO_write(b64, input, length);
    BIO_flush(b64);
    BUF_MEM *bptr;
    BIO_get_mem_ptr(b64, &bptr);
    std::string result(bptr->data, bptr->length - 1);  // Exclude newline
    BIO_free_all(b64);
    return result;
}

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
    std::string modulusBase64Url = base64_encode(modulusBin, modulusLen);
    jwks["n"] = modulusBase64Url;
    
    // Convert exponent to base64url format
    int exponentLen = BN_num_bytes(e);
    unsigned char *exponentBin = (unsigned char *)malloc(exponentLen);
    BN_bn2bin(e, exponentBin);
    std::string exponentBase64Url = base64_encode(exponentBin, exponentLen);
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
