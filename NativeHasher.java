import java.util.Scanner;                   // read input from user
import java.nio.charset.StandardCharsets;   // utf-8 encoding

/* Compile cmdlet
 * javac NativeHasher.java
 * javah -jni NativeHasher
 * java NativeHasher
 */

/** Main container of the solution 3.
 * It does the following:
 * (1) get input text from user.
 * (2) Hash the input string.
 * (3) Download the public key using cURL.
 * (4) Encrypt the hash using OpenSSL - RSA.
 * (5) Return the hash.
 * 
 * @author ChiQin Cheng
 * @version 1.0
 * @since 1.0
 */
public class NativeHasher {
    // load the native c++ library
    static {
        System.load("/home/roan/Desktop/solution3/libnativeHasher.so");
    }

    /**
     * Method to invoke native c++ function
     * @param input Text to be hashed and encrypt
     * @return encrypted string
     */
    public native String encryptStringNative(String input);

    public static void main(String[] args) {
        try {
            NativeHasher hasher = new NativeHasher();
            
            Scanner scanner = new Scanner(System.in);
            System.out.print("Enter a text: ");

            // 1. get input text from user
            // 2-4. hash and encrypt the input string
            // enforce UTF-8 encoding in byte-to-string
            // pass encoded string to native c++ function to be encrypted
            String encryptedStr = hasher.encryptStringNative(
                new String(scanner.nextLine().getBytes(StandardCharsets.UTF_8), StandardCharsets.UTF_8)
            );

            // 5. return the ecrypted hash
            System.out.println("Encrypted text: ");
            System.out.println(encryptedStr);
            
            scanner.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
