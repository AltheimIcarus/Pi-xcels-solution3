import java.util.Scanner;                   // read input from user
import java.nio.charset.StandardCharsets;   // utf-8 encoding

/* Compile cmdlet
 * javac NativeHasher.java
 * javah -jni NativeHasher
 * java NativeHasher
 */
public class NativeHasher {
    // load the native c++ library
    static {
        System.load("/home/roan/Desktop/solution3/libnativeHasher.so");
    }

    // method to invoke native c++ function
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
            System.out.println("Enter a text: " + encryptedStr);
            
            scanner.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
