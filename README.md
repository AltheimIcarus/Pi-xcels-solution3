
# Solution for Option 3

This java project contains a native C++ codes to hash and encrypt user's input with a URL to a public key.

## Installation

### Linux

To compile the project on linux, you must first, following dependencies are required to build the project:

```bash
  sudo apt install cmake
  sudo apt-get install libssl-dev
  sudo apt-get install libcurl4-openssl-dev
  sudo apt-get install nlohmann-json3-dev
  git clone https://github.com/microsoft/vcpkg
  ./vcpkg/bootstrap-vcpkg.sh
  ./vcpkg/vcpkg install cppcodec
```
    
## Usage

1. Setup the URL of which the JWKS json is located at the top of <code>NativeHasher.cpp</code>:

```c++
  /** directive to suppress warning in console,
   * 1 = No warning,
   * 0 = Show warning
   */
  #define SUPPRESS_WARNING 1
  const std::string jwksURL = "https://demo.api.piperks.com/.well-known/pi-xcels.json";

```

2. Replace the <<CURRENT_WORKING_DIR>> with the exact path to the file <code>libnativeHasher.so</code> in <code>NativeHasher.java</code>:

```java
public class NativeHasher {
    // load the native c++ library
    static {
        System.load("<CURRENT_WORKING_DIR>/libnativeHasher.so");
    }
```

3. Compile the java header in bash.

```bash
  javac NativeHasher.java
  javah -jni NativeHasher
```

4. Compile the C++ native codes with the following cmdlet:

```bash
  g++ -shared -fPIC -o libnativeHasher.so NativeHasher.cpp -I${JAVA_HOME}/include -I${JAVA_HOME}/include/linux -lcurl -lssl -lcrypto -I/usr/include/cppcodec -I/usr/include/nlohmann
```

If any error occurs when linking the cppcodec library, change the linker flag to:

```bash
  g++ -shared -fPIC -o libnativeHasher.so NativeHasher.cpp -I${JAVA_HOME}/include -I${JAVA_HOME}/include/linux -lcurl -lssl -lcrypto -lcppcodec -I/usr/include/nlohmann
```

5. Run the main java program in bash or compile the jar package:

```bash
  # Run the java file
  java NativeHasher
  # OR compile the jar package
  jar cmvf MANIFEST.MF NativeHasher.jar NativeHasher.class
  # then run with the command
  java -jar NativeHasher.jar
```
