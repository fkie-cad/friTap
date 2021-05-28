# BUILD INSTRUCTIONS

## WolfSSL

 1. Clone https://github.com/wolfSSL/wolfssl into the "WolfSSL" directory
 2. Open "wolfssl64.sln" contained in the cloned wolfssl directory using Visual Studio
 3. Retarget included projects to the newest platform toolset and SDK version if you are asked to do so by Visual Studio
 4. Reconfigure "wolfssl" project configuration:
	1. Right click "wolfssl" in Solution Explorer -> Properties
	2. Open the "Configuration Manager..." on the top right corner
	3. Change "Configuration" of "wolfssl" to "DLL Debug"
 5. Build "wolfssl" (right click "wolfssl" in Solution Explorer -> "Build")
 6. Open "Windows_Clients.sln" using Visual Studio
 7. Build WolfSSL (right click "WolfSSL" in Solution Explorer -> "Build")
 8. Copy wolfssl.dll from "DLL Debug" (contained in previously cloned folder) into the "Debug" folder which is in the same folder as "Windows_Clients.sln"
 9. Run "WolfSSL.exe" to start the client
 
## OpenSSL
1. Install perl (recommendation/tested with: https://strawberryperl.com/)
2. Install NASM (recommendation/tested with: https://www.nasm.us/pub/nasm/releasebuilds/2.14.02/win32/)
3. Clone https://github.com/openssl/openssl.git into the "OpenSSL" directory
4. Open Developer Command Prompt for VS 20xx and navigate into the cloned repository folder "openssl"
	1. perl Configure
	2. nmake
	2. nmake test
5. Open "Windows_Clients.sln" using Visual Studio
6. Build OpenSSL (right click "OpenSSL" in Solution Explorer -> "Build")
7. Copy libcrypto-3.dll and libssl-3.dll from cloned "openssl" folder into the "Debug" folder which is in the same folder as "Windows_Clients.sln"
8. Run "OpenSSL.exe" to start the client