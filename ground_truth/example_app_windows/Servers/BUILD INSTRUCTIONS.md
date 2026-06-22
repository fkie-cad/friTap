## Example Server
1. Install perl (recommendation/tested with: https://strawberryperl.com/)
2. Install NASM (recommendation/tested with: https://www.nasm.us/pub/nasm/releasebuilds/2.14.02/win32/)
3. Clone https://github.com/openssl/openssl.git into the "Windows_Server" directory
4. Open Developer Command Prompt for VS 20xx and navigate into the cloned repository folder "openssl"
	1. perl Configure
	2. nmake
	2. nmake test
5. Open "Windows_Servers.sln" using Visual Studio
6. Build Windows_Server (right click "Windows_Server" in Solution Explorer -> "Build")
7. Copy libcrypto-3.dll and libssl-3.dll from cloned "openssl" folder next to the build "Windows_Server.exe" located in the "Debug" folder which is in the same folder as "Windows_Clients.sln"
8. Copy probided "mycert.pem" from folder "Windows_Server" right next to the "Windows_Server.exe"
9. Run "Windows_Server.exe" to start the server. It listens on port 443 by default