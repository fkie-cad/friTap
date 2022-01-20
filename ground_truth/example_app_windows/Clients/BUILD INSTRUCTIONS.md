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
 8. Copy wolfssl.dll from "DLL Debug" (contained in previously cloned folder) next to the built "WolfSSL.exe" located in the "Debug" folder which is in the same folder as "Windows_Clients.sln"
 9. Run "WolfSSL.exe" to start the client
 
## OpenSSL
1. Install perl (recommendation/tested with: https://strawberryperl.com/)
2. Install NASM (recommendation/tested with: https://www.nasm.us/pub/nasm/releasebuilds/2.14.02/win32/)
3. Clone https://github.com/openssl/openssl.git into the "OpenSSL" directory
4. Open Developer Command Prompt for VS 201x and navigate into the cloned repository folder "openssl"
	1. perl Configure
	2. nmake
	2. nmake test
5. Open "Windows_Clients.sln" using Visual Studio
6. Build OpenSSL (right click "OpenSSL" in Solution Explorer -> "Build")
7. Copy libcrypto-3.dll and libssl-3.dll from cloned "openssl" folder next to the build "OpenSSL.exe" located in the "Debug" folder which is in the same folder as "Windows_Clients.sln"
8. Run "OpenSSL.exe" to start the client

## NSS (64 Bit only due to NSS' buggy build script)
1. Install ninja (https://github.com/ninja-build/ninja/releases) preferably to some folder as near to your drives root (eg. C:/nss/ninja/) - NSS' build tool tends to crash using more complex paths, avoid spaces in paths!
2. Clone gyp (https://gyp.gsrc.io/) preferably to some folder as near to your drives root (eg. C:/nss/gyp/) - NSS' build tool tends to crash using more complex paths, avoid spaces in paths!
3. Install mozilla-build (https://wiki.mozilla.org/MozillaBuild)
4. Download latest source code package containing nss and nspr (tested with: https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/NSS_3.64_release_notes)
5. Unpack both folders "nss" and "nspr" preferably to some folder as near to your drives root (eg. C:/nss/nss-source/) - NSS' build tool tends to crash using more complex paths, avoid spaces in paths!
6. Navigate into mozilla-build folder and open "start-shell.bat" as administrator
7. Add your ninja installation and gyap installation to the PATH variable in the linux shell (NOT WINDOWS) - e.g. export PATH=/c/nss/gyp:$PATH && export PATH=/c/nss/ninja:$PATH
8. In this new shell navigate to the folder containing the two new folders -> go into the one folder named "nss"
9. Run ./build.sh -v
10. Copy new "dist" folder into NSS/nss folder (Clients/NSS/nss)
11. Open "Windows_Clients.sln" using Visual Studio
12. Build NSS (right click "NSS" in Solution Explorer -> "Build")
13. Copy every .dll file from /NSS/nss/dist/Debug/lib next to the build "NSS.exe" located in the "x64/Debug" folder which was created in the same folder where "Windows_Clients.sln" is located
14. Run "NSS.exe" to start the client

## GnuTLS (Communication with local server)
Luckily Gitlab compiles GnuTLS sourcecode automatically for every support platform. We can just grab the compiled library and import it.
1. Go to https://gitlab.com/gnutls/gnutls/-/jobs and download the latest "mingw32/archive"
2. Copy the lib and bin folder into /GnuTLS/gnutls/
3. Open gnutls.h located in /GnuTLS/gnutls/lib/include modify it as follows:
	1. Change #include <gnutls/compat.h> into #include <compat.h>
	2. Add #if defined(_MSC_VER)
	   #include <BaseTsd.h>
       typedef SSIZE_T ssize_t;
       #endif
	   at the top of the file
4. Build GnuTLS (right click "GnuTLS" in Solution Explorer -> "Build")
5. Copy every .dll file from /GnuTLS/gnutls/bin next to the build "GnuTLS.exe" located in the "Debug" folder which was created in the same folder where "Windows_Clients.sln" is located
6. Run "GnuTLS.exe" to start the client