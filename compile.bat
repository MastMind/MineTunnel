@ECHO OFF

set BUILD_DIR=build
REM set CXXFLAGS=-I. -Wall -Werror -c -s -static -D_WIN32_WINNT=0x0601 -g
REM set LDFLAGS=-L. -lsetupapi -lole32 -luuid -lwsock32 -lws2_32 -s -static -g
set CXXFLAGS=-I. -Wall -Werror -c -D_WIN32_WINNT=0x0601 -DWINVER=0x0601 -DNTDDI_VERSION=0x06010000 -O1 -static -s -Wl,--heap,4294967296 -Wno-unknown-pragmas
set LDFLAGS=-L. -lsetupapi -lole32 -luuid -lwsock32 -lws2_32 -liphlpapi -lfwpuclnt -lrpcrt4 -O1 -static -s -Wl,--heap,4294967296
set PROGNAME=minetunnel
rd /S /Q %BUILD_DIR%
mkdir %BUILD_DIR%

for /R %%f in (*.c) do (
	gcc %CXXFLAGS% %%f -o %BUILD_DIR%/%%~nf.o
	if NOT ERRORLEVEL 1 (set compiled="success")
)

if DEFINED compiled (
	gcc -o %BUILD_DIR%/%PROGNAME%.exe %BUILD_DIR%/*.o %LDFLAGS%
	if NOT ERRORLEVEL 1 (@echo "Compilation success") else (@echo "Linking failed!")
) else (@echo "Compilation failed!")