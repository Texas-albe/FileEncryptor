@echo off
setlocal
:: The directory of this script is the expanded absolute path of the "$qt_prefix/bin" directory.
set script_dir_path=%~dp0

:: Try to use original cmake, otherwise to make it relocatable, use any cmake found in PATH.
set cmake_path=C:/hostedtoolcache/windows/Python/3.12.10/x64/Lib/site-packages/cmake/data/bin/cmake.exe
if not exist "%cmake_path%" set cmake_path=cmake

set CMAKE_TOOLCHAIN_FILE=%script_dir_path%\../lib/cmake/Qt6\qt.toolchain.cmake
"%cmake_path%" -G"Ninja" -DQT_USE_ORIGINAL_COMPILER=ON %*
