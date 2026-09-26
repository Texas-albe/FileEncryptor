@echo off
REM FileEncryptor GUI (WinUI3) 构建脚本
REM 用法: build.cmd [publish]
REM   不带参数: 构建 Release|x64
REM   publish: 发布自包含部署 + 构建 MSI

setlocal
cd /d "%~dp0"

set MSBUILD=E:\Microsoft Visual Studio\MSBuild\Current\Bin\MSBuild.exe

echo === 构建 WinUI3 GUI (Release|x64) ===
"%MSBUILD%" FileEncryptorGUI.WinUI3.csproj /p:Configuration=Release /p:Platform=x64 /t:Build /v:minimal
if errorlevel 1 (
    echo 构建失败
    exit /b 1
)

if /i "%1"=="publish" (
    echo.
    echo === 发布自包含部署 ===
    dotnet publish FileEncryptorGUI.WinUI3.csproj -c Release -r win-x64 -p:Platform=x64 --self-contained true -p:WindowsAppSDKSelfContained=true -o bin\Release\net8.0-windows10.0.19041.0\win-x64\publish
    if errorlevel 1 (
        echo 发布失败
        exit /b 1
    )
    echo.
    echo === 构建 MSI 安装包 ===
    dotnet build installer\FileEncryptorGUI.Installer.wixproj -c Release
    if errorlevel 1 (
        echo MSI 构建失败
        exit /b 1
    )
    echo.
    echo MSI 输出: installer\bin\x64\Release\FileEncryptorGUI-2.0.0-WinUI-Windows.msi
)

echo.
echo 完成。
endlocal
