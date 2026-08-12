# FileEncryptor

一个轻量、快速、跨平台的文件加密工具，基于 **libsodium** 实现，支持 **AES-256-GCM** 和 **XChaCha20-Poly1305** 两种认证加密模式。

## 特性

- 🔐 **强加密**：使用 libsodium 的 AEAD（关联数据认证加密）算法，确保数据机密性、完整性和真实性。
- ⚡ **高性能**：流式分块处理（1 MiB/块），内存占用极小，支持 TB 级大文件。
- 📁 **批量处理**：递归加密/解密整个目录，保留子目录结构。
- 📊 **进度显示**：实时显示处理进度、速度和剩余时间（ETA），支持单文件和批量综合进度。
- 🔑 **Argon2id 密钥派生**：使用 Argon2id（迭代 3 次，内存 64 MiB），抗 GPU/ASIC 破解。
- 🔄 **密码确认**：加密时要求输入两次密码，防止输错；解密仅需输入一次。
- 🗑️ **源文件删除**：可选 `-de` 参数，加密成功后自动删除原始文件。
- 🚫 **反调试保护**：内置简单反调试检测，增加逆向难度（可绕过，仅用于防范普通攻击者）。
- 📂 **灵活输出**：指定输出目录（自动创建），默认与源文件同目录。
- 🧹 **中断自愈**：意外中断后残留半成品文件与进度标记，下次运行会自动检测并重新处理。

## 安装与编译

### 方式一：直接使用（Windows）

```bash
# 将 FileEncryptor.exe 放入任意目录（建议加入 PATH）
FileEncryptor.exe -e secret.txt
```

### 方式二：从源码编译（Windows Visual Studio）

1. 安装 libsodium 开发包（含 `include` 与 `lib`）。
2. 打开 `FileEncryptor.vcxproj`，确认项目属性中的 libsodium 路径正确。
3. 静态链接 `libsodium.lib`，并定义预处理器宏 `SODIUM_STATIC`。
4. 以 **Release x64** 配置编译。

### 方式三：从源码编译（Linux / macOS）

```bash
# 安装依赖（以 Ubuntu 为例）
sudo apt install libsodium-dev

# 编译
g++ -std=c++17 -O2 -s -static -I/usr/include -L/usr/lib -lsodium main.cpp FileEncryptor.cpp -o fileencryptor
```

## 使用方法

### 示例

```text
FileEncryptor.exe -e/-d <FileName> [-o <Path>] [-de] [-m aes|xchacha20] [-y] [-j Num]
FileEncryptor.exe -be/-bd <Path> [-o <Path>] [-de] [-m aes|xchacha20] [-y] [-j Num]
```

### 参数说明

| 参数 | 作用 | 备注 |
|---|---|---|
| `-e` / `-d` | 单文件加密 / 解密 | 仅接受一个输入路径 |
| `-be` / `-bd` | 批量加密 / 解密 | 通过 `-i` 指定输入，可多次使用 |
| `-o <dir>` | 输出目录 | 默认输出到源文件所在目录；**单模式要求目录已存在**，批量模式自动创建 |
| `-de` | 加密成功后删除源文件 | 仅加密模式有效 |
| `-m <mode>` | 加密算法 | `aes`（默认）或 `xchacha20`；解密时自动从文件头读取，忽略此参数 |
| `-i <path>` | 批量输入路径 | 在批量模式（-be 或 -bd）下，您可以通过 -i 指定一个或多个输入目录或文件，也可以省略 -i，直接将路径作为位置参数传递（两者等价）。对于单文件模式（-e 或 -d），不推荐使用 -i，而是直接将文件路径作为位置参数传入 |
| `-j <num>` | 指定并行处理的线程数 | 如果未指定或设置为 0，程序会自动使用 CPU 核心数（std::thread::hardware_concurrency()）。该参数在批量模式（-be/-bd）下有效，单文件模式会忽略此选项 |

## 示例

### 单文件加密
```bash
fileencryptor -e document.pdf
```
- 将 document.pdf 加密为 ./document.pdf.ptd。

### 单文件解密
```bash
fileencryptor -d encrypted/document.pdf.ptd -o ./decrypted/
```

### 批量加密整个目录（递归）
```bash
fileencryptor -be -i /home/user/data/ -o /home/user/backup/
```
- 加密 data/ 下所有文件，在 backup/ 中保持相同目录结构，文件名为原文件名加 .ptd 后缀。

### 批量解密
```bash
fileencryptor -bd -i /home/user/backup/ -o /home/user/restored/
```
- 解密 backup/ 下所有 .ptd 文件，去除.ptd后缀后保存在 restored/ 中。

### 加密后删除源文件
```bash
fileencryptor -e secret.txt -de
```

### 指定加密算法
```bash
fileencryptor -e file.dat -m xchacha20
```
- 默认 aes（AES-256-GCM），备选 xchacha20（更安全，且无硬件加速依赖）。

## 工作流程说明
### 加密流程：

- 提示输入密码两次（确认）。  
- 随机生成 16 字节盐和 12/24 字节 IV（nonce）。  
- 使用 Argon2id 从密码和盐派生出 32 字节密钥。  
- 将文件分块（每块 1 MiB），每块使用独立的 nonce（基础 IV 与块索引异或），用 AEAD 加密并附加 16 字节认证标签。  
- 文件头存储魔数、版本、模式、盐、IV 长度、IV、块大小、总块数和原始文件大小。  
- 写入进度文件（.progress）用于断点续传（正常完成后删除）。

### 解密流程：

- 读取文件头，验证魔数和版本。  
- 提示输入密码（一次）。  
- 用相同的盐和密码派生出密钥。  
- 逐块解密并验证标签，若任一标签不匹配则立即报错并中止。  
- 输出原始文件，删除进度文件。

### 批量模式：

- 递归遍历输入目录，收集所有文件，计算总大小，显示综合进度条。解密时收集错误文件列表，最后一次性输出。

## 注意事项

### 退出码

| 退出码 | 含义 |
|---|---|
| 0 | 全部成功 |
| 1 | 参数错误 / 密码不符 / 加解密失败 / 批量处理存在失败项 |

### 密码强度：

- 建议使用至少 12 个字符，包含大小写字母、数字和特殊符号。  
- 输出目录：若指定目录不存在，程序会自动创建（包括多级目录）。  
- 进度文件：.progress 文件用于检测未完成的操作，若程序意外退出，下次运行将自动清理半成品文件并重新处理。

## 许可证

本程序是自由软件，依据 **GNU GPL v3 许可证** 进行许可。
