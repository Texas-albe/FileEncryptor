# 多阶段构建：构建阶段编译"静态链接 libsodium"的 CLI 可执行文件，
# 运行阶段仅拷贝二进制，得到无外部依赖的最小镜像。
#
# CLI 项目独立构建示例（FileEncryptorCLI.exe → /usr/bin/FileEncryptorCLI）：
FROM ubuntu:22.04 AS build
RUN apt-get update && apt-get install -y --no-install-recommends \
        cmake g++ make libsodium-dev libyaml-cpp-dev pkg-config ca-certificates ninja-build \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN cmake --preset linux-release \
    && cmake --build --preset linux-release -j"$(nproc)"

# 运行镜像：libsodium + yaml-cpp 已静态打进二进制，无需任何 .so
FROM gcr.io/distroless/static-debian12
COPY --from=build /src/out/build/linux-release/bin/FileEncryptorCLI /usr/bin/FileEncryptorCLI
ENTRYPOINT ["/usr/bin/FileEncryptorCLI"]

# 构建并运行示例：
#   docker build -t file-encryptor-cli .
#   docker run --rm -v "$PWD:/data" file-encryptor-cli -e /data/file.txt -o /data
