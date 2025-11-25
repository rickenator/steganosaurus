cmake_minimum_required(VERSION 3.10)
project(steganosaurus)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(include)
include_directories(src)

# Main TurtleFFT executable
add_executable(turtlefft src/steganosaur.cpp)

# ChaCha20-Poly1305 AEAD library
add_library(chacha20poly1305 STATIC
    src/crypto/chacha20poly1305.cpp
)
target_include_directories(chacha20poly1305 PUBLIC src/crypto)

# TurtleFFT key management tool
add_executable(turtlefft-key
    tools/turtlefft-key.cpp
    src/crypto/chacha20poly1305.cpp
)
target_include_directories(turtlefft-key PRIVATE src)
