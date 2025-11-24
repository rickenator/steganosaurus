cmake_minimum_required(VERSION 3.10)
project(steganosaurus)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(include)
include_directories(src)

# Main TurtleFFT steganography tool
add_executable(turtlefft src/steganosaur.cpp)

# ChaCha20-Poly1305 AEAD library (for turtlefft-key)
add_library(chacha20poly1305 STATIC src/crypto/chacha20poly1305.cpp)
target_include_directories(chacha20poly1305 PUBLIC src/crypto)

# Key generation and management tool
add_executable(turtlefft-key tools/turtlefft-key.cpp)
target_link_libraries(turtlefft-key PRIVATE chacha20poly1305)