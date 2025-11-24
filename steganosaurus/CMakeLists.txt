cmake_minimum_required(VERSION 3.10)
project(steganosaurus)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(include)
include_directories(src)

add_executable(turtlefft 
    src/steganosaur.cpp
    src/crypto/chacha20poly1305.cpp
)