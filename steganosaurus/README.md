# Steganosaurus Project

## Overview
The Steganosaurus project implements a steganography algorithm using 2D FFT phase quantization. It allows embedding and extracting data from images while maintaining the visual integrity of the original image.

## Project Structure
```
steganosaurus
├── CMakeLists.txt        # Build configuration file
├── README.md             # Project documentation
├── .gitignore            # Git ignore file
├── include               # Header files
│   ├── stb_image.h      # Image loading functions
│   └── stb_image_write.h # Image writing functions
└── src                   # Source files
    └── turtle_fft_stego.cpp # Main implementation of the algorithm
```

## Requirements
- CMake (version 3.10 or higher)
- A C++17 compatible compiler

## Building the Project
1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd steganosaurus
   ```

2. Create a build directory:
   ```bash
   mkdir build
   cd build
   ```

3. Run CMake to configure the project:
   ```bash
   cmake ..
   ```

4. Build the project:
   ```bash
   make
   ```

## Usage
To embed data into an image:
```bash
./turtlefft embed --in input.png --out output.png --secret "Your secret message" --pass "YourPassword"
```

To extract data from an image:
```bash
./turtlefft extract --in output.png --pass "YourPassword"
```

## License
This project is licensed under some kinda License. See the LICENSE file for details.
