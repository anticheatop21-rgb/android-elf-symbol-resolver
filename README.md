# Android ELF Symbol Resolver

**Android ELF Symbol Resolver** | **ELF Parser** | **.gnu_debugdata Parser** | **Android Binary Analysis** | **ELF Symbol Lookup** | **Android Reverse Engineering** | **AOSP ELF Parser**

[![Android](https://img.shields.io/badge/Platform-Android-green.svg)](https://www.android.com/)
[![C](https://img.shields.io/badge/Language-C-blue.svg)](https://en.wikipedia.org/wiki/C_(programming_language))
[![ELF](https://img.shields.io/badge/Binary%20Format-ELF-orange.svg)](https://en.wikipedia.org/wiki/Executable_and_Linkable_Format)
[![CMake](https://img.shields.io/badge/Build-CMake-blue.svg)](https://cmake.org/)

A robust, high-performance C library for parsing and resolving symbols in ELF binaries on Android. Supports `.gnu_debugdata` section decompression using XZ/LZMA, C++ symbol demangling, and comprehensive symbol table parsing for reverse engineering, debugging, and binary analysis tasks.

**Perfect for:** Android reverse engineering, binary analysis, debugging, symbol resolution, ELF parsing, `.gnu_debugdata` extraction, Android native library analysis, and security research.

## 🎯 Use Cases

- **Android Reverse Engineering**: Extract and resolve symbols from stripped Android native libraries
- **Binary Analysis**: Parse ELF symbol tables and debug information from Android binaries
- **Debugging Tools**: Build custom debugging tools that need symbol information
- **Security Research**: Analyze Android malware and security vulnerabilities in native code
- **Performance Profiling**: Map addresses to function names for profiling Android applications
- **Hooking & Patching**: Resolve function addresses for runtime hooking and code patching
- **Educational**: Learn about ELF format, symbol tables, and `.gnu_debugdata` structure
- **Android NDK Development**: Debug and analyze native libraries during development

## 📖 Inspiration

This project was inspired by **Android 15** and the **Android Open Source Project (AOSP)**. The AOSP published a relevant component about the ELF parser, which can be found at:

🔗 **AOSP ELF Parser Source**: https://android.googlesource.com/platform/system/extras/+/refs/heads/main/simpleperf/read_elf.cpp

The most important part is the `.gnu_debugdata` segment parsing, which helps tools like `gdb` scan symbols from specific ELF files. The key implementation from AOSP's `ParseSymbols` function demonstrates the approach:

```cpp
ElfStatus ParseSymbols(const ParseSymbolCallback& callback) override {
    auto machine = GetELFHeader(elf_).e_machine;
    bool is_arm = (machine == llvm::ELF::EM_ARM || machine == llvm::ELF::EM_AARCH64);
    AddSymbolForPltSection(elf_obj_, callback);
    
    // Some applications deliberately ship elf files with broken section tables.
    // So check the existence of .symtab section and .dynsym section before reading symbols.
    bool has_symtab;
    bool has_dynsym;
    CheckSymbolSections(elf_obj_, &has_symtab, &has_dynsym);
    
    if (has_symtab && elf_obj_->symbol_begin() != elf_obj_->symbol_end()) {
        ReadSymbolTable(elf_obj_->symbol_begin(), elf_obj_->symbol_end(), callback, is_arm,
                        elf_obj_->section_end());
        return ElfStatus::NO_ERROR;
    } else if (has_dynsym && elf_obj_->dynamic_symbol_begin()->getRawDataRefImpl() !=
                             llvm::object::DataRefImpl()) {
        ReadSymbolTable(elf_obj_->dynamic_symbol_begin(), elf_obj_->dynamic_symbol_end(), callback,
                        is_arm, elf_obj_->section_end());
    }
    
    std::string debugdata;
    ElfStatus result = ReadSection(".gnu_debugdata", &debugdata);
    if (result == ElfStatus::SECTION_NOT_FOUND) {
        return ElfStatus::NO_SYMBOL_TABLE;
    } else if (result == ElfStatus::NO_ERROR) {
        std::string decompressed_data;
        if (XzDecompress(debugdata, &decompressed_data)) {
            auto debugdata_elf =
                ElfFile::Open(decompressed_data.data(), decompressed_data.size(), &result);
            if (debugdata_elf) {
                return debugdata_elf->ParseSymbols(callback);
            }
        }
    }
    return result;
}
```

This library implements similar functionality in pure C, providing a lightweight, embeddable solution for Android applications that need to parse ELF symbol tables and resolve symbols from `.gnu_debugdata` sections.

## Features

- **Dual Symbol Lookup Strategy**: First attempts `dlsym` for fast runtime symbol resolution, then falls back to parsing `.gnu_debugdata` for comprehensive symbol tables
- **LZMA Decompression**: Decompresses `.gnu_debugdata` sections using liblzma
- **C++ Demangling**: Demangles C++ mangled symbol names to human-readable form
- **Error Handling**: Comprehensive error system with `errno` integration
- **Library Base Detection**: Uses `dl_iterate_phdr` for reliable library base address detection
- **Android Logging**: Integrated Android log system for debugging

## Dependencies

### Required

- **liblzma**: XZ/LZMA compression library
  - Static library: `liblzma/lib/liblzma.a`
  - Headers: `liblzma/include/`
  - Build liblzma for your target architecture (ARM64, ARM, x86, x86_64)

### System Libraries

- `libdl` (for `dlopen`, `dlsym`, `dladdr`, `dl_iterate_phdr`)
- `libc++` (for `__cxa_demangle`)

## 📦 Installation & Building

### Building with CMake

#### Basic CMakeLists.txt

```cmake
cmake_minimum_required(VERSION 3.18)
project(android_elf_symbol_resolver C 
    DESCRIPTION "Android ELF Symbol Resolver - Parse and resolve symbols from ELF binaries"
    VERSION 1.0.0)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

set(LIBLZMA_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../liblzma")
set(LIBLZMA_LIB "${LIBLZMA_DIR}/lib/liblzma.a")
set(LIBLZMA_INCLUDE "${LIBLZMA_DIR}/include")

add_library(android_elf_symbol_resolver STATIC
    symbol_lookup.c
)

target_include_directories(android_elf_symbol_resolver PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${LIBLZMA_INCLUDE}
)

target_compile_definitions(android_elf_symbol_resolver PRIVATE
    HAVE_LZMA
)

target_link_libraries(android_elf_symbol_resolver PUBLIC
    dl
    c++
)

target_link_libraries(android_elf_symbol_resolver PRIVATE
    ${LIBLZMA_LIB}
)
```

### Android NDK Integration

For Android NDK builds, add to your `CMakeLists.txt`:

```cmake
if(ANDROID)
    target_compile_definitions(android_elf_symbol_resolver PRIVATE
        ANDROID
    )
    find_library(log-lib log)
    target_link_libraries(android_elf_symbol_resolver PRIVATE
        ${log-lib}
    )
endif()
```

## Usage

### Basic Example

```c
#include "symbol_lookup.h"
#include <stdio.h>
#include <string.h>

void example_symbol_lookup(void) {
    const char* lib_name = "libart.so";
    const char* lib_path = "/apex/com.android.art/lib64/libart.so";
    
    SymbolTable* symbols = symbol_table_load_from_elf(lib_path);
    if (!symbols) {
        printf("Error: %s (errno: %d - %s)\n", 
               symbol_lookup_get_error_string(), errno, strerror(errno));
        return;
    }
    
    printf("Loaded %zu symbols\n", symbols->count);
    
    uintptr_t lib_base = get_library_base_address(lib_name);
    if (lib_base == 0) {
        printf("Failed to get library base address\n");
        symbol_table_free(symbols);
        return;
    }
    
    const char* symbol_name = "artDeoptimizeFromCompiledCode";
    uintptr_t addr = symbol_lookup_by_name(symbols, lib_base, symbol_name);
    
    if (addr != 0) {
        printf("Symbol '%s' found at: 0x%llx\n", symbol_name, (unsigned long long)addr);
        
        const char* found_name = symbol_lookup_by_address(symbols, lib_base, addr);
        printf("Verified: 0x%llx -> '%s'\n", (unsigned long long)addr, found_name);
    } else {
        printf("Symbol '%s' not found\n", symbol_name);
    }
    
    symbol_table_free(symbols);
}
```

### Using dlsym First (Automatic)

The library automatically tries `dlsym` first, then falls back to the symbol table:

```c
SymbolTable* symbols = symbol_table_load_from_elf(lib_path);
uintptr_t lib_base = get_library_base_address("libart.so");

uintptr_t addr = symbol_lookup_by_name(symbols, lib_base, "art::Thread::Current");
if (addr != 0) {
    printf("Found at: 0x%llx\n", (unsigned long long)addr);
}
```

### C++ Symbol Demangling

```c
const char* mangled = "_ZN3art6Thread7CurrentEv";
char* demangled = symbol_demangle(mangled);

if (demangled) {
    printf("Mangled: %s\n", mangled);
    printf("Demangled: %s\n", demangled);
    free(demangled);
} else {
    printf("Demangling failed: %s\n", symbol_lookup_get_error_string());
}
```

### Error Handling

```c
SymbolTable* table = symbol_table_load_from_elf(path);
if (!table) {
    int error_code = errno;
    const char* error_msg = symbol_lookup_get_error_string();
    printf("Error %d: %s\n", error_code, error_msg);
    return;
}
```

## API Reference

### Data Structures

```c
typedef struct {
    uint64_t addr;
    uint64_t size;
    char* name;
} Symbol;

typedef struct {
    Symbol* syms;
    size_t count;
    size_t capacity;
} SymbolTable;
```

### Functions

#### `SymbolTable* symbol_table_init(void)`
Initializes a new empty symbol table.

#### `void symbol_table_free(SymbolTable* table)`
Frees a symbol table and all its resources.

#### `SymbolTable* symbol_table_load_from_elf(const char* elf_path)`
Loads symbols from an ELF file's `.gnu_debugdata` section.
- Returns: `SymbolTable*` on success, `NULL` on failure
- Sets `errno` on failure

#### `uintptr_t symbol_lookup_by_name(SymbolTable* table, uintptr_t lib_base, const char* name)`
Looks up a symbol by name. Tries `dlsym` first, then falls back to the symbol table.
- Returns: Address of symbol, or `0` if not found
- Sets `errno` on failure

#### `const char* symbol_lookup_by_address(SymbolTable* table, uintptr_t lib_base, uintptr_t addr)`
Looks up a symbol by address.
- Returns: Symbol name, or `"UNKNOWN"` if not found
- Sets `errno` on failure

#### `uintptr_t get_library_base_address(const char* lib_name)`
Gets the base address of a loaded library.
- Returns: Base address, or `0` if not found
- Sets `errno` on failure

#### `char* symbol_demangle(const char* mangled_name)`
Demangles a C++ mangled symbol name.
- Returns: Demangled name (caller must `free()`), or `NULL` on failure
- Sets `errno` on failure

#### `const char* symbol_lookup_get_error_string(void)`
Gets the last error message.
- Returns: Error message string

## Error Codes

- `SYMBOL_LOOKUP_SUCCESS` (0): Success
- `SYMBOL_LOOKUP_ERROR_INVALID_ARG` (-1): Invalid argument (`errno = EINVAL`)
- `SYMBOL_LOOKUP_ERROR_NOT_FOUND` (-2): Not found (`errno = ENOENT`)
- `SYMBOL_LOOKUP_ERROR_MEMORY` (-3): Memory allocation failed (`errno = ENOMEM`)
- `SYMBOL_LOOKUP_ERROR_IO` (-4): I/O error (`errno = EIO`)
- `SYMBOL_LOOKUP_ERROR_FORMAT` (-5): Invalid format (`errno = EILSEQ`)
- `SYMBOL_LOOKUP_ERROR_DECOMPRESS` (-6): Decompression failed (`errno = EIO`)

## Building liblzma

If you need to build liblzma for Android:

```bash
git clone https://github.com/tukaani-project/xz.git
cd xz
./autogen.sh
./configure --host=aarch64-linux-android --prefix=$(pwd)/install
make
make install
```

Then copy the static library and headers to your project's `liblzma/` directory.
