cmake_minimum_required(VERSION 3.18)
project(android_elf_symbol_resolver C 
    DESCRIPTION "Android ELF Symbol Resolver - Parse and resolve symbols from ELF binaries with .gnu_debugdata support"
    VERSION 1.0.0)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

set(LIBLZMA_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../liblzma")
set(LIBLZMA_LIB "${LIBLZMA_DIR}/lib/liblzma.a")
set(LIBLZMA_INCLUDE "${LIBLZMA_DIR}/include")

if(NOT EXISTS "${LIBLZMA_LIB}")
    message(WARNING "liblzma library not found at ${LIBLZMA_LIB}")
    message(WARNING "Symbol lookup will work but .gnu_debugdata decompression will be disabled")
    set(HAVE_LZMA_AVAILABLE FALSE)
else()
    set(HAVE_LZMA_AVAILABLE TRUE)
endif()

add_library(android_elf_symbol_resolver STATIC
    symbol_lookup.c
)

target_include_directories(android_elf_symbol_resolver PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

if(HAVE_LZMA_AVAILABLE)
    target_include_directories(android_elf_symbol_resolver PUBLIC
        ${LIBLZMA_INCLUDE}
    )
    
    target_compile_definitions(android_elf_symbol_resolver PRIVATE
        HAVE_LZMA
    )
    
    target_link_libraries(android_elf_symbol_resolver PRIVATE
        ${LIBLZMA_LIB}
    )
endif()

target_link_libraries(android_elf_symbol_resolver PUBLIC
    dl
)

if(ANDROID)
    target_compile_definitions(android_elf_symbol_resolver PRIVATE
        ANDROID
    )
    
    find_library(log-lib log)
    if(log-lib)
        target_link_libraries(android_elf_symbol_resolver PRIVATE
            ${log-lib}
        )
    endif()
endif()

if(APPLE)
    target_link_libraries(android_elf_symbol_resolver PUBLIC
        c++
    )
elseif(UNIX AND NOT ANDROID)
    target_link_libraries(android_elf_symbol_resolver PUBLIC
        c++
    )
elseif(ANDROID)
    find_library(cxx-lib c++_shared)
    if(cxx-lib)
        target_link_libraries(android_elf_symbol_resolver PUBLIC
            ${cxx-lib}
        )
    else()
        find_library(cxx-static-lib c++_static)
        if(cxx-static-lib)
            target_link_libraries(android_elf_symbol_resolver PUBLIC
                ${cxx-static-lib}
            )
        endif()
    endif()
endif()

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_definitions(android_elf_symbol_resolver PRIVATE
        DEBUG=1
    )
endif()

install(TARGETS android_elf_symbol_resolver
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION bin
)

install(FILES symbol_lookup.h
    DESTINATION include
)

