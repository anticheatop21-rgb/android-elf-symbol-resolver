#ifndef SYMBOL_LOOKUP_H
#define SYMBOL_LOOKUP_H

#include <stdint.h>
#include <stddef.h>
#include <errno.h>

#define SYMBOL_LOOKUP_SUCCESS 0
#define SYMBOL_LOOKUP_ERROR_INVALID_ARG -1
#define SYMBOL_LOOKUP_ERROR_NOT_FOUND -2
#define SYMBOL_LOOKUP_ERROR_MEMORY -3
#define SYMBOL_LOOKUP_ERROR_IO -4
#define SYMBOL_LOOKUP_ERROR_FORMAT -5
#define SYMBOL_LOOKUP_ERROR_DECOMPRESS -6

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

SymbolTable* symbol_table_init(void);

void symbol_table_free(SymbolTable* table);

SymbolTable* symbol_table_load_from_elf(const char* elf_path);

const char* symbol_lookup_by_address(SymbolTable* table, uintptr_t lib_base, uintptr_t addr);

uintptr_t symbol_lookup_by_name(SymbolTable* table, uintptr_t lib_base, const char* name);

uintptr_t get_library_base_address(const char* lib_name);

char* symbol_demangle(const char* mangled_name);

const char* symbol_lookup_get_error_string(void);

#endif

