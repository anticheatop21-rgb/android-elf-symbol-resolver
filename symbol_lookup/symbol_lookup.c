#include "symbol_lookup.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <dlfcn.h>
#include <link.h>
#include <elf.h>
#include <errno.h>
#include <android/log.h>

#ifdef __cplusplus
#include <cxxabi.h>
#else
extern char* __cxa_demangle(const char* mangled_name, char* output_buffer, size_t* length, int* status);
#endif

#ifdef HAVE_LZMA
#include <lzma.h>
#endif

#define TAG "SymbolLookup"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

#define MAX_DECOMPRESS_SIZE (50 * 1024 * 1024)
#define SYMBOL_TABLE_INITIAL_CAPACITY 1024
#define UNKNOWN_SYMBOL_NAME "UNKNOWN"
#define SECTION_NAME_DEBUGDATA ".gnu_debugdata"
#define SECTION_NAME_SYMTAB ".symtab"
#define SECTION_NAME_STRTAB ".strtab"

static int last_error_code = SYMBOL_LOOKUP_SUCCESS;
static const char* last_error_message = NULL;

static void set_error(int error_code, const char* message) {
    last_error_code = error_code;
    last_error_message = message;
    
    switch (error_code) {
        case SYMBOL_LOOKUP_ERROR_INVALID_ARG:
            errno = EINVAL;
            break;
        case SYMBOL_LOOKUP_ERROR_NOT_FOUND:
            errno = ENOENT;
            break;
        case SYMBOL_LOOKUP_ERROR_MEMORY:
            errno = ENOMEM;
            break;
        case SYMBOL_LOOKUP_ERROR_IO:
            errno = EIO;
            break;
        case SYMBOL_LOOKUP_ERROR_FORMAT:
            errno = EILSEQ;
            break;
        case SYMBOL_LOOKUP_ERROR_DECOMPRESS:
            errno = EIO;
            break;
        default:
            errno = EINVAL;
            break;
    }
    if (message) {
        LOGE("Error %d: %s (errno: %d - %s)", error_code, message, errno, strerror(errno));
    }
}

const char* symbol_lookup_get_error_string(void) {
    if (last_error_code == SYMBOL_LOOKUP_SUCCESS) {
        return "Success";
    }
    if (last_error_message) {
        return last_error_message;
    }
    switch (last_error_code) {
        case SYMBOL_LOOKUP_ERROR_INVALID_ARG:
            return "Invalid argument";
        case SYMBOL_LOOKUP_ERROR_NOT_FOUND:
            return "Not found";
        case SYMBOL_LOOKUP_ERROR_MEMORY:
            return "Memory allocation failed";
        case SYMBOL_LOOKUP_ERROR_IO:
            return "I/O error";
        case SYMBOL_LOOKUP_ERROR_FORMAT:
            return "Invalid format";
        case SYMBOL_LOOKUP_ERROR_DECOMPRESS:
            return "Decompression failed";
        default:
            return "Unknown error";
    }
}

static uint8_t* load_gnu_debugdata(const char* path, size_t* out_size);
static uint8_t* decompress_xz(uint8_t* input, size_t input_size, size_t* out_size);
static int parse_symbols_from_elf(uint8_t* elf_data, size_t elf_size, SymbolTable* table);
static int validate_elf_header(const Elf64_Ehdr* ehdr);

SymbolTable* symbol_table_init(void) {
    errno = 0;
    last_error_code = SYMBOL_LOOKUP_SUCCESS;
    last_error_message = NULL;
    
    SymbolTable* table = calloc(1, sizeof(SymbolTable));
    if (!table) {
        set_error(SYMBOL_LOOKUP_ERROR_MEMORY, "Failed to allocate symbol table");
        return NULL;
    }
    
    table->capacity = SYMBOL_TABLE_INITIAL_CAPACITY;
    table->syms = malloc(sizeof(Symbol) * table->capacity);
    if (!table->syms) {
        set_error(SYMBOL_LOOKUP_ERROR_MEMORY, "Failed to allocate symbol array");
        free(table);
        return NULL;
    }
    
    table->count = 0;
    return table;
}

void symbol_table_free(SymbolTable* table) {
    if (!table) {
        return;
    }
    
    if (table->syms) {
        for (size_t i = 0; i < table->count; i++) {
            free(table->syms[i].name);
        }
        free(table->syms);
    }
    
    free(table);
}

static int symbol_table_add(SymbolTable* table, uint64_t addr, uint64_t size, const char* name) {
    if (!table || !name) {
        set_error(SYMBOL_LOOKUP_ERROR_INVALID_ARG, "Invalid arguments to symbol_table_add");
        return -1;
    }
    
    if (table->count >= table->capacity) {
        size_t new_capacity = table->capacity * 2;
        Symbol* new_syms = realloc(table->syms, sizeof(Symbol) * new_capacity);
        if (!new_syms) {
            set_error(SYMBOL_LOOKUP_ERROR_MEMORY, "Failed to reallocate symbol array");
            return -1;
        }
        table->syms = new_syms;
        table->capacity = new_capacity;
    }
    
    table->syms[table->count].addr = addr;
    table->syms[table->count].size = size;
    table->syms[table->count].name = strdup(name);
    
    if (!table->syms[table->count].name) {
        set_error(SYMBOL_LOOKUP_ERROR_MEMORY, "Failed to duplicate symbol name");
        return -1;
    }
    
    table->count++;
    return 0;
}

static int validate_elf_header(const Elf64_Ehdr* ehdr) {
    if (!ehdr) {
        return 0;
    }
    
    if (ehdr->e_ident[EI_MAG0] != ELFMAG0 ||
        ehdr->e_ident[EI_MAG1] != ELFMAG1 ||
        ehdr->e_ident[EI_MAG2] != ELFMAG2 ||
        ehdr->e_ident[EI_MAG3] != ELFMAG3) {
        return 0;
    }
    
    if (ehdr->e_ident[EI_CLASS] != ELFCLASS64) {
        return 0;
    }
    
    if (ehdr->e_shnum == 0 || ehdr->e_shnum > 65535) {
        return 0;
    }
    
    return 1;
}

static uint8_t* load_gnu_debugdata(const char* path, size_t* out_size) {
    errno = 0;
    if (!path || !out_size) {
        set_error(SYMBOL_LOOKUP_ERROR_INVALID_ARG, "Invalid arguments to load_gnu_debugdata");
        return NULL;
    }
    
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        set_error(SYMBOL_LOOKUP_ERROR_IO, "Failed to open ELF file");
        LOGE("Failed to open %s: %s", path, strerror(errno));
        return NULL;
    }
    
    Elf64_Ehdr ehdr;
    ssize_t bytes_read = pread(fd, &ehdr, sizeof(ehdr), 0);
    if (bytes_read != sizeof(ehdr)) {
        set_error(SYMBOL_LOOKUP_ERROR_IO, "Failed to read ELF header");
        LOGE("Failed to read ELF header from %s", path);
        close(fd);
        return NULL;
    }
    
    if (!validate_elf_header(&ehdr)) {
        set_error(SYMBOL_LOOKUP_ERROR_FORMAT, "Invalid ELF header");
        LOGE("Invalid ELF header in %s", path);
        close(fd);
        return NULL;
    }
    
    Elf64_Shdr* shdrs = malloc(sizeof(Elf64_Shdr) * ehdr.e_shnum);
    if (!shdrs) {
        set_error(SYMBOL_LOOKUP_ERROR_MEMORY, "Failed to allocate section headers");
        LOGE("Failed to allocate memory for section headers (%zu bytes)", 
             sizeof(Elf64_Shdr) * ehdr.e_shnum);
        close(fd);
        return NULL;
    }
    
    bytes_read = pread(fd, shdrs, sizeof(Elf64_Shdr) * ehdr.e_shnum, ehdr.e_shoff);
    if (bytes_read != (ssize_t)(sizeof(Elf64_Shdr) * ehdr.e_shnum)) {
        set_error(SYMBOL_LOOKUP_ERROR_IO, "Failed to read section headers");
        LOGE("Failed to read section headers from %s (expected %zu, got %zd)", 
             path, sizeof(Elf64_Shdr) * ehdr.e_shnum, bytes_read);
        free(shdrs);
        close(fd);
        return NULL;
    }
    
    if (ehdr.e_shstrndx >= ehdr.e_shnum) {
        set_error(SYMBOL_LOOKUP_ERROR_FORMAT, "Invalid section header string table index");
        LOGE("Invalid section header string table index %d (max: %d) in %s", 
             ehdr.e_shstrndx, ehdr.e_shnum, path);
        free(shdrs);
        close(fd);
        return NULL;
    }
    
    Elf64_Shdr* sh_str = &shdrs[ehdr.e_shstrndx];
    char* shstrtab = malloc(sh_str->sh_size);
    if (!shstrtab) {
        set_error(SYMBOL_LOOKUP_ERROR_MEMORY, "Failed to allocate section header string table");
        LOGE("Failed to allocate memory for section header string table (%zu bytes)", 
             sh_str->sh_size);
        free(shdrs);
        close(fd);
        return NULL;
    }
    
    bytes_read = pread(fd, shstrtab, sh_str->sh_size, sh_str->sh_offset);
    if (bytes_read != (ssize_t)sh_str->sh_size) {
        set_error(SYMBOL_LOOKUP_ERROR_IO, "Failed to read section header string table");
        LOGE("Failed to read section header string table from %s (expected %zu, got %zd)", 
             path, sh_str->sh_size, bytes_read);
        free(shstrtab);
        free(shdrs);
        close(fd);
        return NULL;
    }
    
    uint8_t* result = NULL;
    for (int i = 0; i < ehdr.e_shnum; i++) {
        const char* name = shstrtab + shdrs[i].sh_name;
        if (strcmp(name, SECTION_NAME_DEBUGDATA) == 0) {
            LOGD("Found %s section at offset %llu, size %llu", 
                 SECTION_NAME_DEBUGDATA, 
                 (unsigned long long)shdrs[i].sh_offset,
                 (unsigned long long)shdrs[i].sh_size);
            
            uint8_t* buf = malloc(shdrs[i].sh_size);
            if (!buf) {
                set_error(SYMBOL_LOOKUP_ERROR_MEMORY, "Failed to allocate debug data buffer");
                LOGE("Failed to allocate memory for debug data (%llu bytes)", 
                     (unsigned long long)shdrs[i].sh_size);
                break;
            }
            
            bytes_read = pread(fd, buf, shdrs[i].sh_size, shdrs[i].sh_offset);
            if (bytes_read != (ssize_t)shdrs[i].sh_size) {
                set_error(SYMBOL_LOOKUP_ERROR_IO, "Failed to read debug data");
                LOGE("Failed to read debug data from %s (expected %llu, got %zd)", 
                     path, (unsigned long long)shdrs[i].sh_size, bytes_read);
                free(buf);
                break;
            }
            
            *out_size = shdrs[i].sh_size;
            result = buf;
            LOGI("Successfully loaded %s section (%zu bytes)", SECTION_NAME_DEBUGDATA, *out_size);
            break;
        }
    }
    
    free(shstrtab);
    free(shdrs);
    close(fd);
    
    if (!result) {
        set_error(SYMBOL_LOOKUP_ERROR_NOT_FOUND, ".gnu_debugdata section not found");
        LOGW("Section %s not found in %s", SECTION_NAME_DEBUGDATA, path);
    }
    
    return result;
}

static uint8_t* decompress_xz(uint8_t* input, size_t input_size, size_t* out_size) {
    errno = 0;
    if (!input || input_size == 0 || !out_size) {
        set_error(SYMBOL_LOOKUP_ERROR_INVALID_ARG, "Invalid arguments to decompress_xz");
        return NULL;
    }
    
#ifdef HAVE_LZMA
    LOGD("Starting XZ decompression (input size: %zu bytes)", input_size);
    
    lzma_stream strm = LZMA_STREAM_INIT;
    lzma_ret ret = lzma_auto_decoder(&strm, UINT64_MAX, 0);
    if (ret != LZMA_OK) {
        set_error(SYMBOL_LOOKUP_ERROR_DECOMPRESS, "Failed to initialize LZMA decoder");
        LOGE("Failed to initialize LZMA decoder: %d", ret);
        return NULL;
    }
    
    strm.next_in = input;
    strm.avail_in = input_size;
    
    size_t decomp_size = MAX_DECOMPRESS_SIZE;
    uint8_t* out = malloc(decomp_size);
    if (!out) {
        set_error(SYMBOL_LOOKUP_ERROR_MEMORY, "Failed to allocate decompression buffer");
        LOGE("Failed to allocate memory for decompression (%zu bytes)", decomp_size);
        lzma_end(&strm);
        return NULL;
    }
    
    strm.next_out = out;
    strm.avail_out = decomp_size;
    
    ret = lzma_code(&strm, LZMA_FINISH);
    if (ret != LZMA_STREAM_END) {
        set_error(SYMBOL_LOOKUP_ERROR_DECOMPRESS, "LZMA decompression failed");
        LOGE("LZMA decompression failed: %d (input: %zu bytes)", ret, input_size);
        free(out);
        lzma_end(&strm);
        return NULL;
    }
    
    *out_size = decomp_size - strm.avail_out;
    lzma_end(&strm);
    LOGI("XZ decompression successful: %zu -> %zu bytes", input_size, *out_size);
    return out;
#else
    set_error(SYMBOL_LOOKUP_ERROR_DECOMPRESS, "LZMA not available");
    LOGE("LZMA decompression not available. Define HAVE_LZMA and link against liblzma to enable.");
    (void)input;
    (void)input_size;
    (void)out_size;
    return NULL;
#endif
}

static int parse_symbols_from_elf(uint8_t* elf_data, size_t elf_size, SymbolTable* table) {
    errno = 0;
    if (!elf_data || elf_size == 0 || !table) {
        set_error(SYMBOL_LOOKUP_ERROR_INVALID_ARG, "Invalid arguments to parse_symbols_from_elf");
        return -1;
    }
    
    LOGD("Parsing symbols from decompressed ELF data (%zu bytes)", elf_size);
    
    if (elf_size < sizeof(Elf64_Ehdr)) {
        set_error(SYMBOL_LOOKUP_ERROR_FORMAT, "ELF data too small");
        LOGE("ELF data too small (%zu bytes, expected at least %zu)", 
             elf_size, sizeof(Elf64_Ehdr));
        return -1;
    }
    
    Elf64_Ehdr* ehdr = (Elf64_Ehdr*)elf_data;
    if (!validate_elf_header(ehdr)) {
        set_error(SYMBOL_LOOKUP_ERROR_FORMAT, "Invalid ELF header");
        LOGE("Invalid ELF header in decompressed data");
        return -1;
    }
    
    if (ehdr->e_shoff + (sizeof(Elf64_Shdr) * ehdr->e_shnum) > elf_size) {
        set_error(SYMBOL_LOOKUP_ERROR_FORMAT, "Section headers exceed ELF data size");
        LOGE("Section headers exceed ELF data size (offset: %llu, size: %zu, data size: %zu)", 
             (unsigned long long)ehdr->e_shoff, 
             sizeof(Elf64_Shdr) * ehdr->e_shnum, 
             elf_size);
        return -1;
    }
    
    Elf64_Shdr* shdrs = (Elf64_Shdr*)(elf_data + ehdr->e_shoff);
    
    if (ehdr->e_shstrndx >= ehdr->e_shnum) {
        set_error(SYMBOL_LOOKUP_ERROR_FORMAT, "Invalid section header string table index");
        LOGE("Invalid section header string table index %d (max: %d)", 
             ehdr->e_shstrndx, ehdr->e_shnum);
        return -1;
    }
    
    Elf64_Shdr* sh_str = &shdrs[ehdr->e_shstrndx];
    if (sh_str->sh_offset + sh_str->sh_size > elf_size) {
        set_error(SYMBOL_LOOKUP_ERROR_FORMAT, "Section header string table exceeds ELF data size");
        LOGE("Section header string table exceeds ELF data size (offset: %llu, size: %llu, data size: %zu)", 
             (unsigned long long)sh_str->sh_offset,
             (unsigned long long)sh_str->sh_size,
             elf_size);
        return -1;
    }
    
    const char* shstrtab = (const char*)(elf_data + sh_str->sh_offset);
    
    Elf64_Shdr* symtab_sh = NULL;
    Elf64_Shdr* strtab_sh = NULL;
    
    for (int i = 0; i < ehdr->e_shnum; i++) {
        const char* name = shstrtab + shdrs[i].sh_name;
        if (strcmp(name, SECTION_NAME_SYMTAB) == 0) {
            symtab_sh = &shdrs[i];
        } else if (strcmp(name, SECTION_NAME_STRTAB) == 0) {
            strtab_sh = &shdrs[i];
        }
    }
    
    if (!symtab_sh || !strtab_sh) {
        set_error(SYMBOL_LOOKUP_ERROR_NOT_FOUND, "Required sections not found in decompressed data");
        LOGE("Required sections (.symtab or .strtab) not found in decompressed data");
        return -1;
    }
    
    if (symtab_sh->sh_offset + symtab_sh->sh_size > elf_size ||
        strtab_sh->sh_offset + strtab_sh->sh_size > elf_size) {
        set_error(SYMBOL_LOOKUP_ERROR_FORMAT, "Symbol table sections exceed ELF data size");
        LOGE("Symbol table sections exceed ELF data size (symtab: %llu+%llu, strtab: %llu+%llu, data: %zu)", 
             (unsigned long long)symtab_sh->sh_offset,
             (unsigned long long)symtab_sh->sh_size,
             (unsigned long long)strtab_sh->sh_offset,
             (unsigned long long)strtab_sh->sh_size,
             elf_size);
        return -1;
    }
    
    Elf64_Sym* syms = (Elf64_Sym*)(elf_data + symtab_sh->sh_offset);
    const char* strtab = (const char*)(elf_data + strtab_sh->sh_offset);
    size_t count = symtab_sh->sh_size / sizeof(Elf64_Sym);
    
    LOGD("Found symbol table with %zu entries", count);
    
    size_t func_count = 0;
    for (size_t i = 0; i < count; i++) {
        if (ELF64_ST_TYPE(syms[i].st_info) != STT_FUNC) {
            continue;
        }
        
        if (syms[i].st_name >= strtab_sh->sh_size) {
            LOGW("Invalid symbol name index %llu (max: %llu), skipping", 
                 (unsigned long long)syms[i].st_name,
                 (unsigned long long)strtab_sh->sh_size);
            continue;
        }
        
        const char* name = strtab + syms[i].st_name;
        if (symbol_table_add(table, syms[i].st_value, syms[i].st_size, name) != 0) {
            set_error(SYMBOL_LOOKUP_ERROR_MEMORY, "Failed to add symbol to table");
            LOGE("Failed to add symbol '%s' to table (out of memory?)", name);
            return -1;
        }
        func_count++;
    }
    
    LOGI("Successfully parsed %zu function symbols from decompressed data", func_count);
    errno = 0;
    return 0;
}

SymbolTable* symbol_table_load_from_elf(const char* elf_path) {
    errno = 0;
    if (!elf_path) {
        set_error(SYMBOL_LOOKUP_ERROR_INVALID_ARG, "ELF path is NULL");
        LOGE("Invalid ELF path (NULL)");
        return NULL;
    }
    
    LOGI("Loading symbol table from: %s", elf_path);
    
    SymbolTable* table = symbol_table_init();
    if (!table) {
        LOGE("Failed to initialize symbol table");
        return NULL;
    }
    
    size_t compressed_size = 0;
    uint8_t* compressed = load_gnu_debugdata(elf_path, &compressed_size);
    if (!compressed) {
        LOGE("Failed to load .gnu_debugdata from %s", elf_path);
        symbol_table_free(table);
        return NULL;
    }
    
    LOGD("Loaded .gnu_debugdata (%zu bytes), decompressing...", compressed_size);
    
    size_t decompressed_size = 0;
    uint8_t* elf_data = decompress_xz(compressed, compressed_size, &decompressed_size);
    free(compressed);
    
    if (!elf_data) {
        LOGE("Failed to decompress .gnu_debugdata from %s", elf_path);
        symbol_table_free(table);
        return NULL;
    }
    
    if (parse_symbols_from_elf(elf_data, decompressed_size, table) != 0) {
        LOGE("Failed to parse symbols from decompressed .gnu_debugdata");
        free(elf_data);
        symbol_table_free(table);
        return NULL;
    }
    
    free(elf_data);
    LOGI("Successfully loaded %zu symbols from .gnu_debugdata", table->count);
    errno = 0;
    return table;
}

const char* symbol_lookup_by_address(SymbolTable* table, uintptr_t lib_base, uintptr_t addr) {
    errno = 0;
    if (!table) {
        set_error(SYMBOL_LOOKUP_ERROR_INVALID_ARG, "Symbol table is NULL");
        LOGE("symbol_lookup_by_address: table is NULL");
        return UNKNOWN_SYMBOL_NAME;
    }
    
    if (lib_base == 0 || addr == 0) {
        set_error(SYMBOL_LOOKUP_ERROR_INVALID_ARG, "Invalid base or address");
        LOGW("symbol_lookup_by_address: invalid base (0x%llx) or address (0x%llx)", 
             (unsigned long long)lib_base, (unsigned long long)addr);
        return UNKNOWN_SYMBOL_NAME;
    }
    
    if (addr < lib_base) {
        set_error(SYMBOL_LOOKUP_ERROR_INVALID_ARG, "Address below base");
        LOGW("symbol_lookup_by_address: address 0x%llx is below base 0x%llx", 
             (unsigned long long)addr, (unsigned long long)lib_base);
        return UNKNOWN_SYMBOL_NAME;
    }
    
    uintptr_t offset = addr - lib_base;
    LOGD("Looking up symbol for address 0x%llx (offset: 0x%llx, base: 0x%llx)", 
         (unsigned long long)addr, (unsigned long long)offset, (unsigned long long)lib_base);
    
    for (size_t i = 0; i < table->count; i++) {
        if (offset >= table->syms[i].addr && 
            offset < table->syms[i].addr + table->syms[i].size) {
            LOGD("Found symbol: %s at offset 0x%llx", table->syms[i].name, (unsigned long long)offset);
            errno = 0;
            return table->syms[i].name;
        }
    }
    
    set_error(SYMBOL_LOOKUP_ERROR_NOT_FOUND, "Symbol not found for address");
    LOGW("Symbol not found for address 0x%llx (offset: 0x%llx)", 
         (unsigned long long)addr, (unsigned long long)offset);
    return UNKNOWN_SYMBOL_NAME;
}

uintptr_t symbol_lookup_by_name(SymbolTable* table, uintptr_t lib_base, const char* name) {
    errno = 0;
    if (!name) {
        set_error(SYMBOL_LOOKUP_ERROR_INVALID_ARG, "Symbol name is NULL");
        LOGE("symbol_lookup_by_name: name is NULL");
        return 0;
    }
    
    LOGD("Looking up address for symbol: %s", name);
    
    dlerror();
    void* dlsym_addr = dlsym(RTLD_DEFAULT, name);
    const char* dlerr = dlerror();
    
    if (dlsym_addr != NULL && dlerr == NULL) {
        uintptr_t addr = (uintptr_t)dlsym_addr;
        LOGI("Found symbol '%s' via dlsym at address: 0x%llx", name, (unsigned long long)addr);
        errno = 0;
        return addr;
    }
    
    LOGD("dlsym failed for '%s' (%s), trying .gnu_debugdata symbol table...", name, dlerr ? dlerr : "not found");
    
    if (!table) {
        set_error(SYMBOL_LOOKUP_ERROR_INVALID_ARG, "Symbol table is NULL");
        LOGW("symbol_lookup_by_name: table is NULL, cannot use fallback");
        return 0;
    }
    
    if (lib_base == 0) {
        set_error(SYMBOL_LOOKUP_ERROR_INVALID_ARG, "Library base is 0");
        LOGW("symbol_lookup_by_name: lib_base is 0, cannot use fallback");
        return 0;
    }
    
    for (size_t i = 0; i < table->count; i++) {
        if (strcmp(table->syms[i].name, name) == 0) {
            uintptr_t addr = lib_base + table->syms[i].addr;
            LOGI("Found symbol '%s' in symbol table at address: 0x%llx (offset: 0x%llx)", 
                 name, (unsigned long long)addr, (unsigned long long)table->syms[i].addr);
            errno = 0;
            return addr;
        }
    }
    
    set_error(SYMBOL_LOOKUP_ERROR_NOT_FOUND, "Symbol not found");
    LOGW("Symbol '%s' not found via dlsym or in symbol table (%zu symbols)", name, table->count);
    return 0;
}

typedef struct {
    const char* lib_name;
    uintptr_t base_addr;
    int found;
} lib_search_data_t;

static int find_library_callback(struct dl_phdr_info* info, size_t size, void* data) {
    (void)size;
    lib_search_data_t* search_data = (lib_search_data_t*)data;
    
    if (!info->dlpi_name || info->dlpi_name[0] == '\0') {
        return 0;
    }
    
    const char* name = strrchr(info->dlpi_name, '/');
    name = name ? name + 1 : info->dlpi_name;
    
    if (strstr(info->dlpi_name, search_data->lib_name) != NULL || 
        strcmp(name, search_data->lib_name) == 0) {
        search_data->base_addr = info->dlpi_addr;
        search_data->found = 1;
        LOGD("Found library %s at base 0x%llx (path: %s)", 
             search_data->lib_name, (unsigned long long)search_data->base_addr, info->dlpi_name);
        return 1;
    }
    
    return 0;
}

uintptr_t get_library_base_address(const char* lib_name) {
    errno = 0;
    if (!lib_name) {
        set_error(SYMBOL_LOOKUP_ERROR_INVALID_ARG, "Library name is NULL");
        LOGE("get_library_base_address: lib_name is NULL");
        return 0;
    }
    
    LOGD("Getting base address for library: %s", lib_name);
    
    lib_search_data_t search_data = {
        .lib_name = lib_name,
        .base_addr = 0,
        .found = 0
    };
    
    dl_iterate_phdr(find_library_callback, &search_data);
    
    if (search_data.found && search_data.base_addr != 0) {
        LOGI("Library %s base address: 0x%llx", lib_name, (unsigned long long)search_data.base_addr);
        errno = 0;
        return search_data.base_addr;
    }
    
    LOGW("Library %s not found via dl_iterate_phdr, trying dlopen fallback", lib_name);
    
    void* handle = dlopen(lib_name, RTLD_NOW | RTLD_NOLOAD);
    if (handle) {
        Dl_info info;
        if (dladdr(handle, &info) != 0 && info.dli_fbase) {
            uintptr_t result = (uintptr_t)info.dli_fbase;
            LOGI("Library %s base address (via dlopen): 0x%llx", 
                 lib_name, (unsigned long long)result);
            dlclose(handle);
            errno = 0;
            return result;
        }
        dlclose(handle);
    }
    
    set_error(SYMBOL_LOOKUP_ERROR_NOT_FOUND, "Library not found");
    LOGE("Failed to find library %s", lib_name);
    return 0;
}

char* symbol_demangle(const char* mangled_name) {
    errno = 0;
    if (!mangled_name) {
        set_error(SYMBOL_LOOKUP_ERROR_INVALID_ARG, "Mangled name is NULL");
        LOGE("symbol_demangle: mangled_name is NULL");
        return NULL;
    }
    
    int status = 0;
    char* demangled = __cxa_demangle(mangled_name, NULL, NULL, &status);
    
    if (status == 0 && demangled != NULL) {
        LOGD("Demangled '%s' -> '%s'", mangled_name, demangled);
        errno = 0;
        return demangled;
    }
    
    if (status == -1) {
        set_error(SYMBOL_LOOKUP_ERROR_MEMORY, "Memory allocation failure while demangling");
        LOGW("Memory allocation failure while demangling '%s'", mangled_name);
    } else if (status == -2) {
        set_error(SYMBOL_LOOKUP_ERROR_FORMAT, "Not a valid mangled name");
        LOGD("'%s' is not a valid mangled name", mangled_name);
    } else if (status == -3) {
        set_error(SYMBOL_LOOKUP_ERROR_INVALID_ARG, "Invalid argument to __cxa_demangle");
        LOGW("Invalid argument to __cxa_demangle for '%s'", mangled_name);
    }
    
    return NULL;
}
