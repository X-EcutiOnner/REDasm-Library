#pragma once

#include "../database/database.h"
#include "../document/document.h"
#include "../plugin.h"
#include "../buffer.h"
#include "assembler/assembler.h"

enum RDLoaderFlags {
    LoaderFlags_None               = 0,
    LoaderFlags_CustomAssembler    = (1 << 0),
    LoaderFlags_CustomAddressing   = (1 << 1),
};

typedef struct RDLoaderRequest {
    const char* filepath;
    RDBuffer* buffer;
} RDLoaderRequest;

typedef struct RDLoaderBuildRequest {
    rd_offset offset;
    rd_address baseaddress;
    rd_address entrypoint;
} RDLoaderBuildRequest;

DECLARE_HANDLE(RDLoader);

struct RDLoaderPlugin;

typedef const char* (*Callback_LoaderTest)(const struct RDLoaderPlugin* plugin, const RDLoaderRequest* request);
typedef bool (*Callback_LoaderLoad)(struct RDLoaderPlugin* ploader, RDLoader* loader);
typedef bool (*Callback_LoaderBuild)(struct RDLoaderPlugin* ploader, RDLoader* loader, const RDLoaderBuildRequest* req);

typedef struct RDLoaderPlugin {
    RD_PLUGIN_HEADER
    rd_flag flags;

    Callback_LoaderTest test;
    Callback_LoaderLoad load;
    Callback_LoaderBuild build;
} RDLoaderPlugin;

typedef void (*Callback_LoaderPlugin)(RDLoaderPlugin* ploader, void* userdata);

RD_API_EXPORT bool RDLoader_Register(RDLoaderPlugin* ploader);
RD_API_EXPORT bool RDLoader_GetUserData(const RDLoader* ldr, RDUserData* userdata);
RD_API_EXPORT const char* RDLoader_GetAssemblerId(const RDLoaderPlugin* ploader);
RD_API_EXPORT const char* RDLoader_GetId(const RDLoader* ldr);
RD_API_EXPORT RDAssemblerPlugin* RDLoader_GetAssemblerPlugin(const RDLoaderPlugin* ploader);
RD_API_EXPORT rd_flag RDLoader_GetFlags(const RDLoader* ldr);
RD_API_EXPORT RDDocument* RDLoader_GetDocument(RDLoader* ldr);
RD_API_EXPORT RDDatabase* RDLoader_GetDatabase(RDLoader* ldr);
RD_API_EXPORT RDBuffer* RDLoader_GetBuffer(RDLoader* ldr);
RD_API_EXPORT u8* RDLoader_GetData(RDLoader* ldr);

RD_API_EXPORT void RD_GetLoaders(const RDLoaderRequest* loadrequest, Callback_LoaderPlugin callback, void* userdata);
RD_API_EXPORT u8* RD_AddrPointer(const RDLoader* ldr, rd_address address);
RD_API_EXPORT u8* RD_Pointer(const RDLoader* ldr, rd_offset offset);
RD_API_EXPORT RDLocation RD_FileOffset(const RDLoader* ldr, const void* ptr);
RD_API_EXPORT RDLocation RD_AddressOf(const RDLoader* ldr, const void* ptr);
RD_API_EXPORT RDLocation RD_Offset(const RDLoader* ldr, rd_address address);
RD_API_EXPORT RDLocation RD_Address(const RDLoader* ldr, rd_offset offset);
