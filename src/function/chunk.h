#pragma once

#include "db/types.h"
#include <redasm/function/function.h>

typedef enum {
    RD_SUCC_JUMP,
    RD_SUCC_TRUE,
    RD_SUCC_FALSE,
    RD_SUCC_FLOW
} RDChunkSuccKind;

typedef struct RDChunkSucc {
    RDAddress address;
    RDChunkSuccKind kind;
} RDChunkSucc;

typedef struct RDChunkSuccVect {
    RDChunkSucc* data;
    usize length;
    usize capacity;
} RDChunkSuccVect;

typedef struct RDChunk {
    u32 gen;

    RDRelAddress entry;
    RDRelAddress start;
    RDRelAddress end; // exclusive
    RDRelAddress term;
    bool is_noret;
} RDChunk;

typedef struct RDChunkVect {
    RDChunk* data;
    usize length;
    usize capacity;
} RDChunkVect;

const RDChunk* rd_i_chunks_find(const RDContext* ctx, RDAddress address);
void rd_i_chunks_rebuild(RDContext* ctx);
void rd_i_chunks_collect(RDContext* ctx, RDAddress entry, RDChunkVect* out);
void rd_i_chunks_del(RDContext* ctx, RDAddress entry);
void rd_i_chunks_rebuild_at(RDContext* ctx, RDAddress entry);
void rd_i_chunks_build(RDContext* ctx, RDAddress entry, RDChunkVect* out);
void rd_i_chunks_sort(RDChunkVect* self);
const RDChunk* rd_i_chunks_find_start(const RDContext* ctx, RDAddress start,
                                      RDAddress entry);

const RDChunk* rd_i_chunks_find_start_rel(const RDContext* ctx,
                                          RDRelAddress start,
                                          RDRelAddress entry);

static inline const RDChunk* rd_i_chunks_find_head_rel(const RDContext* ctx,
                                                       RDRelAddress entry) {
    return rd_i_chunks_find_start_rel(ctx, entry, entry);
}

static inline const RDChunk* rd_i_chunks_find_head(const RDContext* ctx,
                                                   RDAddress entry) {
    return rd_i_chunks_find_start(ctx, entry, entry);
}

void rd_i_chunk_successors(RDContext* ctx, const RDChunk* c,
                           RDChunkSuccVect* succ, RDXRefVect* refs,
                           bool* noret_end);
