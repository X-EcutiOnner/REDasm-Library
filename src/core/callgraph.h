#pragma once

#include "db/types.h"
#include "function/chunk.h"
#include "graphing/graph.h"
#include <redasm/callgraph.h>

typedef struct RDCallGraph {
    RDGraph base;
    RDXRefVect xrefs_buf;
    RDChunkVect chunks_buf;

    struct {
        RDGraphNode* data;
        usize length;
        usize capacity;
    } wl;
} RDCallGraph;
