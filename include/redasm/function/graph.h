#pragma once

#include <redasm/common.h>
#include <redasm/graphing/graph.h>

typedef struct RDFunctionGraph RDFunctionGraph;

// clang-format off
RD_API RDFunctionGraph* rd_functiongraph_create(RDContext* ctx);
RD_API bool rd_functiongraph_populate(RDFunctionGraph* self, RDAddress entry);
RD_API void rd_functiongraph_destroy(RDFunctionGraph* self);
RD_API bool rd_functiongraph_get_chunk_start(const RDFunctionGraph* self, RDGraphNode n, RDAddress* start_addr); 
RD_API bool rd_functiongraph_get_chunk_end(const RDFunctionGraph* self, RDGraphNode n, RDAddress* end_addr);
RD_API bool rd_functiongraph_is_chunk_noret(const RDFunctionGraph* self, RDGraphNode n, bool* is_noret);  
RD_API bool rd_functiongraph_get_address(const RDFunctionGraph* self, RDAddress* address);
RD_API bool rd_functiongraph_is_current(const RDFunctionGraph* self);
RD_API const char* rd_functiongraph_generate_dot(const RDFunctionGraph* self);
RD_API const char* rd_functiongraph_generate_dot_layout(const RDFunctionGraph* self);
RD_API u32 rd_functiongraph_get_hash(const RDFunctionGraph* self);
RD_API u32 rd_functiongraph_get_hash_layout(const RDFunctionGraph* self);
// clang-format on
