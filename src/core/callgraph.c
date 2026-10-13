#include "callgraph.h"
#include "core/context.h"
#include "function/function.h"
#include "io/flagsbuffer.h"
#include <redasm/allocator.h>
#include <redasm/graphing/graph.h>

typedef struct RDCallGraphNode {
    RDRelAddress func_rel_address;
    bool up_queued, down_queued;
} RDCallGraphNode;

static void _rd_callgraph_destroy(RDGraph* base) {
    RDCallGraph* self = (RDCallGraph*)base;

    const RDNodeVect* nodes = rd_i_graph_get_nodes(&self->base);

    const RDGraphNode* it;
    vect_each(it, nodes) {
        RDCallGraphNode* d =
            (RDCallGraphNode*)rd_graph_get_data(&self->base, *it);

        rd_free(d);
    }

    vect_destroy(&self->chunks_buf);
    vect_destroy(&self->xrefs_buf);
    vect_destroy(&self->wl);
}

static RDGraphNode _rd_callgraph_get_or_add_block(RDCallGraph* self,
                                                  RDRelAddress address) {
    const RDNodeVect* nodes = rd_i_graph_get_nodes(&self->base);

    const RDGraphNode* it;
    vect_each(it, nodes) {
        const RDCallGraphNode* d =
            (const RDCallGraphNode*)rd_graph_get_data(&self->base, *it);

        if(d->func_rel_address == address) return *it;
    }

    RDCallGraphNode* d = rd_alloc(sizeof(*d));
    d->func_rel_address = address;
    d->up_queued = false;
    d->down_queued = false;

    RDGraphNode n = rd_graph_add_node(&self->base);
    rd_graph_set_data(&self->base, n, (RDNodeData)d);
    return n;
}

// A node is explored at most once per direction:
// - only direct calls uses this.
// - indirect ones create/annotate a node but never queue it.
static void _rd_callgraph_enqueue(RDCallGraph* self, RDGraphNode n, bool up) {
    RDCallGraphNode* d = (RDCallGraphNode*)rd_graph_get_data(&self->base, n);
    bool* queued = up ? &d->up_queued : &d->down_queued;
    if(*queued) return;

    *queued = true;
    vect_push(&self->wl, n);
}

static void _rd_callgraph_explore_up(RDCallGraph* self, RDGraphNode child_node,
                                     RDRelAddress rel_entry) {
    RDContext* ctx = self->base.context;

    const RDXRefVect* xrefs = rd_i_db_get_xrefs_to(
        ctx, rd_i_abs(ctx, rel_entry), RD_XR_NONE, &self->xrefs_buf);

    const RDXRef* xref;
    vect_each(xref, xrefs) {
        bool direct = xref->type == RD_CR_CALL;

        // xref->address is the referencing address: a call site, or a data
        // cell for indirect references.
        // Key by the containing function so several calls from one caller
        // collapse into a single node.

        RDRelAddress src_rel_entry;
        bool has_src =
            rd_i_function_find_rel(ctx, xref->address, &src_rel_entry);
        if(!has_src && direct)
            continue; // call site not (yet) claimed by a function

        RDRelAddress key =
            has_src ? src_rel_entry : rd_i_rel(ctx, xref->address);

        // a jump back to our own entry (a loop) isn't a reference to us
        if(!direct && key == rel_entry) continue;

        RDGraphNode n = _rd_callgraph_get_or_add_block(self, key);

        // caller -> callee, same orientation as down edges
        RDGraphEdge e = rd_graph_add_edge(&self->base, n, child_node);

        rd_graph_set_edge_color(
            &self->base, &e,
            rd_get_theme_color(direct ? RD_THEME_FAIL : RD_THEME_MUTED));

        if(direct) _rd_callgraph_enqueue(self, n, true);
    }
}

static void _rd_callgraph_explore_down(RDCallGraph* self,
                                       RDGraphNode parent_node,
                                       RDRelAddress rel_entry) {
    RDContext* ctx = self->base.context;

    rd_i_chunks_collect(ctx, rd_i_abs(ctx, rel_entry), &self->chunks_buf);

    const RDChunk* c;
    vect_each(c, &self->chunks_buf) {
        const RDSegment* seg =
            rd_i_db_find_segment(ctx, rd_i_abs(ctx, c->start));
        if(!seg) continue;

        usize idx = c->start - seg->rel_start,
              end_idx = c->end - seg->rel_start;

        while(idx < end_idx) {
            if(rd_flagsbuffer_has_call(seg->flags, idx)) {
                RDAddress addr = rd_i_index2address(seg, idx);
                const RDXRefVect* xrefs = rd_i_db_get_xrefs_from(
                    ctx, addr, RD_XR_NONE, &self->xrefs_buf);

                const RDXRef* xref;
                vect_each(xref, xrefs) {
                    bool direct = xref->type == RD_CR_CALL;

                    RDGraphNode n = _rd_callgraph_get_or_add_block(
                        self, rd_i_rel(ctx, xref->address));

                    RDGraphEdge e =
                        rd_graph_add_edge(&self->base, parent_node, n);

                    rd_graph_set_edge_color(
                        &self->base, &e,
                        rd_get_theme_color(direct ? RD_THEME_SUCCESS
                                                  : RD_THEME_WARNING));

                    if(direct) _rd_callgraph_enqueue(self, n, false);
                }
            }

            idx += rd_i_flagsbuffer_get_range_length(seg->flags, idx);
        }
    }
}

static void _rd_callgraph_walk_up(RDCallGraph* self, RDGraphNode start) {
    RDContext* ctx = self->base.context;
    vect_push(&self->wl, start);

    while(!vect_is_empty(&self->wl)) {
        RDGraphNode n = vect_pop_last(&self->wl);

        RDCallGraphNode* d =
            (RDCallGraphNode*)rd_graph_get_data(&self->base, n);

        if(rd_is_function(ctx, rd_i_abs(ctx, d->func_rel_address)))
            _rd_callgraph_explore_up(self, n, d->func_rel_address);
    }
}

static void _rd_callgraph_walk_down(RDCallGraph* self, RDGraphNode start) {
    vect_push(&self->wl, start);

    while(!vect_is_empty(&self->wl)) {
        RDGraphNode n = vect_pop_last(&self->wl);

        RDCallGraphNode* d =
            (RDCallGraphNode*)rd_graph_get_data(&self->base, n);

        _rd_callgraph_explore_down(self, n, d->func_rel_address);
    }
}

RDCallGraph* rd_callgraph_create(RDContext* ctx, RDAddress address) {
    RDRelAddress rel_entry;
    if(!rd_i_function_find_rel(ctx, address, &rel_entry)) return NULL;

    RDCallGraph* self =
        rd_graph_create_as(RDCallGraph, ctx, _rd_callgraph_destroy);

    RDGraphNode root = _rd_callgraph_get_or_add_block(self, rel_entry);
    rd_graph_set_root(&self->base, root);
    _rd_callgraph_walk_down(self, root);
    _rd_callgraph_walk_up(self, root);
    return self;
}

void rd_callgraph_destroy(RDCallGraph* self) {
    rd_graph_destroy((RDGraph*)self); // let 'destroy' handle deallocation
}

RDAddress rd_callgraph_get_address(const RDCallGraph* self, RDGraphNode n) {
    const RDCallGraphNode* d =
        (const RDCallGraphNode*)rd_graph_get_data(&self->base, n);
    return rd_i_abs(self->base.context, d->func_rel_address);
}
