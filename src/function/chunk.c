#include "chunk.h"
#include "core/context.h"
#include "io/flags.h"
#include "io/flagsbuffer.h"
#include <inttypes.h>

static bool _rd_chunk_is_tail_call(const RDContext* ctx, RDAddress entry,
                                   RDAddress target) {
    if(target == entry) return false; // loop to own entry

    const RDSegment* seg = rd_i_db_find_segment(ctx, target);
    if(!seg || !rd_segment_has_perm(seg, RD_SP_X)) return false;

    return rd_flagsbuffer_has_func(seg->flags, rd_i_address2index(seg, target));
}

static bool _rd_chunk_falls_into(const RDSegment* seg, RDAddress address) {
    return address < rd_segment_get_end(seg) &&
           rd_flagsbuffer_has_flow(seg->flags,
                                   rd_i_address2index(seg, address));
}

static void _rd_chunk_scan(RDContext* ctx, RDAddress start, RDChunk* c,
                           RDChunkSuccVect* succ, RDXRefVect* refs,
                           bool* noret_end) {
    vect_clear(succ);
    *noret_end = false;

    const RDSegment* seg = rd_i_db_find_segment(ctx, start);
    RDAddress seg_end = rd_segment_get_end(seg);
    RDAddress addr = start, term = start;

    while(addr < seg_end) {
        usize idx = rd_i_address2index(seg, addr);
        RDFlags flags = rd_i_flagsbuffer_get(seg->flags, idx);
        if(!rd_flags_has_code(flags) || rd_flags_has_tail(flags)) break;

        usize len = rd_i_flagsbuffer_get_range_length(seg->flags, idx);
        if(!len) break;

        term = addr;
        RDAddress next = addr + len;
        addr = next;

        if(rd_flags_has_jump(flags)) {
            while(next < seg_end) { // delay slots belong to the block
                usize ni = rd_i_address2index(seg, next);
                if(!rd_i_flags_has_dslot(rd_i_flagsbuffer_get(seg->flags, ni)))
                    break;

                next += rd_i_flagsbuffer_get_range_length(seg->flags, ni);
            }

            addr = next;
            break;
        }

        if(next >= seg_end) break;

        RDFlags nf =
            rd_i_flagsbuffer_get(seg->flags, rd_i_address2index(seg, next));
        if(!rd_i_flags_has_flow(nf) || rd_flags_has_xref_in(nf)) break;
    }

    c->start = rd_i_rel(ctx, start);
    c->term = rd_i_rel(ctx, term);
    c->end = rd_i_rel(ctx, addr);
    rd_i_chunk_successors(ctx, c, succ, refs, noret_end);
}

static bool _rd_chunk_del_if_pred(const void* key, void* item) {
    const RDChunk* c = (const RDChunk*)item;
    return c->entry == *(const RDRelAddress*)key;
}

static int _rd_chunk_cmp_pred(const void* arg1, const void* arg2) {
    const RDChunk* a = (const RDChunk*)arg1;
    const RDChunk* b = (const RDChunk*)arg2;

    if(a->start == b->start)
        return (a->entry > b->entry) - (a->entry < b->entry);

    return (a->start > b->start) - (a->start < b->start);
}

static int _rd_chunk_start_kcmp_pred(const void* key, const void* item) {
    RDRelAddress k = *(const RDRelAddress*)key;
    const RDChunk* c = (const RDChunk*)item;
    return (k > c->start) - (k < c->start);
}

static int _rd_chunk_range_kcmp_pred(const void* key, const void* item) {
    RDRelAddress k = *(const RDRelAddress*)key;
    const RDChunk* c = (const RDChunk*)item;
    if(k < c->start) return -1;
    if(k >= c->end) return 1;
    return 0;
}

static bool _rd_chunk_is_valid_target(RDContext* ctx, RDAddress address) {
    const RDSegment* seg = rd_i_db_find_segment(ctx, address);
    return seg && rd_segment_has_perm(seg, RD_SP_X);
}

// true: valid target not seen yet, now marked as seen (queue it)
static bool _rd_chunk_claim(RDContext* ctx, RDAddressVect* seen,
                            RDAddress address) {
    if(!_rd_chunk_is_valid_target(ctx, address)) return false;

    usize idx = vect_lower_bound(seen, &address, rd_i_address_kcmp_pred);
    if(idx < vect_length(seen) && *vect_at(seen, idx) == address) return false;

    vect_ins(seen, idx, address);
    return true;
}

static const RDChunk* _rd_chunk_find_owner(const RDChunkVect* known,
                                           RDRelAddress start) {
    // sorted by (start, entry): the first match is the lowest entry
    usize i = vect_lower_bound(known, &start, _rd_chunk_start_kcmp_pred);
    if(i < vect_length(known) && vect_at(known, i)->start == start)
        return vect_at(known, i);

    return NULL;
}

static bool _rd_chunk_is_foreign(const RDContext* ctx, const RDChunkVect* known,
                                 RDAddress entry, RDAddress start) {
    const RDChunk* o = _rd_chunk_find_owner(known, rd_i_rel(ctx, start));
    if(!o) return false;

    RDRelAddress rel_entry = rd_i_rel(ctx, entry);
    if(o->entry < rel_entry) return true;
    if(o->entry == rel_entry) return false;

    panic("chunk 0x%" PRIX64 " of 0x%" PRIX64 " is owned by higher entry",
          start, entry);

    return false;
}

static void _rd_chunks_insert(RDChunkVect* chunks, const RDChunk* c) {
    usize idx = vect_lower_bound(chunks, c, _rd_chunk_cmp_pred);
    vect_ins(chunks, idx, *c);
}

static void _rd_chunks_build(RDContext* ctx, RDAddress entry,
                             RDChunkVect* chunks) {
    RDAddressVect work = {0};
    RDAddressVect seen = {0}; // sorted: replaces the O(n) node scan
    RDChunkSuccVect succ = {0};
    RDXRefVect xrefs = {0};
    bool has_noret_exit = false, all_exits_noret = true;
    u32 gen = ++ctx->chunk_gen;

    RDChunk head = {0};
    bool has_head = false;

    if(_rd_chunk_claim(ctx, &seen, entry)) vect_push(&work, entry);

    while(!vect_is_empty(&work)) {
        RDAddress start = vect_pop_last(&work);
        RDChunk c = {.gen = gen, .entry = rd_i_rel(ctx, entry)};
        bool noret_end;

        _rd_chunk_scan(ctx, start, &c, &succ, &xrefs, &noret_end);

        usize n_edges = 0;
        const RDChunkSucc* s;
        vect_each(s, &succ) {
            if(!_rd_chunk_is_valid_target(ctx, s->address)) continue;
            if(_rd_chunk_is_foreign(ctx, chunks, entry, s->address)) continue;

            // exec segment, not seen yet
            if(_rd_chunk_claim(ctx, &seen, s->address))
                vect_push(&work, s->address);

            n_edges++;
        }

        if(!n_edges) { // exit chunk
            if(noret_end)
                has_noret_exit = true;
            else
                all_exits_noret = false;
        }

        if(!has_head) { // first popped: held back until is_noret is known
            head = c;
            has_head = true;
        }
        else
            _rd_chunks_insert(chunks, &c);
    }

    if(has_head) {
        head.is_noret = has_noret_exit && all_exits_noret;
        _rd_chunks_insert(chunks, &head);
    }

    vect_destroy(&work);
    vect_destroy(&seen);
    vect_destroy(&succ);
    vect_destroy(&xrefs);
}

void rd_i_chunk_successors(RDContext* ctx, const RDChunk* c,
                           RDChunkSuccVect* succ, RDXRefVect* refs,
                           bool* noret_end) {
    vect_clear(succ);
    *noret_end = false;
    if(c->start == c->end) return; // not code at all

    RDAddress term = rd_i_abs(ctx, c->term);

    const RDSegment* seg = rd_i_db_find_segment(ctx, term);
    if(!seg) return;

    RDAddress entry = rd_i_abs(ctx, c->entry);
    RDAddress end = rd_i_abs(ctx, c->end);

    RDAddress seg_end = rd_segment_get_end(seg);
    RDFlags flags =
        rd_i_flagsbuffer_get(seg->flags, rd_i_address2index(seg, term));

    if(rd_flags_has_jump(flags)) {
        rd_i_get_xrefs_from_ex(ctx, term, RD_CR_JUMP, refs);
        bool cond = rd_flags_has_cond(flags);

        const RDXRef* r;
        vect_each(r, refs) {
            if(_rd_chunk_is_tail_call(ctx, entry, r->address)) continue;
            vect_push(succ, (RDChunkSucc){r->address,
                                          cond ? RD_SUCC_TRUE : RD_SUCC_JUMP});
        }

        if(cond && _rd_chunk_falls_into(seg, end))
            vect_push(succ, (RDChunkSucc){end, RD_SUCC_FALSE});
    }
    else if(end < seg_end) {
        RDFlags nf =
            rd_i_flagsbuffer_get(seg->flags, rd_i_address2index(seg, end));
        if(!rd_i_flags_has_flow(nf))
            *noret_end = rd_flags_has_noret(flags);
        else if(rd_flags_has_xref_in(nf))
            vect_push(succ, (RDChunkSucc){end, RD_SUCC_FLOW});
    }
}

const RDChunk* rd_i_chunks_find_start(const RDContext* ctx, RDAddress start,
                                      RDAddress entry) {
    if(!rd_is_address(ctx, start) || !rd_is_address(ctx, entry)) return NULL;

    return rd_i_chunks_find_start_rel(ctx, rd_i_rel(ctx, start),
                                      rd_i_rel(ctx, entry));
}

const RDChunk* rd_i_chunks_find_start_rel(const RDContext* ctx,
                                          RDRelAddress start,
                                          RDRelAddress entry) {
    usize i = vect_lower_bound(&ctx->chunks, &start, _rd_chunk_start_kcmp_pred);

    for(; i < vect_length(&ctx->chunks); i++) {
        const RDChunk* c = vect_at(&ctx->chunks, i);
        if(c->start != start) break;
        if(c->entry == entry) return c;
    }

    return NULL;
}

const RDChunk* rd_i_chunks_find(const RDContext* ctx, RDAddress address) {
    if(!rd_is_address(ctx, address) || vect_is_empty(&ctx->chunks)) return NULL;

    RDRelAddress rel = rd_i_rel(ctx, address);
    usize idx = vect_bsearch(&ctx->chunks, &rel, _rd_chunk_range_kcmp_pred);
    return idx != vect_length(&ctx->chunks) ? vect_at(&ctx->chunks, idx) : NULL;
}

void rd_i_chunks_build_all(RDContext* ctx) {
    RDChunkVect chunks = {0};
    vect_reserve(&chunks, vect_capacity(&ctx->chunks));

    RDAddressVect functions = {0};
    rd_i_db_get_all_functions(ctx, &functions);

    RDAddressVect owned = {0};
    const RDAddress* addr;
    vect_each(addr, &functions) { _rd_chunks_build(ctx, *addr, &chunks); }

    mem_swap(RDChunkVect, &ctx->chunks, &chunks);
    vect_destroy(&owned);
    vect_destroy(&functions);
    vect_destroy(&chunks);
}

void rd_i_chunks_collect(RDContext* ctx, RDAddress entry, RDChunkVect* out) {
    assert(out);
    vect_clear(out);

    const RDChunk* head = rd_i_chunks_find_head(ctx, entry);
    if(!head) return;

    RDRelAddress rel_entry = head->entry;

    RDChunkVect work = {0};
    RDAddressVect seen = {0};
    RDChunkSuccVect succ = {0};
    RDXRefVect refs = {0};

    vect_push(&work, *head);
    vect_push(&seen, rd_i_abs(ctx, head->start));

    while(!vect_is_empty(&work)) {
        RDChunk c =
            vect_pop_last(&work); // copy: 'ctx->chunks' is never aliased
        vect_push(out, c);

        bool noret_end;
        rd_i_chunk_successors(ctx, &c, &succ, &refs, &noret_end);

        const RDChunkSucc* s;
        vect_each(s, &succ) {
            if(!rd_is_address(ctx, s->address)) continue;

            const RDChunk* t = rd_i_chunks_find_start_rel(
                ctx, rd_i_rel(ctx, s->address), rel_entry);
            if(!t) continue;

            usize i =
                vect_lower_bound(&seen, &s->address, rd_i_address_kcmp_pred);
            if(i < vect_length(&seen) && *vect_at(&seen, i) == s->address)
                continue;

            vect_ins(&seen, i, s->address);
            vect_push(&work, *t);
        }
    }

    vect_sort(out, _rd_chunk_cmp_pred);
    vect_destroy(&work);
    vect_destroy(&seen);
    vect_destroy(&succ);
    vect_destroy(&refs);
}

void rd_i_chunks_del(RDContext* ctx, RDAddress entry) {
    RDRelAddress rel = rd_i_rel(ctx, entry);
    vect_del_if(&ctx->chunks, &rel, _rd_chunk_del_if_pred);
}

void rd_i_chunks_rebuild_at(RDContext* ctx, RDAddress entry) {
    rd_i_chunks_del(ctx, entry);
    _rd_chunks_build(ctx, entry, &ctx->chunks);
}
