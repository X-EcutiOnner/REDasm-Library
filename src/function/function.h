#pragma once

#include "core/segment.h"
#include "types/def.h"
#include <redasm/function/function.h>

bool rd_i_function_declare(RDContext* ctx, const RDSegment* seg, usize idx,
                           const char* type);
void rd_i_function_undeclare(RDContext* ctx, const RDSegment* seg, usize idx);
void rd_i_function_set_type_def(RDContext* ctx, RDAddress address,
                                const RDTypeDef* tdef);
bool rd_i_function_find_rel(const RDContext* self, RDAddress address,
                            RDRelAddress* rel_entry);
bool rd_i_function_is_noret(const RDContext* self, RDAddress address,
                            const RDTypeDef* tdef);
