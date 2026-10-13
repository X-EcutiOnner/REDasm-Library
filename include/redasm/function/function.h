#pragma once

#include <redasm/config.h>
#include <redasm/types/def.h>

// clang-format off
RD_API bool rd_function_is_noret(const RDContext* self, RDAddress address);
RD_API bool rd_function_find(const RDContext* self, RDAddress address, RDAddress* entry);
RD_API const RDTypeDef* rd_function_get_type_def(const RDContext* self, RDAddress address);
// clang-format on
