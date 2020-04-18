#include "abstract.h"
#include <algorithm>
#include <cassert>

u8 AbstractBuffer::at(size_t offset) const
{
    assert(this->data() && (offset < this->size()));
    return this->data()[offset];
}

const u8* AbstractBuffer::data() const { return const_cast<AbstractBuffer*>(this)->data(); }
const u8* AbstractBuffer::endData() const { return this->data() ? (this->data() + this->size()) : nullptr; }

bool AbstractBuffer::contains(const u8* ptr) const
{
    return (reinterpret_cast<const u8*>(ptr) >= this->data()) &&
           (reinterpret_cast<const u8*>(ptr) < this->endData());
}

bool AbstractBuffer::empty() const { return !this->data() || !this->size(); }
void AbstractBuffer::fill(u8 val) { std::fill_n(this->data(), this->size(), val); }
