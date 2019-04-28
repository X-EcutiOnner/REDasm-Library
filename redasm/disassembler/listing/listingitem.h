#pragma once

#include <memory>
#include <deque>
#include "../../support/containers/sorted_container.h"
#include "../../types/base_types.h"

namespace REDasm {

struct ListingItem
{
    enum: size_t {
        Undefined = 0,
        SegmentItem, EmptyItem, FunctionItem, TypeItem, SymbolItem, MetaItem, InstructionItem,
        AllItems = static_cast<size_t>(-1)
    };

    ListingItem(): address(0), type(ListingItem::Undefined), index(0) { }
    ListingItem(address_t address, size_t type, size_t index): address(address), type(type), index(index) { }
    bool is(size_t t) const { return type == t; }

    address_t address;
    size_t type, index;
};

typedef std::unique_ptr<ListingItem> ListingItemPtr;
typedef std::deque<ListingItem*> ListingItems;

template<typename T> struct ListingItemComparatorT {
    bool operator()(const T& t1, const T& t2) const {
        if(t1->address == t2->address) {
            if(t1->type == t2->type)
                return t1->index < t2->index;
            return t1->type < t2->type;
        }
        return t1->address < t2->address;
    }
};

template<typename T> struct ListingItemFinderT {
    bool operator()(const T& t1, const T& t2) const {
        if(t1->address == t2->address)
            return t1->type < t2->type;
        return t1->address < t2->address;
    }
};

typedef ListingItemComparatorT<ListingItemPtr> ListingItemPtrComparator;
typedef ListingItemComparatorT<ListingItem*> ListingItemComparator;
typedef ListingItemFinderT<ListingItemPtr> ListingItemPtrFinder;
typedef ListingItemFinderT<ListingItem*> ListingItemFinder;
typedef sorted_container<ListingItem*, ListingItemComparator> ListingItemContainer;


} // namespace REDasm
