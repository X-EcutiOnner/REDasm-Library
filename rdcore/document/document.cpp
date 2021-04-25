#include "document.h"
#include "../plugin/assembler.h"
#include "../plugin/loader.h"
#include "../support/utils.h"
#include "../disassembler.h"
#include "../context.h"

Document::Document(const MemoryBufferPtr& buffer, Context* ctx): Object(ctx), m_buffer(buffer), m_addressspace(ctx), m_net(ctx) { }
rd_endianness Document::endianness() const { return m_endianness; }
void Document::setEndianness(rd_endianness endianness) { m_endianness = endianness; }
MemoryBuffer* Document::buffer() const { return m_buffer.get(); }
DocumentNet* Document::net() { return &m_net; }

bool Document::setSegment(const std::string& name, rd_offset offset, rd_address address, size_t psize, size_t vsize, rd_flag flags)
{
    if((!(flags & SegmentFlags_Bss) && !psize) || !vsize)
    {
        this->log("Segment " + Utils::quoted(name) + " is empty, skipping");
        return false;
    }

    size_t len = std::min<size_t>(name.size(), DEFAULT_NAME_SIZE);

    RDSegment segment{ };

    if(flags & SegmentFlags_Bss)
    {
        segment.offset = 0;
        segment.endoffset = 0;
    }
    else
    {
        auto endoffset = offset + psize;
        auto bsize = this->context()->buffer()->size();

        if(endoffset > bsize)
        {
            this->log("Segment " + Utils::quoted(name) +
                      " is bigger than loaded file (" + Utils::hex(endoffset) + " vs " + Utils::hex(bsize) + ")");

            endoffset = bsize;
        }

        segment.offset = offset;
        segment.endoffset = endoffset;
    }

    segment.address = address;
    segment.endaddress = address + vsize;
    segment.flags = flags;
    std::copy_n(name.c_str(), len, reinterpret_cast<char*>(&segment.name));
    return m_addressspace.insert(segment);
}

void Document::setFunction(rd_address address, const std::string& label)
{
    m_functions.insert(address);
    this->setLabel(address, AddressFlags_Function, label.empty() ? Document::makeLabel(address, "sub") : label);
}

void Document::setBranch(rd_address address, int direction)
{
    if(!direction) this->setLabel(address, AddressFlags_Location, Document::makeLabel(address, "inf_loop"));
    else this->setLabel(address, AddressFlags_Location);
}

void Document::setLabel(rd_address address, rd_flag flags, const std::string& label) { m_addressspace.setLabel(address, label.empty() ? Document::makeLabel(address, "loc") : label, flags); }

void Document::setPointer(rd_address address, const std::string& label)
{
    this->setData(address, this->context()->addressWidth(), label.empty() ? Document::makeLabel(address, "ptr") : label);
    m_addressspace.updateFlags(address, AddressFlags_Pointer);
}

void Document::setExportedFunction(rd_address address, const std::string& label)
{
    this->setLabel(address, AddressFlags_Function | AddressFlags_Exported, label);
    this->setFunction(address, label);
}

void Document::setExported(rd_address address, size_t size, const std::string& label)
{
    this->setData(address, size, label);
    this->setLabel(address, AddressFlags_Exported, label);
}

void Document::setImported(rd_address address, size_t size, const std::string& label)
{
    this->setData(address, size, label);
    this->setLabel(address, AddressFlags_Imported, label);
}

void Document::setComments(rd_address address, const std::string& s) { m_addressspace.setComments(address, Utils::split(s, '\n')); }
void Document::addComment(rd_address address, const std::string& s) { m_addressspace.addComment(address, s); }

bool Document::createFunction(rd_address address, const std::string& label)
{
    if(!this->isAddress(address)) return false;
    this->context()->disassembler()->disassembleFunction(address);
    this->setFunction(address, label);
    return true;
}

bool Document::updateLabel(rd_address address, const std::string& s) { return m_addressspace.updateLabel(address, s); }

void Document::setEntry(rd_address address)
{
    auto foundlabel = this->getLabel(address);
    std::string label = foundlabel ? *foundlabel : RD_ENTRY_NAME; // Don't override symbol name, if exists

    this->setLabel(address, AddressFlags_Function | AddressFlags_Exported, label);
    this->setFunction(address, label);
    m_entry = { {address}, true };
}

void Document::setGraph(FunctionGraph* g) { m_functions.bind(g->startAddress(), g); }
const char16_t* Document::readWString(rd_address address, size_t* len) const { return this->readStringT<char16_t>(address, len); }
const char* Document::readString(rd_address address, size_t* len) const { return this->readStringT<char>(address, len); }
std::string Document::readWString(rd_address address, size_t len) const { const char16_t* s = this->readWString(address, &len); return s ? Utils::toString(std::u16string(s, len)) : std::string(); }

std::string Document::readString(rd_address address, size_t len) const
{
    const char* s = this->readString(address, &len);
    return s ? std::string(s, len) : std::string();
}

const AddressSpace* Document::addressSpace() const { return &m_addressspace; }
const BlockContainer* Document::getBlocks(rd_address address) const { return m_addressspace.getBlocks(address); }
RDLocation Document::getEntry() const { return m_entry; }
bool Document::pointerToSegment(const void* ptr, RDSegment* segment) const { return m_addressspace.pointerToSegment(ptr, segment); }
bool Document::addressToSegment(rd_address address, RDSegment* segment) const { return m_addressspace.addressToSegment(address, segment); }
bool Document::offsetToSegment(rd_address address, RDSegment* segment) const { return m_addressspace.offsetToSegment(address, segment); }
bool Document::addressToBlock(rd_address address, RDBlock* block) const { return m_addressspace.addressToBlock(address, block); }

bool Document::getBlockView(rd_address address, RDBufferView* view) const
{
    RDBlock b;
    if(!this->addressToBlock(address, &b)) return false;
    if(!this->getView(b.address, BlockContainer::size(&b), view)) return false;
    BufferView::advance(view, address - b.address); // Adjust view to requested address
    return true;
}

bool Document::getView(rd_address address, size_t size, RDBufferView* view) const
{
    RDLocation loc = this->offset(address);
    return loc.valid ? m_addressspace.offsetToView(loc.offset, size, view) : false;
}

const Type* Document::getTypeField(rd_address address, int* indent) const { return m_addressspace.getTypeField(address, indent); }
std::string Document::getComments(rd_address address) const { return Utils::join(m_addressspace.getComments(address), "\n"); }
rd_flag Document::getFlags(rd_address address) const { return m_addressspace.getFlags(address); }
size_t Document::getLabels(const rd_address** addresses) const { return m_addressspace.getLabels(addresses); }
size_t Document::getLabelsByFlag(rd_flag flag, const rd_address** addresses) const { return m_addressspace.getLabelsByFlag(flag, addresses); }
size_t Document::getSegments(const rd_address** addresses) const { return m_addressspace.data(addresses); }
size_t Document::getFunctions(const rd_address** addresses) const { return m_functions.data(addresses); }

size_t Document::getFunctionInstrCount(rd_address address) const
{
    auto* g = this->getGraph(address);
    return g ? g->blocksCount() : 0;
}

rd_address Document::getAddress(const std::string& label) const { return m_addressspace.getAddress(label); }
rd_address Document::firstAddress() const { return m_addressspace.firstAddress(); }
rd_address Document::lastAddress() const { return m_addressspace.lastAddress(); }
std::optional<std::string> Document::getLabel(rd_address address) const { return m_addressspace.getLabel(address); }
RDLocation Document::offset(rd_address address) const { return m_addressspace.offset(address); }
RDLocation Document::address(rd_offset offset) const { return m_addressspace.address(offset); }
RDLocation Document::addressof(const void* ptr) const { return m_addressspace.addressof(ptr); }

RDLocation Document::fileoffset(const void* ptr) const
{
    if(!m_buffer->contains(reinterpret_cast<const u8*>(ptr))) return { {0}, false };
    return { {static_cast<rd_location>(reinterpret_cast<const u8*>(ptr) - m_buffer->data())}, true };
}

u8* Document::filepointer(rd_offset offset) const { return (offset < m_buffer->size()) ? m_buffer->data() + offset : nullptr; }
u8* Document::addrpointer(rd_address address) const { return m_addressspace.addrpointer(address); }
u8* Document::offspointer(rd_offset offset) const { return m_addressspace.offspointer(offset); }
bool Document::isAddress(rd_address address) const { return this->addressToSegment(address, nullptr); }
bool Document::isBasicBlockTail(rd_address address) const { return m_functions.isBasicBlockTail(address); }
bool Document::setUnknown(rd_address address, size_t size) { return m_addressspace.markUnknown(address, size); }

bool Document::setData(rd_address address, size_t size, const std::string& label)
{
    if(!m_addressspace.markData(address, size)) return false;
    m_addressspace.setLabel(address, label.empty() ? Document::makeLabel(address, "data") : label, AddressFlags_Location);
    return true;
}

bool Document::setLocation(rd_address address) { return this->setData(address, this->context()->addressWidth(), Document::makeLabel(address, "loc")); }

bool Document::setString(rd_address address, size_t size, rd_flag flags, const std::string& label)
{
    if(!m_addressspace.markString(address, size)) return false;

    if(flags & AddressFlags_WideString)
        m_addressspace.setLabel(address, label.empty() ? Document::makeLabel(address, "wstr") : std::string(), AddressFlags_WideString);
    else
        m_addressspace.setLabel(address, label.empty() ? Document::makeLabel(address, "str") : label, AddressFlags_AsciiString);

    return true;
}

const Type* Document::getType(rd_address address) const { return m_addressspace.getType(address); }

bool Document::setTypeName(rd_address address, const std::string& q)
{
    RDDatabaseValue v;

    if(this->context()->database()->query(q, &v) && v.t && (v.type == DatabaseValueType_Type))
        return this->setType(address, CPTR(const Type, v.t));

    return false;
}

bool Document::setType(rd_address address, const Type* type) { return this->setTypeFields(address, type, 0); }
bool Document::findLabel(const std::string& q, rd_address* resaddress) const { return m_addressspace.findLabel(q, resaddress); }
bool Document::findLabelR(const std::string& q, rd_address* resaddress) const { return m_addressspace.findLabelR(q, resaddress); }
size_t Document::findLabels(const std::string& q, const rd_address** resaddresses) const { return m_addressspace.findLabels(q, resaddresses); }
size_t Document::findLabelsR(const std::string& q, const rd_address** resaddresses) const { return m_addressspace.findLabelsR(q, resaddresses); }

rd_address Document::checkLocation(rd_address fromaddress, rd_address address, size_t size)
{
    if(fromaddress == address) return RD_NVAL; // Ignore self references

    RDSegment segment;
    if(!this->addressToSegment(address, &segment)) return RD_NVAL;

    auto label = this->getLabel(address);

    if(label)
    {
        m_net.addRef(fromaddress, address);

        auto flag = this->getFlags(address);

        if(flag & AddressFlags_Pointer)
        {
            auto loc = this->dereferenceAddress(address);
            if(loc.valid) m_net.addRef(fromaddress, loc.address, ReferenceFlags_Indirect);
        }

        return address;
    }

    if(size == RD_NVAL) size = this->context()->addressWidth();

    rd_address resaddress = address;

    bool ok = this->checkPointer(fromaddress, address, size, &resaddress); // Is Pointer?
    if(!ok) ok = this->checkString(address, nullptr); // Is String?

    if(!ok && Utils::isPureCode(&segment)) // Is Code Reference?
    {
        this->setLocation(address);
        this->context()->disassembler()->enqueue(address); // Enqueue for analysis
    }
    else if(!ok) this->setData(address, size); // Data

    m_net.addRef(fromaddress, address);
    return resaddress;
}

void Document::checkTypeName(rd_address fromaddress, rd_address address, const char* q)
{
    if(!q || (fromaddress == address)) return; // Ignore self references

    RDSegment segment;
    if(!this->addressToSegment(address, &segment)) return;

    if(this->setTypeName(address, q))
        m_net.addRef(fromaddress, address);
}

void Document::checkType(rd_address fromaddress, rd_address address, const Type* t)
{
    if(!t || (fromaddress == address)) return; // Ignore self references

    RDSegment segment;
    if(!this->addressToSegment(address, &segment)) return;

    if(this->setType(address, t))
        m_net.addRef(fromaddress, address);
}

void Document::checkString(rd_address fromaddress, rd_address address, size_t size)
{
    RDBufferView view;
    if(!this->getView(address, size, &view)) return;

    size_t totalsize = 0;
    rd_flag flags = StringFinder::categorize(this->context(), view, &totalsize);
    if(flags == AddressFlags_None) flags = AddressFlags_AsciiString; // If invalid, force to Ascii String

    if(StringFinder::checkAndMark(this->context(), address, flags, size != RD_NVAL ? size : totalsize))
        m_net.addRef(fromaddress, address);
}

size_t Document::checkTable(rd_address fromaddress, rd_address address, size_t size, const Document::TableCallback& cb)
{
    auto loc = this->dereferenceAddress(address);
    size_t i = 0, w = this->context()->addressWidth();

    for( ; loc.valid && (i < size); i++, address += w, loc = this->dereferenceAddress(address))
    {
        this->setPointer(address);
        if(!i) m_net.addRef(fromaddress, address);

        m_net.addRef(address, loc.address);
        if(!cb(address, loc.address, i)) break;
    }

    return i;
}

bool Document::setTypeFields(rd_address address, const Type* type, int indent)
{
    if(!type) return false;

    if(auto* st = dynamic_cast<const StructureType*>(type))
    {
        m_addressspace.setType(address, st, indent ? std::string() : Document::makeLabel(address, st->name()));
        rd_address fieldaddress = address;

        for(const auto& [n, f] : st->fields())
        {
            this->setTypeFields(fieldaddress, f, indent + 1);

            auto loc = this->dereference(fieldaddress);
            if(loc.valid) this->checkLocation(fieldaddress, loc.address); // Check the pointed location...
            else this->checkLocation(address, fieldaddress);              // ...or just add a reference to the field

            if(!indent && (f == st->fields().back().second))
                m_addressspace.updateFlags(fieldaddress, AddressFlags_TypeEnd);

            fieldaddress += f->size();
        }
    }
    else if(auto* at = dynamic_cast<const ArrayType*>(type))
    {
        m_addressspace.setType(address, at);
        rd_address itemaddress = address;

        for(size_t i = 0; i < at->itemsCount(); i++)
        {
            this->setType(itemaddress, at->type());

            if(!indent && i == (at->itemsCount() - 1))
                m_addressspace.updateFlags(itemaddress, AddressFlags_TypeEnd);

            itemaddress += at->type()->size();
        }

    }
    else if(auto* st = dynamic_cast<const StringType*>(type))
    {
        TypePtr cst(st->clone(this->context()));
        static_cast<StringType*>(cst.get())->calculateSize(address);

        m_addressspace.setTypeField(address, cst.get(), indent); // Take copy

        switch(cst->type())
        {
            case Type_AsciiString:
                if(!this->setString(address, cst->size(), AddressFlags_AsciiString, cst->name())) return false;
                break;

            case Type_WideString:
                if(!this->setString(address, cst->size(), AddressFlags_WideString, cst->name())) return false;
                break;

            default: return false;
        }
    }
    else if(auto* nt = dynamic_cast<const NumericType*>(type))
        m_addressspace.setTypeField(address, nt, indent);
    else
        this->log("Unhandled type: " + Utils::quoted(type->typeName()));

    return true;
}

bool Document::readAddress(rd_address address, u64* value) const
{
    RDBufferView view;
    if(!this->getView(address, this->context()->addressWidth(), &view)) return false;

    switch(view.size)
    {
        case 1:  if(value) *value = *reinterpret_cast<u8*>(view.data);  break;
        case 2:  if(value) *value = *reinterpret_cast<u16*>(view.data); break;
        case 4:  if(value) *value = *reinterpret_cast<u32*>(view.data); break;
        case 8:  if(value) *value = *reinterpret_cast<u64*>(view.data); break;
        default: this->context()->problem("Invalid size: " + Utils::number(view.size)); return false;
    }

    return true;
}

RDLocation Document::dereferenceAddress(rd_address address) const
{
    u64 ptraddress;
    if(!this->readAddress(address, &ptraddress) || !this->isAddress(ptraddress)) return { };
    return { {ptraddress}, true };
}

bool Document::checkPointer(rd_address fromaddress, rd_address address, size_t size, rd_address* firstaddress)
{
    if(size != this->context()->addressWidth()) return false;

    return this->checkTable(fromaddress, address, RD_NVAL, [&](rd_address ptraddress, rd_address addr, size_t i) {
        if(!i) {
            if(firstaddress) *firstaddress = addr;
            m_net.addRef(fromaddress, addr, ReferenceFlags_Indirect);
        }

        this->checkLocation(ptraddress, addr, size);
        return true;
    });
}

FunctionGraph* Document::getGraph(rd_address address) const { return m_functions.getGraph(address); }
RDLocation Document::getFunctionStart(rd_address address) const { return m_functions.getFunction(address); }

RDLocation Document::dereference(rd_address address) const
{
    RDLocation loc;

    u64 ptrvalue = 0;
    loc.valid = this->readAddress(address, &ptrvalue);
    if(loc.valid) loc.address = static_cast<rd_address>(ptrvalue);
    return loc;
}

std::string Document::getHexDump(rd_address address, size_t size) const
{
    std::string hexdump;

    RDBufferView view;
    if(!this->getView(address, size, &view)) return std::string();

    hexdump = Utils::hexString(&view);
    return hexdump.c_str();
}

void Document::invalidateGraphs() { m_functions.invalidateGraphs(); }

size_t Document::checkString(rd_address address, rd_flag* resflags)
{
    RDBufferView view;
    if(!this->getView(address, RD_NVAL, &view)) return false;

    size_t totalsize = 0;
    rd_flag flags = StringFinder::categorize(this->context(), view, &totalsize);
    if(resflags) *resflags = flags;

    if(StringFinder::checkAndMark(this->context(), address, flags, totalsize)) return totalsize;
    return 0;
}

bool Document::setCode(rd_address address, size_t size) { return m_addressspace.markCode(address, size); }

std::string Document::makeLabel(rd_address address, const std::string& prefix)
{
    if(prefix.empty()) return "lbl_" + Utils::hex(address);
    return prefix + "_" + Utils::hex(address);
}
