#include "MintfixedContext.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstring>
#include <fstream>
#include <limits>
#include <map>
#include <memory>
#include <set>
#include <stdexcept>
#include <string_view>
#include <utility>

namespace bpc::mintfixed {
namespace {
constexpr std::size_t kMaxJsonBytes = 8 * 1024 * 1024;
constexpr std::size_t kMaxMods = 4096;
constexpr std::uint64_t kMaxArchiveBytes = 1024ull * 1024 * 1024;
constexpr std::uint64_t kMaxPakBytes = 512ull * 1024 * 1024;
constexpr std::size_t kMaxZipEntries = 16384;
constexpr std::size_t kMaxNestedPaks = 32;

std::string Lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

// Narrow JSON parser: validates the entire document, including escape sequences,
// rather than grepping strings that may appear in nested data or comments.
struct Value {
    enum Kind { Null, String, Number, Bool, Array, Object } kind = Null;
    std::string text;
    std::uint64_t number = 0;
    bool boolean = false;
    std::vector<Value> array;
    std::map<std::string, Value> object;
    const Value* Get(std::string_view key) const {
        const auto it = object.find(std::string(key));
        return it == object.end() ? nullptr : &it->second;
    }
};

class JsonParser {
    std::string_view s_;
    std::size_t pos_ = 0;
    static bool Hex(char c, unsigned& v) {
        if (c >= '0' && c <= '9') v = c - '0';
        else if (c >= 'a' && c <= 'f') v = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') v = c - 'A' + 10;
        else return false;
        return true;
    }
    void Skip() { while (pos_ < s_.size() && (s_[pos_] == ' ' || s_[pos_] == '\n' || s_[pos_] == '\t' || s_[pos_] == '\r')) ++pos_; }
    bool Take(char c) { Skip(); if (pos_ < s_.size() && s_[pos_] == c) { ++pos_; return true; } return false; }
    [[noreturn]] void Fail() const { throw std::runtime_error("invalid crash_context.json near byte " + std::to_string(pos_)); }
    unsigned Unicode() {
        if (pos_ + 4 > s_.size()) Fail();
        unsigned v = 0, x = 0;
        for (int i = 0; i < 4; ++i) { if (!Hex(s_[pos_++], x)) Fail(); v = (v << 4) | x; }
        return v;
    }
    static void Utf8(std::string& s, unsigned c) {
        if (c < 0x80) s.push_back(static_cast<char>(c));
        else if (c < 0x800) { s.push_back(static_cast<char>(0xC0 | (c >> 6))); s.push_back(static_cast<char>(0x80 | (c & 63))); }
        else if (c < 0x10000) { s.push_back(static_cast<char>(0xE0 | (c >> 12))); s.push_back(static_cast<char>(0x80 | ((c >> 6) & 63))); s.push_back(static_cast<char>(0x80 | (c & 63))); }
        else { s.push_back(static_cast<char>(0xF0 | (c >> 18))); s.push_back(static_cast<char>(0x80 | ((c >> 12) & 63))); s.push_back(static_cast<char>(0x80 | ((c >> 6) & 63))); s.push_back(static_cast<char>(0x80 | (c & 63))); }
    }
    std::string ParseString() {
        if (!Take('"')) Fail();
        std::string out;
        while (pos_ < s_.size()) {
            unsigned char c = static_cast<unsigned char>(s_[pos_++]);
            if (c == '"') return out;
            if (c < 32) Fail();
            if (c != '\\') { out.push_back(static_cast<char>(c)); continue; }
            if (pos_ >= s_.size()) Fail();
            char escaped = s_[pos_++];
            switch (escaped) {
            case '"': case '\\': case '/': out.push_back(escaped); break;
            case 'b': out.push_back('\b'); break;
            case 'f': out.push_back('\f'); break;
            case 'n': out.push_back('\n'); break;
            case 'r': out.push_back('\r'); break;
            case 't': out.push_back('\t'); break;
            case 'u': {
                unsigned code = Unicode();
                if (code >= 0xD800 && code <= 0xDBFF) {
                    if (pos_ + 2 > s_.size() || s_[pos_++] != '\\' || s_[pos_++] != 'u') Fail();
                    const unsigned low = Unicode();
                    if (low < 0xDC00 || low > 0xDFFF) Fail();
                    code = 0x10000 + ((code - 0xD800) << 10) + (low - 0xDC00);
                } else if (code >= 0xDC00 && code <= 0xDFFF) Fail();
                Utf8(out, code); break;
            }
            default: Fail();
            }
            if (out.size() > kMaxJsonBytes) Fail();
        }
        Fail();
    }
    Value ParseValue(unsigned depth) {
        if (depth > 24) Fail();
        Skip(); if (pos_ >= s_.size()) Fail();
        Value v;
        const char c = s_[pos_];
        if (c == '"') { v.kind = Value::String; v.text = ParseString(); }
        else if (c == '{') {
            v.kind = Value::Object; ++pos_; if (Take('}')) return v;
            do {
                if (v.object.size() >= 128) Fail();
                std::string key = ParseString();
                if (!Take(':')) Fail();
                auto value = ParseValue(depth + 1);
                if (!v.object.emplace(std::move(key), std::move(value)).second) Fail();
            } while (Take(','));
            if (!Take('}')) Fail();
        } else if (c == '[') {
            v.kind = Value::Array; ++pos_; if (Take(']')) return v;
            do { if (v.array.size() >= kMaxMods + 1) Fail(); v.array.push_back(ParseValue(depth + 1)); } while (Take(','));
            if (!Take(']')) Fail();
        } else if (s_.substr(pos_, 4) == "true") { pos_ += 4; v.kind = Value::Bool; v.boolean = true; }
        else if (s_.substr(pos_, 5) == "false") { pos_ += 5; v.kind = Value::Bool; }
        else if (s_.substr(pos_, 4) == "null") { pos_ += 4; v.kind = Value::Null; }
        else if (c >= '0' && c <= '9') {
            v.kind = Value::Number;
            do {
                unsigned digit = s_[pos_++] - '0';
                if (v.number > (std::numeric_limits<std::uint64_t>::max() - digit) / 10) Fail();
                v.number = v.number * 10 + digit;
            } while (pos_ < s_.size() && s_[pos_] >= '0' && s_[pos_] <= '9');
        } else Fail();
        return v;
    }
public:
    explicit JsonParser(std::string_view s) : s_(s) {}
    Value Parse() { auto v = ParseValue(0); Skip(); if (pos_ != s_.size()) Fail(); return v; }
};

const Value& Required(const Value& v, std::string_view key, Value::Kind kind) {
    const auto* x = v.Get(key);
    if (!x || x->kind != kind) throw std::runtime_error("missing or invalid field: " + std::string(key));
    return *x;
}
std::string OptionalString(const Value& v, std::string_view key) {
    const auto* x = v.Get(key);
    return x && x->kind == Value::String ? x->text : "";
}
Archive ParseArchive(const Value& v) {
    Archive archive;
    const auto str = Required(v, "path", Value::String).text;
    if (str.empty() || str.find('\0') != std::string::npos) throw std::runtime_error("invalid archive path");
    archive.path = fs::u8path(str);
    archive.exists = Required(v, "exists", Value::Bool).boolean;
    archive.byteSize = Required(v, "byte_size", Value::Number).number;
    return archive;
}
std::uint16_t U16(const unsigned char* p) { return std::uint16_t(p[0]) | (std::uint16_t(p[1]) << 8); }
std::uint32_t U32(const unsigned char* p) { return std::uint32_t(U16(p)) | (std::uint32_t(U16(p + 2)) << 16); }
bool Read(std::ifstream& in, std::uint64_t at, void* ptr, std::size_t n) {
    in.clear(); in.seekg(static_cast<std::streamoff>(at));
    in.read(static_cast<char*>(ptr), static_cast<std::streamsize>(n));
    return !!in;
}
std::uint32_t Crc32(const std::vector<unsigned char>& data) {
    static const auto table = [] {
        std::array<std::uint32_t, 256> t{};
        for (unsigned i = 0; i < 256; ++i) {
            std::uint32_t c = i;
            for (int k = 0; k < 8; ++k) c = (c >> 1) ^ (0xEDB88320u & (0u - (c & 1u)));
            t[i] = c;
        }
        return t;
    }();
    std::uint32_t crc = ~std::uint32_t(0);
    for (const auto b : data) crc = (crc >> 8) ^ table[(crc ^ b) & 255];
    return ~crc;
}

// Small self-contained RFC1951 raw DEFLATE decoder: only used after process exit,
// bounded by the ZIP central directory's declared size, never inside the handler DLL.
class Bits {
    const std::vector<unsigned char>& bytes_;
    std::size_t pos_ = 0;
    std::uint32_t bits_ = 0;
    unsigned available_ = 0;
public:
    explicit Bits(const std::vector<unsigned char>& data) : bytes_(data) {}
    unsigned Get(unsigned count) {
        if (count > 16) throw std::runtime_error("invalid DEFLATE bit count");
        while (available_ < count) {
            if (pos_ >= bytes_.size()) throw std::runtime_error("truncated DEFLATE stream");
            bits_ |= std::uint32_t(bytes_[pos_++]) << available_;
            available_ += 8;
        }
        const unsigned ret = bits_ & ((1u << count) - 1);
        bits_ >>= count; available_ -= count; return ret;
    }
    void Align() { (void)Get(available_ % 8); }
};

struct Huffman {
    std::array<std::vector<int>, 16> table;
    int maximum = 0;
    void Build(const std::vector<unsigned>& lengths) {
        std::array<int, 16> counts{}, next{};
        for (unsigned n : lengths) { if (n > 15) throw std::runtime_error("invalid Huffman code length"); if (n) { ++counts[n]; maximum = std::max(maximum, int(n)); } }
        int code = 0;
        for (int len = 1; len <= 15; ++len) { code = (code + counts[len - 1]) << 1; next[len] = code; if (code + counts[len] > (1 << len)) throw std::runtime_error("oversubscribed Huffman tree"); }
        for (int len = 1; len <= maximum; ++len) if (counts[len]) table[len].assign(1u << len, -1);
        for (std::size_t i = 0; i < lengths.size(); ++i) if (const auto len = lengths[i]) table[len][next[len]++] = static_cast<int>(i);
    }
    int Decode(Bits& bits) const {
        unsigned code = 0;
        for (int len = 1; len <= maximum; ++len) {
            code = (code << 1) | bits.Get(1);
            if (!table[len].empty() && table[len][code] >= 0) return table[len][code];
        }
        throw std::runtime_error("invalid Huffman symbol");
    }
};

std::vector<unsigned char> Inflate(const std::vector<unsigned char>& compressed, std::size_t expected) {
    static constexpr int lenBase[] = {3,4,5,6,7,8,9,10,11,13,15,17,19,23,27,31,35,43,51,59,67,83,99,115,131,163,195,227,258};
    static constexpr int lenExtra[] = {0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0};
    static constexpr int distBase[] = {1,2,3,4,5,7,9,13,17,25,33,49,65,97,129,193,257,385,513,769,1025,1537,2049,3073,4097,6145,8193,12289,16385,24577};
    static constexpr int distExtra[] = {0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13};
    static constexpr unsigned order[] = {16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15};
    Bits bits(compressed);
    std::vector<unsigned char> out;
    out.reserve(expected);
    bool final = false;
    while (!final) {
        final = bits.Get(1) != 0;
        const unsigned type = bits.Get(2);
        if (type == 0) {
            bits.Align(); const unsigned n = bits.Get(16), inverse = bits.Get(16);
            if ((n ^ inverse) != 0xFFFFu || n > expected - out.size()) throw std::runtime_error("invalid stored DEFLATE block");
            for (unsigned i = 0; i < n; ++i) out.push_back(static_cast<unsigned char>(bits.Get(8)));
            continue;
        }
        Huffman literal, distance;
        if (type == 1) {
            std::vector<unsigned> lengths(288), dists(32, 5);
            for (unsigned i = 0; i < 288; ++i) lengths[i] = i <= 143 ? 8 : i <= 255 ? 9 : i <= 279 ? 7 : 8;
            literal.Build(lengths); distance.Build(dists);
        } else if (type == 2) {
            const unsigned hlit = bits.Get(5) + 257, hdist = bits.Get(5) + 1, hclen = bits.Get(4) + 4;
            if (hlit > 286 || hdist > 32) throw std::runtime_error("invalid dynamic DEFLATE header");
            std::vector<unsigned> clen(19);
            for (unsigned i = 0; i < hclen; ++i) clen[order[i]] = bits.Get(3);
            Huffman codeLengths; codeLengths.Build(clen);
            std::vector<unsigned> lengths;
            while (lengths.size() < hlit + hdist) {
                const int sym = codeLengths.Decode(bits);
                if (sym < 16) lengths.push_back(static_cast<unsigned>(sym));
                else {
                    unsigned value = 0, repeat = 0;
                    if (sym == 16) { if (lengths.empty()) throw std::runtime_error("invalid repeat"); value = lengths.back(); repeat = bits.Get(2) + 3; }
                    else if (sym == 17) repeat = bits.Get(3) + 3;
                    else if (sym == 18) repeat = bits.Get(7) + 11;
                    else throw std::runtime_error("invalid code length symbol");
                    if (repeat > hlit + hdist - lengths.size()) throw std::runtime_error("invalid code length repeat");
                    lengths.insert(lengths.end(), repeat, value);
                }
            }
            if (!lengths[256]) throw std::runtime_error("missing end-of-block symbol");
            literal.Build(std::vector<unsigned>(lengths.begin(), lengths.begin() + hlit));
            distance.Build(std::vector<unsigned>(lengths.begin() + hlit, lengths.end()));
        } else throw std::runtime_error("reserved DEFLATE block type");
        while (true) {
            const int symbol = literal.Decode(bits);
            if (symbol == 256) break;
            if (symbol < 256) {
                if (out.size() >= expected) throw std::runtime_error("DEFLATE output exceeds ZIP header");
                out.push_back(static_cast<unsigned char>(symbol));
                continue;
            }
            if (symbol < 257 || symbol > 285) throw std::runtime_error("invalid length symbol");
            const unsigned idx = symbol - 257;
            const unsigned length = lenBase[idx] + bits.Get(lenExtra[idx]);
            const int distSymbol = distance.Decode(bits);
            if (distSymbol < 0 || distSymbol >= 30) throw std::runtime_error("invalid distance symbol");
            const unsigned delta = distBase[distSymbol] + bits.Get(distExtra[distSymbol]);
            if (delta > out.size() || length > expected - out.size()) throw std::runtime_error("invalid DEFLATE backreference");
            for (unsigned i = 0; i < length; ++i) out.push_back(out[out.size() - delta]);
        }
    }
    if (out.size() != expected) throw std::runtime_error("DEFLATE output does not match ZIP header");
    return out;
}
} // namespace

LoadedContext Load(const fs::path& gameExe) {
    LoadedContext result;
    // Do not trust an arbitrary bpcrash.cfg to select another user's context.
    if (Lower(gameExe.parent_path().parent_path().filename().string()) != "binaries") return result;
    result.source = gameExe.parent_path() / "mintfixed-bpcrash" / "crash_context.json";
    std::error_code ec;
    if (!fs::is_regular_file(result.source, ec)) return result;
    result.present = true;
    const auto size = fs::file_size(result.source, ec);
    if (ec || size > kMaxJsonBytes) { result.error = "context exceeds 8 MiB or cannot be read"; return result; }
    try {
        std::ifstream in(result.source, std::ios::binary);
        if (!in) throw std::runtime_error("cannot read manifest");
        std::string body((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        auto json = JsonParser(body).Parse();
        if (json.kind != Value::Object || Required(json, "schema_version", Value::Number).number != 1 ||
            Required(json, "producer", Value::String).text != "mintfixed" ||
            !Required(json, "captured_after_successful_install", Value::Bool).boolean)
            throw std::runtime_error("unsupported or incomplete mintfixed context schema");
        result.context.generatedUnixMs = Required(json, "generated_unix_ms", Value::Number).number;
        result.context.installedPak = ParseArchive(Required(json, "installed_pak", Value::Object));
        const auto& mods = Required(json, "installed_mods", Value::Array).array;
        if (mods.size() > kMaxMods) throw std::runtime_error("too many installed mods");
        std::set<std::uint64_t> seenOrder;
        for (const auto& modValue : mods) {
            if (modValue.kind != Value::Object) throw std::runtime_error("invalid mod entry");
            Mod mod;
            mod.name = Required(modValue, "name", Value::String).text;
            if (mod.name.empty()) throw std::runtime_error("empty mod name");
            mod.provider = Required(modValue, "provider", Value::String).text;
            mod.integrationOrder = Required(modValue, "integration_order", Value::Number).number;
            if (!seenOrder.insert(mod.integrationOrder).second) throw std::runtime_error("duplicate integration order");
            mod.archive = ParseArchive(Required(modValue, "archive", Value::Object));
            mod.archiveType = Required(modValue, "archive_type", Value::String).text;
            mod.sha256 = OptionalString(modValue, "archive_sha256");
            mod.modioReference = OptionalString(modValue, "modio_reference");
            mod.nestedPaksMustBeScanned = Required(modValue, "nested_paks_must_be_scanned", Value::Bool).boolean;
            result.context.installedMods.push_back(std::move(mod));
        }
        std::sort(result.context.installedMods.begin(), result.context.installedMods.end(),
                  [](const Mod& a, const Mod& b) { return a.integrationOrder < b.integrationOrder; });
        result.valid = true;
    } catch (const std::exception& e) { result.error = e.what(); }
    return result;
}

ZipStats VisitZipPaks(const fs::path& archive,
    const std::function<void(const std::string&, const std::vector<unsigned char>&)>& visitor) {
    ZipStats stats;
    std::ifstream zip(archive, std::ios::binary);
    if (!zip) { stats.warning = "cannot open ZIP archive"; return stats; }
    zip.seekg(0, std::ios::end);
    const auto endPos = zip.tellg();
    if (endPos < 0) { stats.warning = "cannot determine ZIP size"; return stats; }
    const auto zipSize = static_cast<std::uint64_t>(endPos);
    if (zipSize < 22 || zipSize > kMaxArchiveBytes) { stats.warning = "ZIP archive size outside supported range"; return stats; }
    const std::size_t tailSize = static_cast<std::size_t>(std::min<std::uint64_t>(zipSize, 65557));
    std::vector<unsigned char> tail(tailSize);
    if (!Read(zip, zipSize - tailSize, tail.data(), tail.size())) { stats.warning = "cannot read ZIP footer"; return stats; }
    std::size_t at = tail.size() - 22;
    bool foundFooter = false;
    for (;;) {
        if (U32(tail.data() + at) == 0x06054B50u &&
            at + 22 + U16(tail.data() + at + 20) == tail.size()) { foundFooter = true; break; }
        if (at == 0) break;
        --at;
    }
    if (!foundFooter) { stats.warning = "ZIP footer not found"; return stats; }
    const auto* eocd = tail.data() + at;
    const unsigned count = U16(eocd + 10);
    const std::uint64_t centralSize = U32(eocd + 12);
    const std::uint64_t centralAt = U32(eocd + 16);
    if (U16(eocd + 4) || U16(eocd + 6) || U16(eocd + 8) != count ||
        count > kMaxZipEntries || count == 0xFFFF || centralSize > 16 * 1024 * 1024 ||
        centralAt + centralSize > zipSize || centralAt == 0xFFFFFFFFu) {
        stats.warning = "unsupported multi-disk, ZIP64, or oversized directory"; return stats;
    }
    std::vector<unsigned char> central(static_cast<std::size_t>(centralSize));
    if (!Read(zip, centralAt, central.data(), central.size())) { stats.warning = "cannot read central directory"; return stats; }
    std::size_t p = 0;
    for (unsigned i = 0; i < count; ++i) {
        if (p + 46 > central.size() || U32(central.data() + p) != 0x02014B50u) {
            stats.warning = "invalid ZIP central directory"; break;
        }
        const auto* h = central.data() + p;
        const unsigned flags = U16(h + 8), method = U16(h + 10);
        const std::uint32_t crc = U32(h + 16), compressed = U32(h + 20), uncompressed = U32(h + 24);
        const unsigned nameLen = U16(h + 28), extraLen = U16(h + 30), commentLen = U16(h + 32);
        const std::uint64_t localAt = U32(h + 42);
        if (p + 46ull + nameLen + extraLen + commentLen > central.size()) { stats.warning = "truncated ZIP directory entry"; break; }
        std::string name(reinterpret_cast<const char*>(h + 46), nameLen);
        p += 46u + nameLen + extraLen + commentLen;
        std::replace(name.begin(), name.end(), '\\', '/');
        const auto dot = name.find_last_of('.');
        if (dot == std::string::npos || Lower(name.substr(dot)) != ".pak") continue;
        ++stats.pakEntries;
        if (stats.pakEntries > kMaxNestedPaks || (flags & 1) || (method != 0 && method != 8) ||
            compressed > kMaxPakBytes || uncompressed > kMaxPakBytes || localAt == 0xFFFFFFFFu ||
            (compressed && uncompressed > 200ull * compressed + 4ull * 1024 * 1024)) {
            ++stats.skipped; continue;
        }
        std::array<unsigned char, 30> local{};
        if (localAt + local.size() > zipSize || !Read(zip, localAt, local.data(), local.size()) ||
            U32(local.data()) != 0x04034B50u || U16(local.data() + 8) != method) { ++stats.skipped; continue; }
        const std::uint64_t dataAt = localAt + local.size() + U16(local.data() + 26) + U16(local.data() + 28);
        if (dataAt + compressed > zipSize) { ++stats.skipped; continue; }
        std::vector<unsigned char> packed(compressed);
        if (compressed && !Read(zip, dataAt, packed.data(), packed.size())) { ++stats.skipped; continue; }
        try {
            auto bytes = method == 0 ? std::move(packed) : Inflate(packed, uncompressed);
            if (bytes.size() != uncompressed || Crc32(bytes) != crc) { ++stats.skipped; continue; }
            visitor(name, bytes);
            ++stats.decoded;
        } catch (const std::exception&) { ++stats.skipped; }
    }
    if (stats.skipped && stats.warning.empty()) stats.warning = "some nested PAK entries are unsupported, corrupt, or exceed scan limits";
    return stats;
}
} // namespace bpc::mintfixed
