#include "tlv.h"

#include <array>
#include <cstring>
#include <limits>
#include <new>
#include <vector>

namespace tlv {
namespace {
using byte = std::uint8_t;
constexpr std::size_t header_size = 6;

// 本地成员用 memcpy 读写，码流用固定宽度小端；不要求成员自然对齐。
template<class T> T load(const byte* source) {
    T value;
    std::memcpy(&value, source, sizeof(value));
    return value;
}
template<class T> void store(byte* destination, T value) {
    std::memcpy(destination, &value, sizeof(value));
}
template<std::unsigned_integral T> T read_le(const byte* source) {
    T value = 0;
    for (std::size_t i = 0; i < sizeof(T); ++i)
        value = static_cast<T>(value | (static_cast<T>(source[i]) << (i * 8)));
    return value;
}
template<std::unsigned_integral T> void write_le(byte* destination, T value) {
    for (std::size_t i = 0; i < sizeof(T); ++i)
        destination[i] = static_cast<byte>(value >> (i * 8));
}

// 游标只借用缓冲区；嵌套消息先写 length 占位，成功后回填。
class writer {
    std::span<byte> buffer_;
    std::size_t offset_ = 0;
public:
    explicit writer(std::span<byte> buffer) : buffer_(buffer) {}
    std::size_t offset() const { return offset_; }
    template<std::unsigned_integral T> result<void> put(T value) {
        if (sizeof(T) > buffer_.size() - offset_)
            return std::unexpected(CODEC_BUFFER_TOO_SMALL);
        write_le(buffer_.data() + offset_, value);
        offset_ += sizeof(T);
        return {};
    }
    result<void> put(std::span<const byte> bytes) {
        if (bytes.size() > buffer_.size() - offset_)
            return std::unexpected(CODEC_BUFFER_TOO_SMALL);
        if (!bytes.empty()) std::memcpy(buffer_.data() + offset_, bytes.data(), bytes.size());
        offset_ += bytes.size();
        return {};
    }
    void patch_length(std::size_t offset, std::uint32_t length) {
        write_le(buffer_.data() + offset, length);
    }
};

struct item {
    std::uint16_t tag;
    std::span<const byte> value;
};
class reader {
    std::span<const byte> remaining_;
public:
    explicit reader(std::span<const byte> input) : remaining_(input) {}
    bool empty() const { return remaining_.empty(); }
    result<item> next() {
        if (remaining_.size() < header_size) return std::unexpected(CODEC_TRUNCATED_HEADER);
        const auto tag = read_le<std::uint16_t>(remaining_.data());
        const auto length = read_le<std::uint32_t>(remaining_.data() + 2);
        if (length > remaining_.size() - header_size)
            return std::unexpected(CODEC_TRUNCATED_VALUE);
        const item current{tag, remaining_.subspan(header_size, length)};
        remaining_ = remaining_.subspan(header_size + length);
        return current;
    }
};

// count、choice、整数 presence 共用本地无符号成员访问逻辑。
template<class F> auto dispatch_uint(tlv_value_type_t type, F&& visit)
    -> decltype(visit.template operator()<std::uint8_t>()) {
    switch (type) {
        case TLV_VALUE_UINT8: return visit.template operator()<std::uint8_t>();
        case TLV_VALUE_UINT16: return visit.template operator()<std::uint16_t>();
        case TLV_VALUE_UINT32: return visit.template operator()<std::uint32_t>();
        case TLV_VALUE_UINT64: return visit.template operator()<std::uint64_t>();
        default: return std::unexpected(CODEC_INVALID_SCHEMA);
    }
}
result<std::uint64_t> read_member(const byte* object, std::size_t offset, tlv_value_type_t type) {
    return dispatch_uint(type, [&]<class T>() -> result<std::uint64_t> {
        return load<T>(object + offset);
    });
}
result<void> write_member(byte* object, std::size_t offset, tlv_value_type_t type, std::uint64_t value) {
    return dispatch_uint(type, [&]<class T>() -> result<void> {
        if (value > std::numeric_limits<T>::max()) return std::unexpected(CODEC_OVERFLOW);
        store(object + offset, static_cast<T>(value));
        return {};
    });
}
result<std::size_t> read_count(const tlv_array_schema_t& array, const byte* object) {
    auto count = read_member(object, array.count_offset, array.count_type);
    if (!count) return std::unexpected(count.error());
    if (*count > SIZE_MAX) return std::unexpected(CODEC_OVERFLOW);
    return static_cast<std::size_t>(*count);
}
result<bool> active(const tlv_field_schema_t& field, const byte* object) {
    if (const auto* presence = field.present_schema) {
        if (presence->type == TLV_VALUE_BOOL) {
            if (!load<bool>(object + presence->offset)) return false;
        } else {
            auto flags = read_member(object, presence->offset, presence->type);
            if (!flags) return std::unexpected(flags.error());
            if ((*flags & presence->mask) == 0) return false;
        }
    }
    // presence 优先：缺失字段不读取 choice、count 或实际值。
    if (const auto* branch = field.union_schema) {
        auto choice = read_member(object, branch->choice_offset, branch->choice_type);
        if (!choice) return std::unexpected(choice.error());
        return *choice == branch->choice_value;
    }
    return true;
}
result<void> mark_present(const tlv_present_schema_t& presence, byte* object) {
    if (presence.type == TLV_VALUE_BOOL) {
        store(object + presence.offset, true);
        return {};
    }
    auto flags = read_member(object, presence.offset, presence.type);
    if (!flags) return std::unexpected(flags.error());
    return write_member(object, presence.offset, presence.type, *flags | presence.mask);
}

// 元素步长来自本地类型；BOOL 的本地大小与单字节码流大小分开处理。
result<std::size_t> element_size(const tlv_field_schema_t& field) {
    switch (field.type) {
        case TLV_VALUE_INT8: case TLV_VALUE_UINT8: return sizeof(std::uint8_t);
        case TLV_VALUE_INT16: case TLV_VALUE_UINT16: return sizeof(std::uint16_t);
        case TLV_VALUE_INT32: case TLV_VALUE_UINT32: return sizeof(std::uint32_t);
        case TLV_VALUE_INT64: case TLV_VALUE_UINT64: return sizeof(std::uint64_t);
        case TLV_VALUE_BOOL: return sizeof(bool);
        case TLV_VALUE_STRING: return field.string_capacity;
        case TLV_VALUE_MESSAGE:
            if (!field.nested_schema) return std::unexpected(CODEC_INVALID_SCHEMA);
            return field.nested_schema->struct_size;
        default: return std::unexpected(CODEC_INVALID_SCHEMA);
    }
}
result<std::size_t> element_offset(const tlv_field_schema_t& field, std::size_t index) {
    auto size = element_size(field);
    if (!size) return std::unexpected(size.error());
    if (index != 0 && *size > SIZE_MAX / index) return std::unexpected(CODEC_OVERFLOW);
    const auto relative = index * *size;
    if (relative > SIZE_MAX - field.offset) return std::unexpected(CODEC_OVERFLOW);
    return field.offset + relative;
}
result<std::size_t> field_count(const tlv_field_schema_t& field, const byte* object) {
    if (!field.array_schema) return 1;
    auto count = read_count(*field.array_schema, object);
    if (!count) return std::unexpected(count.error());
    if (*count > field.array_schema->capacity) return std::unexpected(CODEC_INVALID_COUNT);
    return count;
}

result<std::size_t> measure(const tlv_message_schema_t& schema, const byte* object);
result<void> encode_message(const tlv_message_schema_t& schema, const byte* object, writer& output);
result<void> decode_message(const tlv_message_schema_t& schema, std::span<const byte> input, byte* object);

result<std::size_t> value_size(const tlv_field_schema_t& field, const byte* value) {
    switch (field.type) {
        case TLV_VALUE_INT8: case TLV_VALUE_UINT8: case TLV_VALUE_BOOL: return 1;
        case TLV_VALUE_INT16: case TLV_VALUE_UINT16: return 2;
        case TLV_VALUE_INT32: case TLV_VALUE_UINT32: return 4;
        case TLV_VALUE_INT64: case TLV_VALUE_UINT64: return 8;
        case TLV_VALUE_STRING:
            if (field.string_capacity == 0) return std::unexpected(CODEC_INVALID_VALUE);
            for (std::size_t i = 0; i < field.string_capacity; ++i)
                if (value[i] == 0) return i;
            return std::unexpected(CODEC_STRING_NOT_TERMINATED);
        case TLV_VALUE_MESSAGE:
            if (!field.nested_schema) return std::unexpected(CODEC_INVALID_SCHEMA);
            return measure(*field.nested_schema, value);
        default: return std::unexpected(CODEC_INVALID_VALUE);
    }
}
result<std::size_t> measure(const tlv_message_schema_t& schema, const byte* object) {
    std::size_t total = 0;
    for (const auto& field : std::span(schema.fields, schema.field_count)) {
        auto enabled = active(field, object);
        if (!enabled) return std::unexpected(enabled.error());
        if (!*enabled) continue;
        auto count = field_count(field, object);
        if (!count) return std::unexpected(count.error());
        for (std::size_t i = 0; i < *count; ++i) {
            auto offset = element_offset(field, i);
            if (!offset) return std::unexpected(offset.error());
            auto size = value_size(field, object + *offset);
            if (!size) return std::unexpected(size.error());
            if (*size > UINT32_MAX || header_size > SIZE_MAX - total)
                return std::unexpected(CODEC_OVERFLOW);
            total += header_size;
            if (*size > SIZE_MAX - total) return std::unexpected(CODEC_OVERFLOW);
            total += *size;
        }
    }
    return total;
}

// 有符号整数按相同宽度的原始位表示读写，不做宿主字节序假设。
template<class F> auto dispatch_scalar(tlv_value_type_t type, F&& visit)
    -> decltype(visit.template operator()<std::uint8_t>()) {
    switch (type) {
        case TLV_VALUE_INT8: case TLV_VALUE_UINT8: return visit.template operator()<std::uint8_t>();
        case TLV_VALUE_INT16: case TLV_VALUE_UINT16: return visit.template operator()<std::uint16_t>();
        case TLV_VALUE_INT32: case TLV_VALUE_UINT32: return visit.template operator()<std::uint32_t>();
        case TLV_VALUE_INT64: case TLV_VALUE_UINT64: return visit.template operator()<std::uint64_t>();
        default: return std::unexpected(CODEC_INVALID_SCHEMA);
    }
}
result<void> encode_value(const tlv_field_schema_t& field, const byte* value,
    std::size_t length, writer& output) {
    if (field.type == TLV_VALUE_BOOL)
        return output.put(static_cast<byte>(load<bool>(value) ? 1 : 0));
    if (field.type == TLV_VALUE_STRING) return output.put(std::span(value, length));
    return dispatch_scalar(field.type, [&]<class T>() { return output.put(load<T>(value)); });
}
result<void> encode_message(const tlv_message_schema_t& schema, const byte* object, writer& output) {
    for (const auto& field : std::span(schema.fields, schema.field_count)) {
        auto enabled = active(field, object);
        if (!enabled) return std::unexpected(enabled.error());
        if (!*enabled) continue;
        auto count = field_count(field, object);
        if (!count) return std::unexpected(count.error());
        for (std::size_t i = 0; i < *count; ++i) {
            auto offset = element_offset(field, i);
            if (!offset) return std::unexpected(offset.error());
            const auto* value = object + *offset;
            if (field.type == TLV_VALUE_MESSAGE) {
                if (auto status = output.put(field.tag); !status) return status;
                const auto length_offset = output.offset();
                if (auto status = output.put(std::uint32_t{0}); !status) return status;
                const auto start = output.offset();
                if (auto status = encode_message(*field.nested_schema, value, output); !status) return status;
                const auto length = output.offset() - start;
                if (length > UINT32_MAX) return std::unexpected(CODEC_OVERFLOW);
                output.patch_length(length_offset, static_cast<std::uint32_t>(length));
            } else {
                auto length = value_size(field, value);
                if (!length) return std::unexpected(length.error());
                if (*length > UINT32_MAX) return std::unexpected(CODEC_OVERFLOW);
                if (auto status = output.put(field.tag); !status) return status;
                if (auto status = output.put(static_cast<std::uint32_t>(*length)); !status) return status;
                if (auto status = encode_value(field, value, *length, output); !status) return status;
            }
        }
    }
    return {};
}

result<void> decode_value(const tlv_field_schema_t& field, std::span<const byte> bytes, byte* destination) {
    switch (field.type) {
        case TLV_VALUE_BOOL:
            if (bytes.size() != 1) return std::unexpected(CODEC_FIELD_LENGTH_MISMATCH);
            if (bytes[0] > 1) return std::unexpected(CODEC_INVALID_BOOL);
            store(destination, bytes[0] != 0);
            return {};
        case TLV_VALUE_STRING:
            if (bytes.size() >= field.string_capacity)
                return std::unexpected(CODEC_STRING_CAPACITY_EXCEEDED);
            if (!bytes.empty()) {
                if (std::memchr(bytes.data(), 0, bytes.size())) return std::unexpected(CODEC_STRING_CONTAINS_NUL);
                std::memcpy(destination, bytes.data(), bytes.size());
            }
            destination[bytes.size()] = 0;
            return {};
        case TLV_VALUE_MESSAGE:
            if (!field.nested_schema) return std::unexpected(CODEC_INVALID_SCHEMA);
            return decode_message(*field.nested_schema, bytes, destination);
        default:
            return dispatch_scalar(field.type, [&]<class T>() -> result<void> {
                if (bytes.size() != sizeof(T)) return std::unexpected(CODEC_FIELD_LENGTH_MISMATCH);
                store(destination, read_le<T>(bytes.data()));
                return {};
            });
    }
}
result<void> decode_field(const tlv_field_schema_t& field, std::span<const byte> bytes, byte* object) {
    if (!field.array_schema) return decode_value(field, bytes, object + field.offset);
    const auto& array = *field.array_schema;
    auto count = read_count(array, object);
    if (!count) return std::unexpected(count.error());
    if (*count >= array.capacity) return std::unexpected(CODEC_ARRAY_CAPACITY_EXCEEDED);
    auto offset = element_offset(field, *count);
    if (!offset) return std::unexpected(offset.error());
    if (auto status = decode_value(field, bytes, object + *offset); !status) return status;
    return write_member(object, array.count_offset, array.count_type, *count + 1);
}

// 去重表每层独立，256 字段内使用栈，更多字段才分配堆内存。
class seen_fields {
    std::array<byte, 32> local_{};
    std::vector<byte> heap_;
    std::span<byte> bits_;
public:
    explicit seen_fields(std::size_t count) {
        const auto size = count / 8 + (count % 8 != 0);
        if (size <= local_.size()) bits_ = local_;
        else {
            heap_.resize(size);
            bits_ = heap_;
        }
    }
    bool contains(std::size_t index) const { return (bits_[index / 8] & (1u << (index % 8))) != 0; }
    void mark(std::size_t index) { bits_[index / 8] |= static_cast<byte>(1u << (index % 8)); }
};
bool same_choice(const tlv_field_schema_t& left, const tlv_field_schema_t& right) {
    return left.union_schema && right.union_schema
        && left.union_schema->choice_offset == right.union_schema->choice_offset
        && left.union_schema->choice_type == right.union_schema->choice_type;
}
result<void> decode_message(const tlv_message_schema_t& schema, std::span<const byte> input, byte* object) {
    seen_fields seen(schema.field_count);
    const auto fields = std::span(schema.fields, schema.field_count);
    reader source(input);
    while (!source.empty()) {
        auto current = source.next();
        if (!current) return std::unexpected(current.error());
        std::size_t index = 0;
        while (index < fields.size() && fields[index].tag != current->tag) ++index;
        if (index == fields.size()) continue;
        const auto& field = fields[index];
        if (!field.array_schema && seen.contains(index)) return std::unexpected(CODEC_DUPLICATE_FIELD);
        if (field.union_schema) {
            for (std::size_t other = 0; other < fields.size(); ++other)
                if (other != index && seen.contains(other) && same_choice(field, fields[other]))
                    return std::unexpected(CODEC_UNION_CONFLICT);
        }
        if (auto status = decode_field(field, current->value, object); !status) return status;
        // 更新顺序与 C 版一致：值/count、presence、choice，最后记录出现状态。
        if (field.present_schema) {
            if (auto status = mark_present(*field.present_schema, object); !status) return status;
        }
        if (const auto* branch = field.union_schema) {
            if (auto status = write_member(object, branch->choice_offset, branch->choice_type,
                branch->choice_value); !status) return status;
        }
        if (!field.array_schema) seen.mark(index);
    }
    return {};
}
} // namespace

result<std::size_t> encode_size(const tlv_message_schema_t& schema, const void* input) {
    if (!input) return std::unexpected(CODEC_INVALID_ARGUMENT);
    return measure(schema, static_cast<const byte*>(input));
}
result<std::size_t> encode(const tlv_message_schema_t& schema, const void* input, std::span<byte> output) {
    if (!input) return std::unexpected(CODEC_INVALID_ARGUMENT);
    writer destination(output);
    if (auto status = encode_message(schema, static_cast<const byte*>(input), destination); !status)
        return std::unexpected(status.error());
    return destination.offset();
}
result<void> decode(const tlv_message_schema_t& schema, std::span<const byte> input,
    void* output, std::size_t output_size) {
    if (!output) return std::unexpected(CODEC_INVALID_ARGUMENT);
    if (output_size < schema.struct_size) return std::unexpected(CODEC_BUFFER_TOO_SMALL);
    try {
        return decode_message(schema, input, static_cast<byte*>(output));
    } catch (const std::bad_alloc&) {
        return std::unexpected(CODEC_FAILED);
    }
}
} // namespace tlv
