#include "cpp/tlv.h"

#include <bit>
#include <cstring>
#include <limits>

namespace tlv {
namespace {
using byte = std::uint8_t;
constexpr std::size_t header_size = 6;

// 与 C 版一致：native 表示对象内存布局，measure 表示计算编码字节数。
// element 是单值字段本身或一个数组元素；encode_element_tlv 写完整 TLV，encode_value 只写数据部分。

// 本地成员用 memcpy 读写，码流用固定宽度小端；不要求成员自然对齐。
template<class T> T load(const byte* source) {
    T value;
    std::memcpy(&value, source, sizeof(value));
    return value;
}
template<class T> void store(byte* destination, T value) {
    std::memcpy(destination, &value, sizeof(value));
}
static_assert(std::endian::native == std::endian::little ||
              std::endian::native == std::endian::big,
              "TLV requires little-endian or big-endian byte order");

template<std::unsigned_integral T> T read_le(const byte* source) {
    T value = load<T>(source);
    if constexpr (std::endian::native == std::endian::big)
        value = std::byteswap(value);
    return value;
}

template<std::unsigned_integral T> void write_le(byte* destination, T value) {
    if constexpr (std::endian::native == std::endian::big)
        value = std::byteswap(value);
    store(destination, value);
}

// 写入游标借用调用方缓冲区；每次 put 检查容量，offset 是已写入的字节数。
// patch_length 仅回填已写入的长度占位，不推进游标；用于直接编码嵌套消息。
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

// 读取游标持有尚未消费的码流；只有头部和 value 完整时才消费一个 TLV，value 借用输入存储。
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

result<std::uint64_t> read_uint_member(const byte* object, std::size_t offset, tlv_value_type_t type) {
    return dispatch_uint(type, [&]<class T>() -> result<std::uint64_t> {
        return load<T>(object + offset);
    });
}

result<void> write_uint_member(byte* object, std::size_t offset, tlv_value_type_t type, std::uint64_t value) {
    return dispatch_uint(type, [&]<class T>() -> result<void> {
        if (value > std::numeric_limits<T>::max()) return std::unexpected(CODEC_OVERFLOW);
        store(object + offset, static_cast<T>(value));
        return {};
    });
}

result<std::size_t> read_array_count(const tlv_array_schema_t& array, const byte* object) {
    auto count = read_uint_member(object, array.count_offset, array.count_type);
    if (!count) return std::unexpected(count.error());
    if (*count > SIZE_MAX) return std::unexpected(CODEC_OVERFLOW);
    return static_cast<std::size_t>(*count);
}

// 根据 presence 和 choice 判断字段是否被选中，不校验字段数据或 schema。
// 编码据此决定是否输出字段；解码据此判断目标 union 是否已经处于当前分支。
result<bool> field_is_selected(const tlv_field_schema_t& field, const byte* object) {
    if (const auto* presence = field.present_schema) {
        if (presence->type == TLV_VALUE_BOOL) {
            if (!load<bool>(object + presence->offset)) return false;
        } else {
            auto flags = read_uint_member(object, presence->offset, presence->type);
            if (!flags) return std::unexpected(flags.error());
            if ((*flags & presence->mask) == 0) return false;
        }
    }
    // presence 未置位时已返回；没有 presence 描述时仍需按 choice 判断。
    if (const auto* branch = field.union_schema) {
        auto choice = read_uint_member(object, branch->choice_offset, branch->choice_type);
        if (!choice) return std::unexpected(choice.error());
        return *choice == branch->choice_value;
    }
    return true;
}

// BOOL 标记写 true；整数标记只置位当前 mask，保留同一成员中的其他位。
result<void> mark_field_present(const tlv_present_schema_t& presence, byte* object) {
    if (presence.type == TLV_VALUE_BOOL) {
        store(object + presence.offset, true);
        return {};
    }
    auto flags = read_uint_member(object, presence.offset, presence.type);
    if (!flags) return std::unexpected(flags.error());
    return write_uint_member(object, presence.offset, presence.type, *flags | presence.mask);
}

// 单个元素占用的对象内存字节数，也是数组步长；STRING 为字符数组容量，MESSAGE 为子结构体大小。
// BOOL 的本地 sizeof(bool) 与码流中的固定 1 字节分别处理。
result<std::size_t> native_element_size(const tlv_field_schema_t& field) {
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

// 元素相对所属消息对象的字节偏移；调用方已检查数组容量，单值字段传 index=0。
result<std::size_t> field_element_offset(const tlv_field_schema_t& field, std::size_t index, std::size_t stride) {
    if (index != 0 && stride > SIZE_MAX / index) return std::unexpected(CODEC_OVERFLOW);
    const auto relative = index * stride;
    if (relative > SIZE_MAX - field.offset) return std::unexpected(CODEC_OVERFLOW);
    return field.offset + relative;
}

// 已选中字段的待编码元素数：单值为 1，数组读取 count 并检查容量；不统计 schema 字段数。
result<std::size_t> encoded_element_count(const tlv_field_schema_t& field, const byte* object) {
    if (!field.array_schema) return 1;
    auto count = read_array_count(*field.array_schema, object);
    if (!count) return std::unexpected(count.error());
    if (*count > field.array_schema->capacity) return std::unexpected(CODEC_INVALID_COUNT);
    return count;
}

result<std::size_t> measure_message_size(const tlv_message_schema_t& schema, const byte* object);
result<void> encode_message(const tlv_message_schema_t& schema, const byte* object, writer& output);
result<void> decode_message(const tlv_message_schema_t& schema, std::span<const byte> input, byte* object);

// 测量一个元素的 value 字节数，不含本元素的 TLV 头；STRING 不含结尾 NUL。
// MESSAGE 的 value 是完整子消息，因此包含子消息内部各 TLV 的头部和 value。
result<std::size_t> measure_value_size(const tlv_field_schema_t& field, const byte* value) {
    switch (field.type) {
        case TLV_VALUE_INT8: case TLV_VALUE_UINT8: case TLV_VALUE_BOOL: return 1;
        case TLV_VALUE_INT16: case TLV_VALUE_UINT16: return 2;
        case TLV_VALUE_INT32: case TLV_VALUE_UINT32: return 4;
        case TLV_VALUE_INT64: case TLV_VALUE_UINT64: return 8;
        case TLV_VALUE_STRING: {
            if (field.string_capacity == 0) return std::unexpected(CODEC_INVALID_VALUE);
            const auto* end = static_cast<const byte*>(std::memchr(value, 0, field.string_capacity));
            if (!end) return std::unexpected(CODEC_STRING_NOT_TERMINATED);
            return static_cast<std::size_t>(end - value);
        }
        case TLV_VALUE_MESSAGE:
            if (!field.nested_schema) return std::unexpected(CODEC_INVALID_SCHEMA);
            return measure_message_size(*field.nested_schema, value);
        default: return std::unexpected(CODEC_INVALID_VALUE);
    }
}

// 累加当前消息所有被选中元素的 TLV 头部和 value 长度，不写码流。
result<std::size_t> measure_message_size(const tlv_message_schema_t& schema, const byte* object) {
    std::size_t total = 0;
    for (const auto& field : std::span(schema.fields, schema.field_count)) {
        auto enabled = field_is_selected(field, object);
        if (!enabled) return std::unexpected(enabled.error());
        if (!*enabled) continue;
        auto count = encoded_element_count(field, object);
        if (!count) return std::unexpected(count.error());
        if (*count == 0) continue;
        auto stride = native_element_size(field);
        if (!stride) return std::unexpected(stride.error());
        for (std::size_t i = 0; i < *count; ++i) {
            auto offset = field_element_offset(field, i, *stride);
            if (!offset) return std::unexpected(offset.error());
            auto size = measure_value_size(field, object + *offset);
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

// 整数字段统一按相同宽度的无符号类型搬运原始位表示；不处理 BOOL、STRING 或 MESSAGE。
template<class F> auto dispatch_integer(tlv_value_type_t type, F&& visit)
    -> decltype(visit.template operator()<std::uint8_t>()) {
    switch (type) {
        case TLV_VALUE_INT8: case TLV_VALUE_UINT8: return visit.template operator()<std::uint8_t>();
        case TLV_VALUE_INT16: case TLV_VALUE_UINT16: return visit.template operator()<std::uint16_t>();
        case TLV_VALUE_INT32: case TLV_VALUE_UINT32: return visit.template operator()<std::uint32_t>();
        case TLV_VALUE_INT64: case TLV_VALUE_UINT64: return visit.template operator()<std::uint64_t>();
        default: return std::unexpected(CODEC_INVALID_SCHEMA);
    }
}

// 只写整数、BOOL 或 STRING 的 value；TLV 头和 MESSAGE 递归由 encode_element_tlv 处理。
result<void> encode_value(const tlv_field_schema_t& field, const byte* value,
    std::size_t length, writer& output) {
    if (field.type == TLV_VALUE_BOOL)
        return output.put(static_cast<byte>(load<bool>(value) ? 1 : 0));
    if (field.type == TLV_VALUE_STRING) return output.put(std::span(value, length));
    return dispatch_integer(field.type, [&]<class T>() { return output.put(load<T>(value)); });
}

// 一个元素对应一个完整 TLV；嵌套消息直接写入后回填长度。
result<void> encode_element_tlv(const tlv_field_schema_t& field, const byte* value, writer& output) {
    if (field.type == TLV_VALUE_MESSAGE) {
        if (auto status = output.put(field.tag); !status) return status;
        const auto length_offset = output.offset();
        if (auto status = output.put(std::uint32_t{0}); !status) return status;
        const auto start = output.offset();
        if (auto status = encode_message(*field.nested_schema, value, output); !status) return status;
        const auto length = output.offset() - start;
        if (length > UINT32_MAX) return std::unexpected(CODEC_OVERFLOW);
        output.patch_length(length_offset, static_cast<std::uint32_t>(length));
        return {};
    }

    auto length = measure_value_size(field, value);
    if (!length) return std::unexpected(length.error());
    if (*length > UINT32_MAX) return std::unexpected(CODEC_OVERFLOW);
    if (auto status = output.put(field.tag); !status) return status;
    if (auto status = output.put(static_cast<std::uint32_t>(*length)); !status) return status;
    return encode_value(field, value, *length, output);
}

// 仅遍历存在且被 choice 选中的字段；数组按 count 编码为重复 tag。
result<void> encode_message(const tlv_message_schema_t& schema, const byte* object, writer& output) {
    for (const auto& field : std::span(schema.fields, schema.field_count)) {
        auto enabled = field_is_selected(field, object);
        if (!enabled) return std::unexpected(enabled.error());
        if (!*enabled) continue;
        auto count = encoded_element_count(field, object);
        if (!count) return std::unexpected(count.error());
        if (*count == 0) continue;
        auto stride = native_element_size(field);
        if (!stride) return std::unexpected(stride.error());
        for (std::size_t i = 0; i < *count; ++i) {
            auto offset = field_element_offset(field, i, *stride);
            if (!offset) return std::unexpected(offset.error());
            const auto* value = object + *offset;
            if (auto status = encode_element_tlv(field, value, output); !status) return status;
        }
    }
    return {};
}

// 将一个 TLV 的 value 写入已定位的元素，不更新所属字段的 count、presence 或 choice。
// MESSAGE 递归合并到目标子对象；STRING 拒绝内嵌 NUL，检查容量后复制并补结尾 NUL。
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
            return dispatch_integer(field.type, [&]<class T>() -> result<void> {
                if (bytes.size() != sizeof(T)) return std::unexpected(CODEC_FIELD_LENGTH_MISMATCH);
                store(destination, read_le<T>(bytes.data()));
                return {};
            });
    }
}

// 单值写入固定成员，数组写入下标为 count 的元素；数组元素解码成功后才尝试递增 count。
// count 类型无法表示新值时仍可能返回溢出，此时元素已经写入。
result<void> decode_field(const tlv_field_schema_t& field, std::span<const byte> bytes, byte* object) {
    if (!field.array_schema) return decode_value(field, bytes, object + field.offset);
    const auto& array = *field.array_schema;
    auto count = read_array_count(array, object);
    if (!count) return std::unexpected(count.error());
    if (*count >= array.capacity) return std::unexpected(CODEC_ARRAY_CAPACITY_EXCEEDED);
    auto stride = native_element_size(field);
    if (!stride) return std::unexpected(stride.error());
    auto offset = field_element_offset(field, *count, *stride);
    if (!offset) return std::unexpected(offset.error());
    if (auto status = decode_value(field, bytes, object + *offset); !status) return status;
    return write_uint_member(object, array.count_offset, array.count_type, *count + 1);
}

// 为即将收到的字段准备 union 存储：同分支保留内容，首次进入或切换时清零新分支及其数组 count。
// 配置 presence 且标记未置位时视为首次进入；未配置时按 choice 判断，0 也可表示已选中分支。
// 此处不更新 choice/presence，留待字段解码成功后处理。
result<void> prepare_union_branch_for_decode(const tlv_field_schema_t& field, byte* object) {
    if (!field.union_schema) return {};
    auto selected = field_is_selected(field, object);
    if (!selected) return std::unexpected(selected.error());
    if (*selected) return {};
    auto size = native_element_size(field);
    if (!size) return std::unexpected(size.error());
    if (field.array_schema) {
        const auto capacity = field.array_schema->capacity;
        if (*size != 0 && capacity > SIZE_MAX / *size) return std::unexpected(CODEC_OVERFLOW);
        *size *= capacity;
    }
    if (*size > SIZE_MAX - field.offset) return std::unexpected(CODEC_OVERFLOW);
    if (*size != 0) std::memset(object + field.offset, 0, *size);
    if (const auto* array = field.array_schema)
        return write_uint_member(object, array->count_offset, array->count_type, 0);
    return {};
}

// 查找当前消息层的字段；不对 tag 排序，重复 tag 始终重新处理。
const tlv_field_schema_t* find_field_by_tag(const tlv_message_schema_t& schema, std::uint16_t tag) {
    for (const auto& field : std::span(schema.fields, schema.field_count))
        if (field.tag == tag) return &field;
    return nullptr;
}

// 字段成功后再更新 presence/choice；失败时保留已完成的部分写入。
result<void> decode_message(const tlv_message_schema_t& schema, std::span<const byte> input, byte* object) {
    reader source(input);
    while (!source.empty()) {
        auto current = source.next();
        if (!current) return std::unexpected(current.error());
        const auto* found = find_field_by_tag(schema, current->tag);
        if (!found) continue;
        const auto& field = *found;
        if (auto status = prepare_union_branch_for_decode(field, object); !status) return status;
        if (auto status = decode_field(field, current->value, object); !status) return status;
        // 顺序：值和数组 count、presence、choice。
        if (field.present_schema) {
            if (auto status = mark_field_present(*field.present_schema, object); !status) return status;
        }
        if (const auto* branch = field.union_schema) {
            if (auto status = write_uint_member(object, branch->choice_offset, branch->choice_type,
                branch->choice_value); !status) return status;
        }
    }
    return {};
}
} // namespace

result<std::size_t> encode_size(const tlv_message_schema_t& schema, const void* input) {
    if (!input) return std::unexpected(CODEC_INVALID_ARGUMENT);
    return measure_message_size(schema, static_cast<const byte*>(input));
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
    return decode_message(schema, input, static_cast<byte*>(output));
}
} // namespace tlv
