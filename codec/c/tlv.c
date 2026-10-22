#include "c/tlv.h"

#include <stdbool.h>
#include <string.h>

/* 内部命名约定：native 表示对象内存布局，measure 表示计算编码后的字节数。
 * element 是单值字段本身或一个数组元素；每个被编码的 element 对应一个完整 TLV。
 * 编码分为 message -> element_tlv -> value；解码先读取 TLV，再定位字段和写入 value。
 */

/* TLV 头由 2 字节 tag 和 4 字节 value 长度组成，均使用小端序。 */
#define TLV_TAG_LEN           2u
#define TLV_LENGTH_LEN        4u
#define TLV_HEAD_LEN          (TLV_TAG_LEN + TLV_LENGTH_LEN)

/* 内部调用失败时，原样返回错误码。 */
#define CODEC_TRY(call) do { \
    codec_status_t status_ = (call); \
    if (status_ != CODEC_OK) return status_; \
} while (0)

/* 单个 TLV 的读取结果；value 借用输入缓冲区。 */
typedef struct tlv_item {
    uint16_t       tag;
    uint32_t       length;
    const uint8_t* value;
} tlv_item_t;

/* 写入游标；capacity 为字节容量，不持有缓冲区所有权。 */
typedef struct tlv_writer {
    uint8_t* buffer;
    size_t capacity;
    size_t offset;
} tlv_writer_t;

/* 读取游标；size 为输入字节数，不持有缓冲区所有权。 */
typedef struct tlv_reader {
    const uint8_t* buffer;
    size_t size;
    size_t offset;
} tlv_reader_t;

/* 基础工具：字节序与长度运算。 */
static uint16_t read_le16(const uint8_t* input) {
    return (uint16_t)input[0] | ((uint16_t)input[1] << 8);
}

static uint32_t read_le32(const uint8_t* input) {
    return (uint32_t)input[0]
        | ((uint32_t)input[1] << 8)
        | ((uint32_t)input[2] << 16)
        | ((uint32_t)input[3] << 24);
}

static uint64_t read_le64(const uint8_t* input) {
    return (uint64_t)read_le32(input)
        | ((uint64_t)read_le32(input + 4) << 32);
}

static void write_le16(uint8_t* output, uint16_t value) {
    output[0] = (uint8_t)value;
    output[1] = (uint8_t)(value >> 8);
}

static void write_le32(uint8_t* output, uint32_t value) {
    output[0] = (uint8_t)value;
    output[1] = (uint8_t)(value >> 8);
    output[2] = (uint8_t)(value >> 16);
    output[3] = (uint8_t)(value >> 24);
}

static void write_le64(uint8_t* output, uint64_t value) {
    write_le32(output, (uint32_t)value);
    write_le32(output + 4, (uint32_t)(value >> 32));
}

/* 将 value 累加到 total，检查 size_t 溢出。 */
static codec_status_t add_size(size_t* total, size_t value) {
    if (total == NULL || value > SIZE_MAX - *total) {
        return CODEC_OVERFLOW;
    }
    *total += value;
    return CODEC_OK;
}

/* 计算乘积，检查 size_t 溢出。 */
static codec_status_t multiply_size(size_t left, size_t right, size_t* result) {
    if (result == NULL || (left != 0u && right > SIZE_MAX / left)) {
        return CODEC_OVERFLOW;
    }
    *result = left * right;
    return CODEC_OK;
}

/* 在容量范围内查找结尾 NUL；返回的码流长度不包含 NUL。 */
static codec_status_t string_length(const char* value, size_t capacity, size_t* length) {
    const char* end;

    if (value == NULL || length == NULL || capacity == 0u) {
        return CODEC_INVALID_VALUE;
    }
    end = memchr(value, '\0', capacity);
    if (end == NULL) return CODEC_STRING_NOT_TERMINATED;
    *length = (size_t)(end - value);
    return CODEC_OK;
}

/* 码流缓冲区读写：写入前检查剩余容量，读取前检查头部和 value 是否完整。 */
static codec_status_t writer_check_capacity(const tlv_writer_t* writer, size_t size) {
    if (writer->offset > writer->capacity || size > writer->capacity - writer->offset)
        return CODEC_BUFFER_TOO_SMALL;
    return CODEC_OK;
}

static codec_status_t writer_put_bytes(tlv_writer_t* writer, const uint8_t* data, size_t size) {
    CODEC_TRY(writer_check_capacity(writer, size));
    if (size != 0u) memcpy(writer->buffer + writer->offset, data, size);
    writer->offset += size;
    return CODEC_OK;
}

static codec_status_t writer_put_u8(tlv_writer_t* writer, uint8_t value) {
    CODEC_TRY(writer_check_capacity(writer, sizeof(value)));
    writer->buffer[writer->offset++] = value;
    return CODEC_OK;
}

static codec_status_t writer_put_le16(tlv_writer_t* writer, uint16_t value) {
    CODEC_TRY(writer_check_capacity(writer, sizeof(value)));
    write_le16(writer->buffer + writer->offset, value);
    writer->offset += sizeof(value);
    return CODEC_OK;
}

static codec_status_t writer_put_le32(tlv_writer_t* writer, uint32_t value) {
    CODEC_TRY(writer_check_capacity(writer, sizeof(value)));
    write_le32(writer->buffer + writer->offset, value);
    writer->offset += sizeof(value);
    return CODEC_OK;
}

static codec_status_t writer_put_le64(tlv_writer_t* writer, uint64_t value) {
    CODEC_TRY(writer_check_capacity(writer, sizeof(value)));
    write_le64(writer->buffer + writer->offset, value);
    writer->offset += sizeof(value);
    return CODEC_OK;
}

/* 回填已经写入的长度字段，不推进游标。 */
static codec_status_t writer_patch_le32(tlv_writer_t* writer, size_t offset, uint32_t value) {
    if (writer->offset > writer->capacity || offset > writer->offset ||
        sizeof(value) > writer->offset - offset)
        return CODEC_INVALID_ARGUMENT;
    write_le32(writer->buffer + offset, value);
    return CODEC_OK;
}

/* 完整读取一个 TLV 后推进游标；失败时 reader->offset 保持不变。 */
static codec_status_t reader_read_tlv(tlv_reader_t* reader, tlv_item_t* item) {
    size_t cursor;

    if (reader == NULL || reader->buffer == NULL || item == NULL) return CODEC_INVALID_ARGUMENT;
    if (reader->offset > reader->size || reader->size - reader->offset < TLV_HEAD_LEN)
        return CODEC_TRUNCATED_HEADER;
    cursor = reader->offset;

    item->tag = read_le16(reader->buffer + cursor);
    cursor += TLV_TAG_LEN;

    item->length = read_le32(reader->buffer + cursor);
    cursor += TLV_LENGTH_LEN;

    if ((size_t)item->length > reader->size - cursor) {
        return CODEC_TRUNCATED_VALUE;
    }
    item->value = reader->buffer + cursor;
    reader->offset = cursor + (size_t)item->length;
    return CODEC_OK;
}

/* 本地整数成员访问：用于 count、choice 和整数 presence，不转换字节序。
 * 通过 memcpy 访问，避免成员对齐和类型别名问题。
 */
static codec_status_t read_uint_member(const uint8_t* object, size_t offset,
    tlv_value_type_t type, uint64_t* result) {
    switch (type) {
        case TLV_VALUE_UINT8: {
            uint8_t value;
            memcpy(&value, object + offset, sizeof(value));
            *result = value;
            return CODEC_OK;
        }
        case TLV_VALUE_UINT16: {
            uint16_t value;
            memcpy(&value, object + offset, sizeof(value));
            *result = value;
            return CODEC_OK;
        }
        case TLV_VALUE_UINT32: {
            uint32_t value;
            memcpy(&value, object + offset, sizeof(value));
            *result = value;
            return CODEC_OK;
        }
        case TLV_VALUE_UINT64: {
            uint64_t value;
            memcpy(&value, object + offset, sizeof(value));
            *result = value;
            return CODEC_OK;
        }
        default: return CODEC_INVALID_SCHEMA;
    }
}

static codec_status_t write_uint_member(uint8_t* object, size_t offset,
    tlv_value_type_t type, uint64_t value) {
    switch (type) {
        case TLV_VALUE_UINT8: {
            if (value > UINT8_MAX) return CODEC_OVERFLOW;
            uint8_t scalar = (uint8_t)value;
            memcpy(object + offset, &scalar, sizeof(scalar));
            return CODEC_OK;
        }
        case TLV_VALUE_UINT16: {
            if (value > UINT16_MAX) return CODEC_OVERFLOW;
            uint16_t scalar = (uint16_t)value;
            memcpy(object + offset, &scalar, sizeof(scalar));
            return CODEC_OK;
        }
        case TLV_VALUE_UINT32: {
            if (value > UINT32_MAX) return CODEC_OVERFLOW;
            uint32_t scalar = (uint32_t)value;
            memcpy(object + offset, &scalar, sizeof(scalar));
            return CODEC_OK;
        }
        case TLV_VALUE_UINT64: {
            uint64_t scalar = (uint64_t)value;
            memcpy(object + offset, &scalar, sizeof(scalar));
            return CODEC_OK;
        }
        default: return CODEC_INVALID_SCHEMA;
    }
}

static codec_status_t read_array_count(const tlv_array_schema_t* schema,
    const uint8_t* object, size_t* result) {
    uint64_t value;
    if (schema == NULL || object == NULL || result == NULL) return CODEC_INVALID_ARGUMENT;
    CODEC_TRY(read_uint_member(object, schema->count_offset, schema->count_type, &value));
    if (value > SIZE_MAX) return CODEC_OVERFLOW;
    *result = (size_t)value;
    return CODEC_OK;
}

static codec_status_t write_array_count(const tlv_array_schema_t* schema,
    uint8_t* object, size_t count) {
    if (schema == NULL || object == NULL) return CODEC_INVALID_ARGUMENT;
    return write_uint_member(object, schema->count_offset, schema->count_type, count);
}

static codec_status_t read_union_choice(const tlv_union_schema_t* schema,
    const uint8_t* object, uint64_t* result) {
    if (schema == NULL || object == NULL || result == NULL) return CODEC_INVALID_ARGUMENT;
    return read_uint_member(object, schema->choice_offset, schema->choice_type, result);
}

static codec_status_t write_union_choice(const tlv_union_schema_t* schema,
    uint8_t* object, uint64_t value) {
    if (schema == NULL || object == NULL) return CODEC_INVALID_ARGUMENT;
    return write_uint_member(object, schema->choice_offset, schema->choice_type, value);
}

/* 字段定位与编码条件。 */

/* 单个元素占用的对象内存字节数，也是数组步长。
 * STRING 包含整个字符数组容量，MESSAGE 包含整个子结构体，均不等于编码后的 value 长度。
 */
static codec_status_t native_element_size(const tlv_field_schema_t* field, size_t* result) {
    if (field == NULL || result == NULL) return CODEC_INVALID_ARGUMENT;
    switch (field->type) {
        case TLV_VALUE_INT8:
        case TLV_VALUE_UINT8:
            *result = sizeof(uint8_t);
            return CODEC_OK;
        case TLV_VALUE_INT16:
        case TLV_VALUE_UINT16:
            *result = sizeof(uint16_t);
            return CODEC_OK;
        case TLV_VALUE_INT32:
        case TLV_VALUE_UINT32:
            *result = sizeof(uint32_t);
            return CODEC_OK;
        case TLV_VALUE_INT64:
        case TLV_VALUE_UINT64:
            *result = sizeof(uint64_t);
            return CODEC_OK;
        case TLV_VALUE_BOOL:
            *result = sizeof(bool);
            return CODEC_OK;
        case TLV_VALUE_STRING:
            *result = field->string_capacity;
            return CODEC_OK;
        case TLV_VALUE_MESSAGE:
            if (field->nested_schema == NULL) return CODEC_INVALID_SCHEMA;
            *result = field->nested_schema->struct_size;
            return CODEC_OK;
        default:
            return CODEC_INVALID_SCHEMA;
    }
}

/* 已选中字段的待编码元素数：单值为 1，数组读取 count 并检查容量；不统计 schema 字段数。 */
static codec_status_t encoded_element_count(const tlv_field_schema_t* field,
    const uint8_t* object, size_t* count) {
    if (field == NULL || object == NULL || count == NULL) return CODEC_INVALID_ARGUMENT;
    if (field->array_schema == NULL) {
        *count = 1u;
        return CODEC_OK;
    }
    CODEC_TRY(read_array_count(field->array_schema, object, count));
    if (*count > field->array_schema->capacity) return CODEC_INVALID_COUNT;
    return CODEC_OK;
}

/* 返回对象中第 index 个元素的地址：字段偏移 + index * stride；单值字段的 index 必须为 0。 */
static codec_status_t locate_field_element(const tlv_field_schema_t* field,
    const uint8_t* object, size_t index, size_t stride,
    const uint8_t** result) {
    size_t relative_offset;
    if (field == NULL || object == NULL || result == NULL) return CODEC_INVALID_ARGUMENT;
    if (field->array_schema == NULL && index != 0u) return CODEC_INVALID_ARGUMENT;
    if (field->array_schema != NULL && index >= field->array_schema->capacity) return CODEC_INVALID_VALUE;
    CODEC_TRY(multiply_size(index, stride, &relative_offset));
    if (relative_offset > SIZE_MAX - field->offset) return CODEC_OVERFLOW;
    *result = object + field->offset + relative_offset;
    return CODEC_OK;
}

/* 查找当前消息层的字段；未知 tag 返回 NULL，由解码器跳过。 */
static const tlv_field_schema_t* find_field_by_tag(const tlv_message_schema_t* schema, uint16_t tag) {
    size_t index;
    for (index = 0; index < schema->field_count; ++index) {
        if (schema->fields[index].tag == tag) return &schema->fields[index];
    }
    return NULL;
}

/* 读取本地 presence；没有存在描述时，按存在处理。 */
static codec_status_t field_is_present(const tlv_field_schema_t* field,
    const uint8_t* object, int* result) {
    const tlv_present_schema_t* present = field->present_schema;
    uint64_t value;
    if (present == NULL) {
        *result = 1;
        return CODEC_OK;
    }
    if (present->type == TLV_VALUE_BOOL) {
        bool flag;
        memcpy(&flag, object + present->offset, sizeof(flag));
        *result = flag;
        return CODEC_OK;
    }
    CODEC_TRY(read_uint_member(object, present->offset, present->type, &value));
    *result = (value & present->mask) != 0u;
    return CODEC_OK;
}

/* 设置 presence：BOOL 写 true，整数按位或并保留其他标记。 */
static codec_status_t mark_field_present(const tlv_present_schema_t* present, uint8_t* object) {
    uint64_t value;
    if (present->type == TLV_VALUE_BOOL) {
        bool flag = true;
        memcpy(object + present->offset, &flag, sizeof(flag));
        return CODEC_OK;
    }
    CODEC_TRY(read_uint_member(object, present->offset, present->type, &value));
    return write_uint_member(object, present->offset, present->type, value | present->mask);
}

/* 根据对象中的控制成员判断字段是否被选中，不校验字段数据或 schema。
 * 先看 presence；未置位时不读取 choice。没有对应控制描述时，视为满足该条件。
 * 编码据此决定是否输出字段；解码据此判断目标 union 是否已经处于当前分支。
 */
static codec_status_t field_is_selected(const tlv_field_schema_t* field,
    const uint8_t* object,
    int* active) {
    uint64_t choice;

    if (field == NULL || object == NULL || active == NULL) {
        return CODEC_INVALID_VALUE;
    }
    CODEC_TRY(field_is_present(field, object, active));
    if (!*active || field->union_schema == NULL) return CODEC_OK;
    CODEC_TRY(read_union_choice(field->union_schema, object, &choice));
    *active = choice == field->union_schema->choice_value;
    return CODEC_OK;
}

/* 为即将收到的字段准备 union 存储：同分支保留原内容，首次进入或切换时清零新分支。
 * 配置 presence 且标记未置位时不读取旧 choice；未配置 presence 时仍按 choice 判断。
 * choice=0 也可表示已选中分支；此处不更新 choice/presence，留待字段解码成功后处理。
 */
static codec_status_t prepare_union_branch_for_decode(const tlv_field_schema_t* field, uint8_t* object) {
    int active;
    size_t size;
    if (field->union_schema == NULL) return CODEC_OK;
    CODEC_TRY(field_is_selected(field, object, &active));
    if (active) return CODEC_OK;
    CODEC_TRY(native_element_size(field, &size));
    if (field->array_schema != NULL) {
        CODEC_TRY(multiply_size(size, field->array_schema->capacity, &size));
    }
    if (size > SIZE_MAX - field->offset) return CODEC_OVERFLOW;
    if (size != 0u) memset(object + field->offset, 0, size);
    if (field->array_schema != NULL) {
        CODEC_TRY(write_array_count(field->array_schema, object, 0u));
    }
    return CODEC_OK;
}

/* 编码长度计算。 */
static codec_status_t measure_message_size(const tlv_message_schema_t* schema,
    const uint8_t* object, size_t* encoded_size);

/* 测量单个元素编码后的 value 字节数，不含本元素的 6 字节 TLV 头。
 * STRING 不含结尾 NUL；MESSAGE 包含子消息内部各 TLV 的头部和 value。
 */
static codec_status_t measure_value_size(const tlv_field_schema_t* field,
    const uint8_t* value, size_t* result) {
    if (field == NULL || value == NULL || result == NULL) return CODEC_INVALID_ARGUMENT;
    switch (field->type) {
        case TLV_VALUE_INT8:
        case TLV_VALUE_UINT8: *result = 1u; return CODEC_OK;
        case TLV_VALUE_INT16:
        case TLV_VALUE_UINT16: *result = 2u; return CODEC_OK;
        case TLV_VALUE_INT32:
        case TLV_VALUE_UINT32: *result = sizeof(uint32_t); return CODEC_OK;
        case TLV_VALUE_INT64:
        case TLV_VALUE_UINT64: *result = sizeof(uint64_t); return CODEC_OK;
        case TLV_VALUE_BOOL:
            *result = sizeof(uint8_t);
            return CODEC_OK;
        case TLV_VALUE_STRING: return string_length((const char*)value, field->string_capacity, result);
        case TLV_VALUE_MESSAGE: return measure_message_size(field->nested_schema, value, result);
        default: return CODEC_INVALID_VALUE;
    }
}

/* 累加当前消息中所有待编码字段的头部和 value 长度。 */
static codec_status_t measure_message_size(const tlv_message_schema_t* schema,
    const uint8_t* object, size_t* encoded_size) {
    size_t index;
    size_t total = 0u;

    for (index = 0; index < schema->field_count; ++index) {
        const tlv_field_schema_t* field = &schema->fields[index];
        size_t count;
        size_t item_index;
        size_t stride;
        int active;

        CODEC_TRY(field_is_selected(field, object, &active));
        if (!active) continue;
        CODEC_TRY(encoded_element_count(field, object, &count));
        if (count == 0u) continue;
        CODEC_TRY(native_element_size(field, &stride));

        for (item_index = 0; item_index < count; ++item_index) {
            const uint8_t* value;
            size_t length;
            CODEC_TRY(locate_field_element(field, object, item_index, stride, &value));
            CODEC_TRY(measure_value_size(field, value, &length));
            if (length > UINT32_MAX) return CODEC_OVERFLOW;
            CODEC_TRY(add_size(&total, TLV_HEAD_LEN));
            CODEC_TRY(add_size(&total, length));
        }
    }
    *encoded_size = total;
    return CODEC_OK;
}

codec_status_t tlv_encode_size(const tlv_message_schema_t* schema,
    const void* input, size_t* encoded_size) {
    if (schema == NULL || input == NULL || encoded_size == NULL) return CODEC_INVALID_ARGUMENT;
    return measure_message_size(schema, (const uint8_t*)input, encoded_size);
}

/* 消息编码。 */

/* 只写入整数、BOOL 或 STRING 的 value；完整 TLV 头和 MESSAGE 递归由 encode_element_tlv 处理。 */
static codec_status_t encode_value(const tlv_field_schema_t* field,
    const uint8_t* value, tlv_writer_t* writer,
    size_t length) {
    switch (field->type) {
        case TLV_VALUE_INT8:
        case TLV_VALUE_UINT8: {
            uint8_t scalar;
            memcpy(&scalar, value, sizeof(scalar));
            return writer_put_u8(writer, scalar);
        }
        case TLV_VALUE_INT16:
        case TLV_VALUE_UINT16: {
            uint16_t scalar;
            memcpy(&scalar, value, sizeof(scalar));
            return writer_put_le16(writer, scalar);
        }
        case TLV_VALUE_INT32:
        case TLV_VALUE_UINT32: {
            uint32_t scalar;
            memcpy(&scalar, value, sizeof(scalar));
            return writer_put_le32(writer, scalar);
        }
        case TLV_VALUE_INT64:
        case TLV_VALUE_UINT64: {
            uint64_t scalar;
            memcpy(&scalar, value, sizeof(scalar));
            return writer_put_le64(writer, scalar);
        }
        case TLV_VALUE_BOOL: {
            bool scalar;
            memcpy(&scalar, value, sizeof(scalar));
            return writer_put_u8(writer, scalar ? 1u : 0u);
        }
        case TLV_VALUE_STRING:
            return writer_put_bytes(writer, value, length);
        default:
            return CODEC_INVALID_VALUE;
    }
}

static codec_status_t encode_message(const tlv_message_schema_t* schema,
    const uint8_t* object, tlv_writer_t* writer);

/* 编码一个完整 TLV；MESSAGE 直接递归写入，再回填其 value 长度。 */
static codec_status_t encode_element_tlv(const tlv_field_schema_t* field,
    const uint8_t* value, tlv_writer_t* writer) {
    size_t length;
    if (field->type == TLV_VALUE_MESSAGE) {
        size_t length_offset;
        size_t value_offset;
        CODEC_TRY(writer_put_le16(writer, field->tag));
        length_offset = writer->offset;
        CODEC_TRY(writer_put_le32(writer, 0u));
        value_offset = writer->offset;
        CODEC_TRY(encode_message(field->nested_schema, value, writer));
        length = writer->offset - value_offset;
        if (length > UINT32_MAX) return CODEC_OVERFLOW;
        return writer_patch_le32(writer, length_offset, (uint32_t)length);
    }

    CODEC_TRY(measure_value_size(field, value, &length));
    if (length > UINT32_MAX) return CODEC_OVERFLOW;
    CODEC_TRY(writer_put_le16(writer, field->tag));
    CODEC_TRY(writer_put_le32(writer, (uint32_t)length));
    return encode_value(field, value, writer, length);
}

/* 遍历当前层字段，仅编码存在且被 choice 选中的元素；数组按 count 重复 tag。 */
static codec_status_t encode_message(const tlv_message_schema_t* schema,
    const uint8_t* object, tlv_writer_t* writer) {
    size_t index;
    for (index = 0; index < schema->field_count; ++index) {
        const tlv_field_schema_t* field = &schema->fields[index];
        size_t count;
        size_t item_index;
        size_t stride;
        int active;
        CODEC_TRY(field_is_selected(field, object, &active));
        if (!active) continue;
        CODEC_TRY(encoded_element_count(field, object, &count));
        if (count == 0u) continue;
        CODEC_TRY(native_element_size(field, &stride));
        for (item_index = 0; item_index < count; ++item_index) {
            const uint8_t* value;
            CODEC_TRY(locate_field_element(field, object, item_index, stride, &value));
            CODEC_TRY(encode_element_tlv(field, value, writer));
        }
    }
    return CODEC_OK;
}

codec_status_t tlv_encode(const tlv_message_schema_t* schema,
    const void* input, uint8_t* buffer,
    size_t buffer_size, size_t* written) {
    tlv_writer_t writer = {buffer, buffer_size, 0u};
    if (written != NULL) *written = 0u;
    if (schema == NULL || input == NULL || buffer == NULL) return CODEC_INVALID_ARGUMENT;
    CODEC_TRY(encode_message(schema, (const uint8_t*)input, &writer));
    if (written != NULL) *written = writer.offset;
    return CODEC_OK;
}

/* 消息解码：value 转换、数组定位、字段状态更新分别处理。
 * 同一 MESSAGE 重复时复用原对象，只有 MESSAGE 数组才写入下一个元素。
 */
static codec_status_t decode_message(const tlv_message_schema_t* schema,
    const uint8_t* input, size_t input_size, uint8_t* object);

/* 将一个 TLV 的 value 写入已定位的元素；不更新所属字段的 count、presence 或 choice。
 * MESSAGE 递归合并到目标子对象；STRING 拒绝内嵌 NUL，检查容量后复制并补结尾 NUL。
 */
static codec_status_t decode_value(const tlv_field_schema_t* field,
    const tlv_item_t* item, uint8_t* destination) {
    if (field == NULL || item == NULL || destination == NULL) return CODEC_INVALID_ARGUMENT;
    switch (field->type) {
        case TLV_VALUE_INT8:
        case TLV_VALUE_UINT8: {
            uint8_t scalar;
            if (item->length != sizeof(scalar)) return CODEC_FIELD_LENGTH_MISMATCH;
            scalar = item->value[0];
            memcpy(destination, &scalar, sizeof(scalar));
            return CODEC_OK;
        }
        case TLV_VALUE_INT16:
        case TLV_VALUE_UINT16: {
            uint16_t scalar;
            if (item->length != sizeof(scalar)) return CODEC_FIELD_LENGTH_MISMATCH;
            scalar = read_le16(item->value);
            memcpy(destination, &scalar, sizeof(scalar));
            return CODEC_OK;
        }
        case TLV_VALUE_INT32:
        case TLV_VALUE_UINT32: {
            uint32_t scalar;
            if (item->length != sizeof(scalar)) {
                return CODEC_FIELD_LENGTH_MISMATCH;
            }
            scalar = read_le32(item->value);
            memcpy(destination, &scalar, sizeof(scalar));
            return CODEC_OK;
        }
        case TLV_VALUE_INT64:
        case TLV_VALUE_UINT64: {
            uint64_t scalar;
            if (item->length != sizeof(scalar)) {
                return CODEC_FIELD_LENGTH_MISMATCH;
            }
            scalar = read_le64(item->value);
            memcpy(destination, &scalar, sizeof(scalar));
            return CODEC_OK;
        }
        case TLV_VALUE_BOOL: {
            bool scalar;
            if (item->length != sizeof(uint8_t)) {
                return CODEC_FIELD_LENGTH_MISMATCH;
            }
            if (item->value[0] > 1u) return CODEC_INVALID_BOOL;
            scalar = item->value[0] != 0u;
            memcpy(destination, &scalar, sizeof(scalar));
            return CODEC_OK;
        }
        case TLV_VALUE_STRING:
            if ((size_t)item->length >= field->string_capacity) {
                return CODEC_STRING_CAPACITY_EXCEEDED;
            }
            if (item->length != 0u) {
                if (memchr(item->value, '\0', item->length) != NULL)
                    return CODEC_STRING_CONTAINS_NUL;
                memcpy(destination, item->value, item->length);
            }
            destination[item->length] = '\0';
            return CODEC_OK;
        case TLV_VALUE_MESSAGE:
            if (field->nested_schema == NULL) return CODEC_INVALID_SCHEMA;
            return decode_message(field->nested_schema, item->value, item->length, destination);
        default:
            return CODEC_INVALID_SCHEMA;
    }
}

/* 定位并解码一个字段元素：单值写入固定成员，数组写入下标为 count 的元素。
 * 数组元素解码成功后才尝试递增 count；若 count 类型无法表示新值，仍可能返回溢出。
 */
static codec_status_t decode_field(const tlv_field_schema_t* field,
    const tlv_item_t* item, uint8_t* object) {
    size_t count;
    size_t stride;
    const uint8_t* value;
    if (field->array_schema == NULL) return decode_value(field, item, object + field->offset);
    CODEC_TRY(read_array_count(field->array_schema, object, &count));
    if (count >= field->array_schema->capacity) return CODEC_ARRAY_CAPACITY_EXCEEDED;
    CODEC_TRY(native_element_size(field, &stride));
    CODEC_TRY(locate_field_element(field, object, count, stride, &value));
    CODEC_TRY(decode_value(field, item, (uint8_t*)value));
    return write_array_count(field->array_schema, object, count + 1u);
}

/* 按码流顺序处理字段；重复标量覆盖、数组追加、消息合并，未知 tag 跳过。 */
static codec_status_t decode_message(const tlv_message_schema_t* schema,
    const uint8_t* input, size_t input_size, uint8_t* object) {
    tlv_reader_t reader = {input, input_size, 0u};
    while (reader.offset < reader.size) {
        tlv_item_t item;
        const tlv_field_schema_t* field;
        CODEC_TRY(reader_read_tlv(&reader, &item));
        field = find_field_by_tag(schema, item.tag);
        if (field == NULL) continue;
        CODEC_TRY(prepare_union_branch_for_decode(field, object));
        CODEC_TRY(decode_field(field, &item, object));
        /* 字段完整解码后，再更新 presence 和 choice。 */
        if (field->present_schema != NULL)
            CODEC_TRY(mark_field_present(field->present_schema, object));
        if (field->union_schema != NULL) {
            CODEC_TRY(write_union_choice(field->union_schema, object, field->union_schema->choice_value));
        }
    }
    return CODEC_OK;
}

codec_status_t tlv_decode(const tlv_message_schema_t* schema,
    const uint8_t* input, size_t input_size, void* buffer, size_t buffer_size) {
    if (input == NULL || buffer == NULL || schema == NULL) return CODEC_INVALID_ARGUMENT;
    if (buffer_size < schema->struct_size) return CODEC_BUFFER_TOO_SMALL;
    return decode_message(schema, input, input_size, (uint8_t*)buffer);
}
