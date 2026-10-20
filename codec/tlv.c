#include "tlv.h"

#include <stdbool.h>
#include <string.h>

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
    size_t index;

    if (value == NULL || length == NULL || capacity == 0u) {
        return CODEC_INVALID_VALUE;
    }
    for (index = 0; index < capacity; ++index) {
        if (value[index] == '\0') {
            *length = index;
            return CODEC_OK;
        }
    }
    return CODEC_STRING_NOT_TERMINATED;
}

/* 缓冲区读写。 */
static codec_status_t writer_check(const tlv_writer_t* writer, size_t size) {
    if (writer->offset > writer->capacity || size > writer->capacity - writer->offset)
        return CODEC_BUFFER_TOO_SMALL;
    return CODEC_OK;
}

static codec_status_t writer_put_bytes(tlv_writer_t* writer, const uint8_t* data, size_t size) {
    CODEC_TRY(writer_check(writer, size));
    if (size != 0u) memcpy(writer->buffer + writer->offset, data, size);
    writer->offset += size;
    return CODEC_OK;
}

static codec_status_t writer_put_u8(tlv_writer_t* writer, uint8_t value) {
    CODEC_TRY(writer_check(writer, sizeof(value)));
    writer->buffer[writer->offset++] = value;
    return CODEC_OK;
}

static codec_status_t writer_put_le16(tlv_writer_t* writer, uint16_t value) {
    CODEC_TRY(writer_check(writer, sizeof(value)));
    write_le16(writer->buffer + writer->offset, value);
    writer->offset += sizeof(value);
    return CODEC_OK;
}

static codec_status_t writer_put_le32(tlv_writer_t* writer, uint32_t value) {
    CODEC_TRY(writer_check(writer, sizeof(value)));
    write_le32(writer->buffer + writer->offset, value);
    writer->offset += sizeof(value);
    return CODEC_OK;
}

static codec_status_t writer_put_le64(tlv_writer_t* writer, uint64_t value) {
    CODEC_TRY(writer_check(writer, sizeof(value)));
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
static codec_status_t reader_next(tlv_reader_t* reader, tlv_item_t* item) {
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

static codec_status_t read_count(const tlv_array_schema_t* schema,
    const uint8_t* object, size_t* result) {
    uint64_t value;
    if (schema == NULL || object == NULL || result == NULL) return CODEC_INVALID_ARGUMENT;
    CODEC_TRY(read_uint_member(object, schema->count_offset, schema->count_type, &value));
    if (value > SIZE_MAX) return CODEC_OVERFLOW;
    *result = (size_t)value;
    return CODEC_OK;
}

static codec_status_t write_count(const tlv_array_schema_t* schema,
    uint8_t* object, size_t count) {
    if (schema == NULL || object == NULL) return CODEC_INVALID_ARGUMENT;
    return write_uint_member(object, schema->count_offset, schema->count_type, count);
}

static codec_status_t read_choice(const tlv_union_schema_t* schema,
    const uint8_t* object, uint64_t* result) {
    if (schema == NULL || object == NULL || result == NULL) return CODEC_INVALID_ARGUMENT;
    return read_uint_member(object, schema->choice_offset, schema->choice_type, result);
}

static codec_status_t write_choice(const tlv_union_schema_t* schema,
    uint8_t* object, uint64_t value) {
    if (schema == NULL || object == NULL) return CODEC_INVALID_ARGUMENT;
    return write_uint_member(object, schema->choice_offset, schema->choice_type, value);
}

/* 字段定位与编码条件。 */

/* 本地元素大小；数组使用该大小作为步长，与码流 value 长度区分。 */
static codec_status_t element_size(const tlv_field_schema_t* field, size_t* result) {
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

/* 编码元素数：单值为 1，数组读取 count 并检查容量。 */
static codec_status_t field_count(const tlv_field_schema_t* field,
    const uint8_t* object, size_t* count) {
    if (field == NULL || object == NULL || count == NULL) return CODEC_INVALID_ARGUMENT;
    if (field->array_schema == NULL) {
        *count = 1u;
        return CODEC_OK;
    }
    CODEC_TRY(read_count(field->array_schema, object, count));
    if (*count > field->array_schema->capacity) return CODEC_INVALID_COUNT;
    return CODEC_OK;
}

/* 按本地元素步长定位；单值字段的 index 必须为 0。 */
static codec_status_t field_element(const tlv_field_schema_t* field,
    const uint8_t* object, size_t index,
    const uint8_t** result) {
    size_t size;
    size_t relative_offset;
    if (field == NULL || object == NULL || result == NULL) return CODEC_INVALID_ARGUMENT;
    if (field->array_schema == NULL && index != 0u) return CODEC_INVALID_ARGUMENT;
    if (field->array_schema != NULL && index >= field->array_schema->capacity) return CODEC_INVALID_VALUE;
    CODEC_TRY(element_size(field, &size));
    CODEC_TRY(multiply_size(index, size, &relative_offset));
    if (relative_offset > SIZE_MAX - field->offset) return CODEC_OVERFLOW;
    *result = object + field->offset + relative_offset;
    return CODEC_OK;
}

/* 按 tag 查找字段；未找到时返回 field_count。 */
static size_t find_field(const tlv_message_schema_t* schema, uint16_t tag) {
    size_t index;
    for (index = 0; index < schema->field_count; ++index) {
        if (schema->fields[index].tag == tag) return index;
    }
    return schema->field_count;
}

/* choice 的偏移和类型相同，即视为同一 union 的分支。 */
static int same_choice(const tlv_field_schema_t* left,
    const tlv_field_schema_t* right) {
    if (left == NULL || right == NULL) return 0;
    if (left->union_schema == NULL || right->union_schema == NULL) return 0;
    if (left->union_schema->choice_offset != right->union_schema->choice_offset) {
        return 0;
    }
    if (left->union_schema->choice_type != right->union_schema->choice_type) {
        return 0;
    }
    return 1;
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

/* 编码前先判断 presence，再判断 choice；缺失字段不读取 choice。 */
static codec_status_t field_is_active(const tlv_field_schema_t* field,
    const uint8_t* object,
    int* active) {
    uint64_t choice;

    if (field == NULL || object == NULL || active == NULL) {
        return CODEC_INVALID_VALUE;
    }
    CODEC_TRY(field_is_present(field, object, active));
    if (!*active || field->union_schema == NULL) return CODEC_OK;
    CODEC_TRY(read_choice(field->union_schema, object, &choice));
    *active = choice == field->union_schema->choice_value;
    return CODEC_OK;
}

/* 解码出现状态：非数组字段按下标记录，用于检测重复和 union 冲突。 */
static int field_seen(const uint8_t* seen_fields, size_t index) {
    return (seen_fields[index / 8u] & (uint8_t)(1u << (index % 8u))) != 0u;
}

/* 检查同一 union 是否已有其他分支解码成功。 */
static int choice_seen(const tlv_message_schema_t* schema,
    const uint8_t* seen_fields, size_t field_index) {
    size_t index;
    const tlv_field_schema_t* field;

    if (schema == NULL || field_index >= schema->field_count) return 0;
    field = &schema->fields[field_index];
    if (field->union_schema == NULL) return 0;
    for (index = 0u; index < schema->field_count; ++index) {
        if (index != field_index
            && field_seen(seen_fields, index)
            && same_choice(field, &schema->fields[index])) {
            return 1;
        }
    }
    return 0;
}

/* 编码输入检查：存在的 union 必须有与当前 choice 匹配的分支。 */
static codec_status_t validate_input_choices(
    const tlv_message_schema_t* schema, const uint8_t* object) {
    size_t index;

    if (schema == NULL || object == NULL) return CODEC_INVALID_ARGUMENT;
    for (index = 0u; index < schema->field_count; ++index) {
        const tlv_field_schema_t* field = &schema->fields[index];
        uint64_t choice;
        size_t other;
        int found = 0;

        if (field->union_schema == NULL) continue;
        {
            int present;
            CODEC_TRY(field_is_present(field, object, &present));
            if (!present) continue;
        }
        if (read_choice(field->union_schema, object, &choice)
                != CODEC_OK) {
            return CODEC_INVALID_CHOICE;
        }
        for (other = 0u; other < schema->field_count; ++other) {
            const tlv_field_schema_t* candidate = &schema->fields[other];
            if (same_choice(field, candidate)
                    && candidate->union_schema->choice_value == choice) {
                found = 1;
                break;
            }
        }
        if (!found) return CODEC_INVALID_CHOICE;
    }
    return CODEC_OK;
}

/* 编码长度计算。 */
static codec_status_t measure_message(const tlv_message_schema_t* schema,
    const uint8_t* object, size_t* encoded_size);

/* 单个元素的码流 value 长度，不包含 TLV 头。 */
static codec_status_t value_size(const tlv_field_schema_t* field,
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
        case TLV_VALUE_MESSAGE: return measure_message(field->nested_schema, value, result);
        default: return CODEC_INVALID_VALUE;
    }
}

/* 累加当前消息中所有待编码字段的头部和 value 长度。 */
static codec_status_t measure_message(const tlv_message_schema_t* schema,
    const uint8_t* object, size_t* encoded_size) {
    size_t index;
    size_t total = 0u;

    CODEC_TRY(validate_input_choices(schema, object));

    for (index = 0; index < schema->field_count; ++index) {
        const tlv_field_schema_t* field = &schema->fields[index];
        size_t count;
        size_t item_index;
        int active;

        CODEC_TRY(field_is_active(field, object, &active));
        if (!active) continue;
        CODEC_TRY(field_count(field, object, &count));

        for (item_index = 0; item_index < count; ++item_index) {
            const uint8_t* value;
            size_t length;
            CODEC_TRY(field_element(field, object, item_index, &value));
            CODEC_TRY(value_size(field, value, &length));
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
    return measure_message(schema, (const uint8_t*)input, encoded_size);
}

/* 消息编码。 */

/* 写入单个非 MESSAGE 元素的 value；TLV 头由 encode_message 写入。 */
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

/* 直接写入消息；嵌套 MESSAGE 先占位 length，编码完成后回填。 */
static codec_status_t encode_message(const tlv_message_schema_t* schema,
    const uint8_t* object, tlv_writer_t* writer) {
    size_t index;
    CODEC_TRY(validate_input_choices(schema, object));
    for (index = 0; index < schema->field_count; ++index) {
        const tlv_field_schema_t* field = &schema->fields[index];
        size_t count;
        size_t item_index;
        int active;
        CODEC_TRY(field_is_active(field, object, &active));
        if (!active) continue;
        CODEC_TRY(field_count(field, object, &count));
        for (item_index = 0; item_index < count; ++item_index) {
            const uint8_t* value;
            size_t length;
            CODEC_TRY(field_element(field, object, item_index, &value));
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
                CODEC_TRY(writer_patch_le32(writer, length_offset, (uint32_t)length));
            } else {
                CODEC_TRY(value_size(field, value, &length));
                if (length > UINT32_MAX) return CODEC_OVERFLOW;
                CODEC_TRY(writer_put_le16(writer, field->tag));
                CODEC_TRY(writer_put_le32(writer, (uint32_t)length));
                CODEC_TRY(encode_value(field, value, writer, length));
            }
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

/* 消息解码。 */
static codec_status_t decode_message(const tlv_message_schema_t* schema,
    const uint8_t* input, size_t input_size, uint8_t* object);

/* 解码单个 value；MESSAGE 递归解析，STRING 检查容量并补结尾 NUL。 */
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

/* 数组写入 count 对应的下一个元素；仅在元素解码成功后递增 count。 */
static codec_status_t decode_field(const tlv_field_schema_t* field,
    const tlv_item_t* item, uint8_t* object) {
    size_t count;
    const uint8_t* value;
    if (field->array_schema == NULL) return decode_value(field, item, object + field->offset);
    CODEC_TRY(read_count(field->array_schema, object, &count));
    if (count >= field->array_schema->capacity) return CODEC_ARRAY_CAPACITY_EXCEEDED;
    CODEC_TRY(field_element(field, object, count, &value));
    CODEC_TRY(decode_value(field, item, (uint8_t*)value));
    return write_count(field->array_schema, object, count + 1u);
}

/* 按码流顺序处理字段，跳过未知 tag，检查重复字段和 union 冲突。 */
static codec_status_t decode_message(const tlv_message_schema_t* schema,
    const uint8_t* input, size_t input_size, uint8_t* object) {
    uint8_t seen_fields[schema->field_count / 8u + (schema->field_count % 8u != 0u)];
    tlv_reader_t reader = {input, input_size, 0u};
    memset(seen_fields, 0, sizeof(seen_fields));
    while (reader.offset < reader.size) {
        tlv_item_t item;
        size_t index;
        const tlv_field_schema_t* field;
        CODEC_TRY(reader_next(&reader, &item));
        index = find_field(schema, item.tag);
        if (index == schema->field_count) continue;
        field = &schema->fields[index];
        if (field->array_schema == NULL && field_seen(seen_fields, index)) {
            return CODEC_DUPLICATE_FIELD;
        }
        if (choice_seen(schema, seen_fields, index)) {
            return CODEC_UNION_CONFLICT;
        }
        CODEC_TRY(decode_field(field, &item, object));
        /* 字段完整解码后，再更新 presence、choice 和出现状态。 */
        if (field->present_schema != NULL)
            CODEC_TRY(mark_field_present(field->present_schema, object));
        if (field->union_schema != NULL) {
            CODEC_TRY(write_choice(field->union_schema, object, field->union_schema->choice_value));
        }
        if (field->array_schema == NULL) {
            seen_fields[index / 8u] |= (uint8_t)(1u << (index % 8u));
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
