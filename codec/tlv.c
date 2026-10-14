#include "tlv.h"

#include <limits.h>
#include <string.h>

/* TLV 内部布局与实现限制。 */
#define TLV_TAG_LEN           2u
#define TLV_LENGTH_LEN        4u
#define TLV_HEAD_LEN          (TLV_TAG_LEN + TLV_LENGTH_LEN)
#define TLV_MAX_SCHEMA_FIELDS 64u

/* ????????????? */
#define CODEC_TRY(call) do { \
    codec_status_t status_ = (call); \
    if (status_ != CODEC_OK) return status_; \
} while (0)

typedef struct tlv_item {
    uint16_t       tag;
    uint32_t       length;
    const uint8_t* value;
} tlv_item_t;

/* 按小端字节序读取 16 位整数。 */
static uint16_t read_le16(const uint8_t* input) {
    return (uint16_t)input[0] | ((uint16_t)input[1] << 8);
}

/* 按小端字节序读取 32 位整数。 */
static uint32_t read_le32(const uint8_t* input) {
    return (uint32_t)input[0]
        | ((uint32_t)input[1] << 8)
        | ((uint32_t)input[2] << 16)
        | ((uint32_t)input[3] << 24);
}

/* 按小端字节序读取 64 位整数。 */
static uint64_t read_le64(const uint8_t* input) {
    return (uint64_t)read_le32(input)
        | ((uint64_t)read_le32(input + 4) << 32);
}

/* 按小端字节序写入 16 位整数。 */
static void write_le16(uint8_t* output, uint16_t value) {
    output[0] = (uint8_t)value;
    output[1] = (uint8_t)(value >> 8);
}

/* 按小端字节序写入 32 位整数。 */
static void write_le32(uint8_t* output, uint32_t value) {
    output[0] = (uint8_t)value;
    output[1] = (uint8_t)(value >> 8);
    output[2] = (uint8_t)(value >> 16);
    output[3] = (uint8_t)(value >> 24);
}

/* 按小端字节序写入 64 位整数。 */
static void write_le64(uint8_t* output, uint64_t value) {
    write_le32(output, (uint32_t)value);
    write_le32(output + 4, (uint32_t)(value >> 32));
}

/* 读取下一个 TLV，并检查头部和值是否完整。 */
static codec_status_t tlv_read_next(const uint8_t* input, size_t input_size,
                                   size_t* offset, tlv_item_t* item) {
    size_t cursor;

    if (input == NULL || offset == NULL || item == NULL) return CODEC_INVALID_ARGUMENT;
    if (*offset > input_size || input_size - *offset < TLV_HEAD_LEN) return CODEC_TRUNCATED_DATA;
    cursor = *offset;

    // 读取字段编号。
    item->tag = read_le16(input + cursor);
    cursor += TLV_TAG_LEN;

    // 读取字段值长度。
    item->length = read_le32(input + cursor);
    cursor += TLV_LENGTH_LEN;

    // 读取字段值。
    if ((size_t)item->length > input_size - cursor) {
        return CODEC_TRUNCATED_DATA;
    }
    item->value = input + cursor;
    *offset = cursor + (size_t)item->length;
    return CODEC_OK;
}

/* 安全加法，检测 size_t 加法溢出。 */
static codec_status_t add_size(size_t* total, size_t value) {
    if (total == NULL || value > SIZE_MAX - *total) {
        return CODEC_OVERFLOW;
    }
    *total += value;
    return CODEC_OK;
}

/* 安全乘法，检测 size_t 乘法溢出。 */
static codec_status_t multiply_size(size_t left, size_t right, size_t* result) {
    if (result == NULL || (left != 0u && right > SIZE_MAX / left)) {
        return CODEC_OVERFLOW;
    }
    *result = left * right;
    return CODEC_OK;
}

/* 在固定容量字符串中查找结尾 NUL，返回实际编码长度。 */
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
    return CODEC_INVALID_VALUE;
}

/* 根据字段类型推导单个本机内存元素的大小。 */
static codec_status_t element_size(const tlv_field_schema_t* field, size_t* result) {
    if (field == NULL || result == NULL) return CODEC_INVALID_ARGUMENT;
    switch (field->type) {
        case TLV_VALUE_BOOL:
            if (field->string_capacity != 0u || field->nested_schema != NULL) return CODEC_INVALID_SCHEMA;
            *result = sizeof(uint8_t);
            return CODEC_OK;
        case TLV_VALUE_INT64:
            if (field->string_capacity != 0u || field->nested_schema != NULL) return CODEC_INVALID_SCHEMA;
            *result = sizeof(int64_t);
            return CODEC_OK;
        case TLV_VALUE_UINT32:
            if (field->string_capacity != 0u || field->nested_schema != NULL) return CODEC_INVALID_SCHEMA;
            *result = sizeof(uint32_t);
            return CODEC_OK;
        case TLV_VALUE_UINT64:
            if (field->string_capacity != 0u || field->nested_schema != NULL) return CODEC_INVALID_SCHEMA;
            *result = sizeof(uint64_t);
            return CODEC_OK;
        case TLV_VALUE_STRING:
            if (field->string_capacity == 0u || field->nested_schema != NULL) return CODEC_INVALID_SCHEMA;
            *result = field->string_capacity;
            return CODEC_OK;
        case TLV_VALUE_MESSAGE:
            if (field->string_capacity != 0u || field->nested_schema == NULL
                    || field->nested_schema->struct_size == 0u) return CODEC_INVALID_SCHEMA;
            *result = field->nested_schema->struct_size;
            return CODEC_OK;
        default:
            return CODEC_INVALID_SCHEMA;
    }
}

/* 计算字段在所属结构体中占用的完整存储空间。 */
static codec_status_t storage_size(const tlv_field_schema_t* field, size_t* result) {
    size_t item_size;
    CODEC_TRY(element_size(field, &item_size));
    if (field->array_schema == NULL) {
        *result = item_size;
        return CODEC_OK;
    }
    if (field->array_schema->capacity == 0u) return CODEC_INVALID_SCHEMA;
    return multiply_size(field->array_schema->capacity, item_size, result);
}

/* 根据 count_type 返回数组计数成员的本机内存大小。 */
static codec_status_t count_size(const tlv_array_schema_t* schema,
                                    size_t* result) {
    if (schema == NULL || result == NULL) return CODEC_INVALID_ARGUMENT;
    if (schema->count_type == TLV_VALUE_UINT32) {
        *result = sizeof(uint32_t);
        return CODEC_OK;
    }
    if (schema->count_type == TLV_VALUE_UINT64) {
        *result = sizeof(uint64_t);
        return CODEC_OK;
    }
    return CODEC_INVALID_SCHEMA;
}

/* 按 count_type 从结构体中读取数组元素数量。 */
static codec_status_t read_count(const tlv_array_schema_t* schema,
                                    const uint8_t* object, size_t* result) {
    uint32_t count32;
    uint64_t count64;

    if (schema == NULL || object == NULL || result == NULL) return CODEC_INVALID_ARGUMENT;

    if (schema->count_type == TLV_VALUE_UINT32) {
        memcpy(&count32, object + schema->count_offset, sizeof(count32));
        *result = (size_t)count32;
        return CODEC_OK;
    }
    if (schema->count_type == TLV_VALUE_UINT64) {
        memcpy(&count64, object + schema->count_offset, sizeof(count64));
        if (count64 > SIZE_MAX) return CODEC_OVERFLOW;
        *result = (size_t)count64;
        return CODEC_OK;
    }
    return CODEC_INVALID_VALUE;
}

/* 按 count_type 将数组元素数量写回结构体。 */
static codec_status_t write_count(const tlv_array_schema_t* schema,
                                     uint8_t* object, size_t count) {
    uint32_t count32;
    uint64_t count64;
    if (schema == NULL || object == NULL) return CODEC_INVALID_ARGUMENT;
    if (schema->count_type == TLV_VALUE_UINT32) {
        if (count > UINT32_MAX) return CODEC_OVERFLOW;
        count32 = (uint32_t)count;
        memcpy(object + schema->count_offset, &count32, sizeof(count32));
        return CODEC_OK;
    }
    if (schema->count_type == TLV_VALUE_UINT64) {
        count64 = (uint64_t)count;
        memcpy(object + schema->count_offset, &count64, sizeof(count64));
        return CODEC_OK;
    }
    return CODEC_INVALID_VALUE;
}

/* 判断同一结构体内两段已验证边界的存储区域是否重叠。 */
static int ranges_overlap(size_t left_offset, size_t left_size,
                          size_t right_offset, size_t right_size) {
    return left_offset < right_offset + right_size && right_offset < left_offset + left_size;
}

/* 获取 choice 类型对应的本机存储大小。 */
static codec_status_t choice_size(tlv_value_type_t type,
                                     size_t* result) {
    if (result == NULL) return CODEC_INVALID_ARGUMENT;
    if (type == TLV_VALUE_UINT32) {
        *result = sizeof(uint32_t);
        return CODEC_OK;
    }
    if (type == TLV_VALUE_UINT64) {
        *result = sizeof(uint64_t);
        return CODEC_OK;
    }
    return CODEC_INVALID_SCHEMA;
}

/* 从结构体中读取 choice 值。 */
static codec_status_t read_choice(
    const tlv_union_schema_t* schema, const uint8_t* object,
    uint32_t* result) {
    uint64_t value64;

    if (schema == NULL || object == NULL || result == NULL) {
        return CODEC_INVALID_VALUE;
    }
    if (schema->choice_type == TLV_VALUE_UINT32) {
        memcpy(result, object + schema->choice_offset,
               sizeof(uint32_t));
        return CODEC_OK;
    }
    if (schema->choice_type == TLV_VALUE_UINT64) {
        memcpy(&value64, object + schema->choice_offset,
               sizeof(value64));
        if (value64 > UINT32_MAX) return CODEC_INVALID_VALUE;
        *result = (uint32_t)value64;
        return CODEC_OK;
    }
    return CODEC_INVALID_VALUE;
}

/* 将 choice 值写回结构体。 */
static codec_status_t write_choice(
    const tlv_union_schema_t* schema, uint8_t* object, uint32_t value) {
    uint64_t value64;

    if (schema == NULL || object == NULL) return CODEC_INVALID_ARGUMENT;

    switch (schema->choice_type) {
        case TLV_VALUE_UINT32:
            memcpy(object + schema->choice_offset, &value,
                   sizeof(value));
            return CODEC_OK;
        case TLV_VALUE_UINT64:
            value64 = value;
            memcpy(object + schema->choice_offset, &value64,
                   sizeof(value64));
            return CODEC_OK;
        default:
            return CODEC_INVALID_VALUE;
    }
}

/* 判断两个字段是否属于同一个 choice。 */
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

/* 校验 choice 的类型、范围、数组限制和存储区域。 */
static codec_status_t validate_field_choice(
    const tlv_message_schema_t* message,
    const tlv_field_schema_t* field, size_t field_size) {
    size_t choice_bytes;

    if (message == NULL || field == NULL) return CODEC_INVALID_ARGUMENT;
    if (field->union_schema == NULL) return CODEC_OK;
    if (field->array_schema != NULL
            || field->union_schema->choice_value == 0u
            || choice_size(field->union_schema->choice_type, &choice_bytes)
                   != CODEC_OK
            || field->union_schema->choice_offset > message->struct_size
            || choice_bytes > message->struct_size
                                       - field->union_schema->choice_offset
            || ranges_overlap(field->offset, field_size,
                              field->union_schema->choice_offset,
                              choice_bytes)) {
        return CODEC_INVALID_SCHEMA;
    }
    return CODEC_OK;
}

/* 校验 schema 的类型、偏移、数组计数、choice、存储区域和重复 tag。 */
static codec_status_t validate_schema(const tlv_message_schema_t* schema) {
    size_t index;

    if (schema == NULL || schema->struct_size == 0u
            || schema->field_count > TLV_MAX_SCHEMA_FIELDS
            || (schema->field_count != 0u && schema->fields == NULL)
            || schema->field_count == 0u) {
        return CODEC_INVALID_SCHEMA;
    }
    for (index = 0u; index < schema->field_count; ++index) {
        const tlv_field_schema_t* field = &schema->fields[index];
        size_t field_size;
        size_t other;
        if (field->tag == 0u || storage_size(field, &field_size) != CODEC_OK) {
            return CODEC_INVALID_SCHEMA;
        }
        if (field->offset > schema->struct_size || field_size > schema->struct_size - field->offset) {
            return CODEC_INVALID_SCHEMA;
        }
        if (field->type == TLV_VALUE_MESSAGE && validate_schema(field->nested_schema) != CODEC_OK) {
            return CODEC_INVALID_SCHEMA;
        }
        if (field->array_schema != NULL) {
            size_t count_bytes;
            CODEC_TRY(count_size(field->array_schema, &count_bytes));
            if (field->array_schema->count_offset > schema->struct_size
                    || count_bytes > schema->struct_size - field->array_schema->count_offset
                    || ranges_overlap(field->offset, field_size, field->array_schema->count_offset, count_bytes)) {
                return CODEC_INVALID_SCHEMA;
            }
        }
        CODEC_TRY(validate_field_choice(schema, field, field_size));
        for (other = 0u; other < index; ++other) {
            const tlv_field_schema_t* previous = &schema->fields[other];
            size_t previous_size;
            size_t field_choice_bytes = 0u;
            size_t previous_choice_bytes = 0u;
            if (previous->tag == field->tag || storage_size(previous, &previous_size) != CODEC_OK) {
                return CODEC_INVALID_SCHEMA;
            }
            if (field->union_schema != NULL && choice_size(field->union_schema->choice_type, &field_choice_bytes) != CODEC_OK) {
                return CODEC_INVALID_SCHEMA;
            }
            if (previous->union_schema != NULL && choice_size(previous->union_schema->choice_type, &previous_choice_bytes) != CODEC_OK) {
                return CODEC_INVALID_SCHEMA;
            }
            if (ranges_overlap(field->offset, field_size, previous->offset, previous_size) && !same_choice(field, previous)) {
                return CODEC_INVALID_SCHEMA;
            }
            if (field->union_schema != NULL && ranges_overlap(previous->offset, previous_size, field->union_schema->choice_offset, field_choice_bytes)) {
                return CODEC_INVALID_SCHEMA;
            }
            if (previous->union_schema != NULL && ranges_overlap(field->offset, field_size, previous->union_schema->choice_offset, previous_choice_bytes)) {
                return CODEC_INVALID_SCHEMA;
            }
            if (same_choice(field, previous) && field->union_schema->choice_value == previous->union_schema->choice_value) {
                return CODEC_INVALID_SCHEMA;
            }
        }
    }
    return CODEC_OK;
}

/* 按 tag 在线性字段表中查找字段下标。 */
static size_t find_field(const tlv_message_schema_t* schema, uint16_t tag) {
    size_t index;
    for (index = 0; index < schema->field_count; ++index) if (schema->fields[index].tag == tag) return index;
    return schema->field_count;
}

/* 获取字段编码时应处理的元素数量；单值字段数量固定为一。 */
static codec_status_t field_count(const tlv_field_schema_t* field,
                                     const uint8_t* object, size_t* count) {
    if (field == NULL || object == NULL || count == NULL) return CODEC_INVALID_ARGUMENT;
    if (field->array_schema == NULL) {
        *count = 1u;
        return CODEC_OK;
    }
    CODEC_TRY(read_count(field->array_schema, object, count));
    if (*count > field->array_schema->capacity) return CODEC_INVALID_VALUE;
    return CODEC_OK;
}

/* 计算字段中指定数组元素的本机内存地址。 */
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

/* 计算一个字段元素编码为 TLV value 后所需的实际字节数。 */
static codec_status_t value_size(const tlv_field_schema_t* field,
                                    const uint8_t* value, size_t* result) {
    if (field == NULL || value == NULL || result == NULL) return CODEC_INVALID_ARGUMENT;
    switch (field->type) {
        case TLV_VALUE_BOOL: *result = sizeof(uint8_t); return CODEC_OK;
        case TLV_VALUE_INT64: *result = sizeof(int64_t); return CODEC_OK;
        case TLV_VALUE_UINT32: *result = sizeof(uint32_t); return CODEC_OK;
        case TLV_VALUE_UINT64: *result = sizeof(uint64_t); return CODEC_OK;
        case TLV_VALUE_STRING: return string_length((const char*)value, field->string_capacity, result);
        case TLV_VALUE_MESSAGE: return tlv_encode_size(field->nested_schema, value, result);
        default: return CODEC_INVALID_VALUE;
    }
}

/* 判断字段当前是否由 choice 选中。 */
static codec_status_t field_is_active(const tlv_field_schema_t* field,
                                         const uint8_t* object,
                                         int* active) {
    uint32_t choice;

    if (field == NULL || object == NULL || active == NULL) {
        return CODEC_INVALID_VALUE;
    }
    if (field->union_schema == NULL) {
        *active = 1;
        return CODEC_OK;
    }
    CODEC_TRY(read_choice(field->union_schema, object, &choice));
    *active = choice != 0u && choice == field->union_schema->choice_value;
    return CODEC_OK;
}

/* 校验输入对象中的 choice 值是否存在对应字段。 */
static codec_status_t validate_input_choices(
    const tlv_message_schema_t* schema, const uint8_t* object) {
    size_t index;

    if (schema == NULL || object == NULL) return CODEC_INVALID_ARGUMENT;
    for (index = 0u; index < schema->field_count; ++index) {
        const tlv_field_schema_t* field = &schema->fields[index];
        uint32_t choice;
        size_t other;
        int found = 0;

        if (field->union_schema == NULL) continue;
        if (read_choice(field->union_schema, object, &choice)
                != CODEC_OK) {
            return CODEC_INVALID_VALUE;
        }
        if (choice == 0u) continue;
        for (other = 0u; other < schema->field_count; ++other) {
            const tlv_field_schema_t* candidate = &schema->fields[other];
            if (same_choice(field, candidate)
                    && candidate->union_schema->choice_value == choice) {
                found = 1;
                break;
            }
        }
        if (!found) return CODEC_INVALID_VALUE;
    }
    return CODEC_OK;
}

/* 判断同一选择项是否已经解码过其他分支。 */
static int choice_seen(const tlv_message_schema_t* schema,
                       uint64_t seen_fields, size_t field_index) {
    size_t index;
    const tlv_field_schema_t* field;

    if (schema == NULL || field_index >= schema->field_count) return 0;
    field = &schema->fields[field_index];
    if (field->union_schema == NULL) return 0;
    for (index = 0u; index < schema->field_count; ++index) {
        if (index != field_index
            && (seen_fields & ((uint64_t)1u << index)) != 0u
            && same_choice(field, &schema->fields[index])) {
            return 1;
        }
    }
    return 0;
}

/* 计算消息按 schema 编码所需的 TLV payload 大小。 */
codec_status_t tlv_encode_size(const tlv_message_schema_t* schema,
                                     const void* input, size_t* encoded_size) {
    const uint8_t* object = (const uint8_t*)input;
    size_t index;
    size_t total = 0u;

    if (schema == NULL || input == NULL || encoded_size == NULL) return CODEC_INVALID_ARGUMENT;
    CODEC_TRY(validate_schema(schema));
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

/* 将单个字段元素写为 TLV value，不写 tag 和 length。 */
static codec_status_t encode_value(const tlv_field_schema_t* field,
                                      const uint8_t* value, uint8_t* buffer,
                                      size_t length) {
    switch (field->type) {
        case TLV_VALUE_BOOL:
            buffer[0] = *value;
            return CODEC_OK;
        case TLV_VALUE_INT64: {
            uint64_t scalar;
            memcpy(&scalar, value, sizeof(scalar));
            write_le64(buffer, scalar);
            return CODEC_OK;
        }
        case TLV_VALUE_UINT32: {
            uint32_t scalar;
            memcpy(&scalar, value, sizeof(scalar));
            write_le32(buffer, scalar);
            return CODEC_OK;
        }
        case TLV_VALUE_UINT64: {
            uint64_t scalar;
            memcpy(&scalar, value, sizeof(scalar));
            write_le64(buffer, scalar);
            return CODEC_OK;
        }
        case TLV_VALUE_STRING:
            if (length != 0u) memcpy(buffer, value, length);
            return CODEC_OK;
        case TLV_VALUE_MESSAGE:
            return tlv_encode(field->nested_schema, value, buffer, length);
        default:
            return CODEC_INVALID_VALUE;
    }
}

/* 按 schema 将消息编码为 TLV payload。 */
codec_status_t tlv_encode(const tlv_message_schema_t* schema,
                                const void* input, uint8_t* buffer,
                                size_t buffer_size) {
    const uint8_t* object = (const uint8_t*)input;
    size_t expected_size;
    size_t index;
    size_t cursor = 0u;
    if (schema == NULL || input == NULL || buffer == NULL) return CODEC_INVALID_ARGUMENT;
    CODEC_TRY(tlv_encode_size(schema, input, &expected_size));
    if (buffer_size < expected_size) return CODEC_BUFFER_TOO_SMALL;
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
            write_le16(buffer + cursor, field->tag);
            cursor += TLV_TAG_LEN;
            write_le32(buffer + cursor, (uint32_t)length);
            cursor += TLV_LENGTH_LEN;
            CODEC_TRY(encode_value(field, value, buffer + cursor, length));
            cursor += length;
        }
    }
    return cursor == expected_size ? CODEC_OK : CODEC_FAILED;
}

/* 将单个 TLV value 解码至指定字段元素，不处理数组下标。 */
static codec_status_t decode_value(const tlv_field_schema_t* field,
                                      const tlv_item_t* item, uint8_t* destination) {
    size_t size;
    if (field == NULL || item == NULL || destination == NULL) return CODEC_INVALID_ARGUMENT;
    CODEC_TRY(element_size(field, &size));
    switch (field->type) {
        case TLV_VALUE_BOOL:
            if (item->length != sizeof(uint8_t)) {
                return CODEC_INVALID_DATA;
            }
            *destination = item->value[0];
            return CODEC_OK;
        case TLV_VALUE_INT64: {
            uint64_t scalar;
            if (item->length != sizeof(scalar)) {
                return CODEC_INVALID_DATA;
            }
            scalar = read_le64(item->value);
            memcpy(destination, &scalar, sizeof(scalar));
            return CODEC_OK;
        }
        case TLV_VALUE_UINT32: {
            uint32_t scalar;
            if (item->length != sizeof(scalar)) {
                return CODEC_INVALID_DATA;
            }
            scalar = read_le32(item->value);
            memcpy(destination, &scalar, sizeof(scalar));
            return CODEC_OK;
        }
        case TLV_VALUE_UINT64: {
            uint64_t scalar;
            if (item->length != sizeof(scalar)) {
                return CODEC_INVALID_DATA;
            }
            scalar = read_le64(item->value);
            memcpy(destination, &scalar, sizeof(scalar));
            return CODEC_OK;
        }
        case TLV_VALUE_STRING:
            if ((size_t)item->length >= field->string_capacity) {
                return CODEC_BUFFER_TOO_SMALL;
            }
            if (item->length != 0u) {
                memcpy(destination, item->value, item->length);
            }
            destination[item->length] = '\0';
            return CODEC_OK;
        case TLV_VALUE_MESSAGE:
            return tlv_decode(field->nested_schema, item->value, item->length, destination, size);
        default:
            return CODEC_INVALID_DATA;
    }
}

/* 为单值字段或数组下一个元素执行解码并更新数组计数。 */
static codec_status_t decode_field(const tlv_field_schema_t* field,
                                      const tlv_item_t* item, uint8_t* object) {
    size_t count;
    const uint8_t* value;
    if (field->array_schema == NULL) return decode_value(field, item, object + field->offset);
    CODEC_TRY(read_count(field->array_schema, object, &count));
    if (count >= field->array_schema->capacity) return CODEC_BUFFER_TOO_SMALL;
    CODEC_TRY(field_element(field, object, count, &value));
    CODEC_TRY(decode_value(field, item, (uint8_t*)value));
    return write_count(field->array_schema, object, count + 1u);
}

/* 按 schema 将 TLV payload 解码到调用方提供的消息对象。 */
codec_status_t tlv_decode(const tlv_message_schema_t* schema,
                                const uint8_t* input, size_t input_size,
                                void* buffer, size_t buffer_size) {
    uint8_t* object = (uint8_t*)buffer;
    uint64_t seen_fields = 0u;
    size_t cursor = 0u;
    if (input == NULL || buffer == NULL || schema == NULL) return CODEC_INVALID_ARGUMENT;
    CODEC_TRY(validate_schema(schema));
    if (buffer_size < schema->struct_size) return CODEC_BUFFER_TOO_SMALL;
    while (cursor < input_size) {
        tlv_item_t item;
        size_t index;
        const tlv_field_schema_t* field;
        CODEC_TRY(tlv_read_next(input, input_size, &cursor, &item));
        index = find_field(schema, item.tag);
        if (index != schema->field_count) {
            field = &schema->fields[index];
            if (field->array_schema == NULL && (seen_fields & ((uint64_t)1u << index)) != 0u) {
                return CODEC_INVALID_DATA;
            }
            if (choice_seen(schema, seen_fields, index)) {
                return CODEC_INVALID_DATA;
            }
            CODEC_TRY(decode_field(field, &item, object));
            if (field->union_schema != NULL && write_choice(field->union_schema, object, field->union_schema->choice_value) != CODEC_OK) {
                return CODEC_INVALID_DATA;
            }
            if (field->array_schema == NULL) {
                seen_fields |= (uint64_t)1u << index;
            }
            continue;
        }
    }
    return CODEC_OK;
}
