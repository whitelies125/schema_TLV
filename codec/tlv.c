#include "tlv.h"

#include <limits.h>
#include <stdbool.h>
#include <string.h>

/* TLV 内部布局。 */
#define TLV_TAG_LEN           2u
#define TLV_LENGTH_LEN        4u
#define TLV_HEAD_LEN          (TLV_TAG_LEN + TLV_LENGTH_LEN)

/* 内部调用失败时直接传递具体错误码。 */
#define CODEC_TRY(call) do { \
    codec_status_t status_ = (call); \
    if (status_ != CODEC_OK) return status_; \
} while (0)

/* 内部类型。 */
typedef struct tlv_item {
    uint16_t       tag;
    uint32_t       length;
    const uint8_t* value;
} tlv_item_t;

/* 写入游标统一管理输出空间，不拥有缓冲区。 */
typedef struct tlv_writer {
    uint8_t* buffer;
    size_t capacity;
    size_t offset;
} tlv_writer_t;

/* 读取游标统一管理输入范围，不拥有缓冲区。 */
typedef struct tlv_reader {
    const uint8_t* buffer;
    size_t size;
    size_t offset;
} tlv_reader_t;

/* 按小端字节序读取 16 位整数。 */
/* 基础工具：字节序、长度运算和内存区域。 */
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
    return CODEC_STRING_NOT_TERMINATED;
}

/* 判断同一结构体内两段已验证边界的存储区域是否重叠。 */
static int ranges_overlap(size_t left_offset, size_t left_size,
    size_t right_offset, size_t right_size) {
    return left_offset < right_offset + right_size && right_offset < left_offset + left_size;
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

/* 完整读取一个字段后推进游标，失败时保持偏移不变。 */
static codec_status_t reader_next(tlv_reader_t* reader, tlv_item_t* item) {
    size_t cursor;

    if (reader == NULL || reader->buffer == NULL || item == NULL) return CODEC_INVALID_ARGUMENT;
    if (reader->offset > reader->size || reader->size - reader->offset < TLV_HEAD_LEN)
        return CODEC_TRUNCATED_HEADER;
    cursor = reader->offset;

    // 读取字段编号。
    item->tag = read_le16(reader->buffer + cursor);
    cursor += TLV_TAG_LEN;

    // 读取字段值长度。
    item->length = read_le32(reader->buffer + cursor);
    cursor += TLV_LENGTH_LEN;

    // 读取字段值。
    if ((size_t)item->length > reader->size - cursor) {
        return CODEC_TRUNCATED_VALUE;
    }
    item->value = reader->buffer + cursor;
    reader->offset = cursor + (size_t)item->length;
    return CODEC_OK;
}

/* 根据 count_type 返回数组计数成员的本机内存大小。 */
/* 计数和选择成员共用固定宽度无符号整数访问，不处理码流字节序。 */
static codec_status_t uint_member_size(tlv_value_type_t type, size_t* result) {
    switch (type) {
        case TLV_VALUE_UINT8: *result = sizeof(uint8_t); return CODEC_OK;
        case TLV_VALUE_UINT16: *result = sizeof(uint16_t); return CODEC_OK;
        case TLV_VALUE_UINT32: *result = sizeof(uint32_t); return CODEC_OK;
        case TLV_VALUE_UINT64: *result = sizeof(uint64_t); return CODEC_OK;
        default: return CODEC_INVALID_SCHEMA;
    }
}

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

static codec_status_t count_size(const tlv_array_schema_t* schema, size_t* result) {
    if (schema == NULL || result == NULL) return CODEC_INVALID_ARGUMENT;
    return uint_member_size(schema->count_type, result);
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

static codec_status_t choice_size(tlv_value_type_t type, size_t* result) {
    if (result == NULL) return CODEC_INVALID_ARGUMENT;
    return uint_member_size(type, result);
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

/* 根据字段类型推导单个本机内存元素的大小。 */
static codec_status_t element_size(const tlv_field_schema_t* field, size_t* result) {
    if (field == NULL || result == NULL) return CODEC_INVALID_ARGUMENT;
    switch (field->type) {
        case TLV_VALUE_INT8:
        case TLV_VALUE_UINT8:
            if (field->string_capacity != 0u || field->nested_schema != NULL) return CODEC_SCHEMA_INVALID_FIELD;
            *result = sizeof(uint8_t);
            return CODEC_OK;
        case TLV_VALUE_INT16:
        case TLV_VALUE_UINT16:
            if (field->string_capacity != 0u || field->nested_schema != NULL) return CODEC_SCHEMA_INVALID_FIELD;
            *result = sizeof(uint16_t);
            return CODEC_OK;
        case TLV_VALUE_INT32:
        case TLV_VALUE_UINT32:
            if (field->string_capacity != 0u || field->nested_schema != NULL) return CODEC_SCHEMA_INVALID_FIELD;
            *result = sizeof(uint32_t);
            return CODEC_OK;
        case TLV_VALUE_INT64:
        case TLV_VALUE_UINT64:
            if (field->string_capacity != 0u || field->nested_schema != NULL) return CODEC_SCHEMA_INVALID_FIELD;
            *result = sizeof(uint64_t);
            return CODEC_OK;
        case TLV_VALUE_BOOL:
            if (field->string_capacity != 0u || field->nested_schema != NULL) return CODEC_SCHEMA_INVALID_FIELD;
            *result = sizeof(bool);
            return CODEC_OK;
        case TLV_VALUE_STRING:
            if (field->string_capacity == 0u || field->nested_schema != NULL) return CODEC_SCHEMA_INVALID_FIELD;
            *result = field->string_capacity;
            return CODEC_OK;
        case TLV_VALUE_MESSAGE:
            if (field->string_capacity != 0u || field->nested_schema == NULL
                    || field->nested_schema->struct_size == 0u) return CODEC_SCHEMA_INVALID_FIELD;
            *result = field->nested_schema->struct_size;
            return CODEC_OK;
        default:
            return CODEC_SCHEMA_INVALID_FIELD;
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
    if (field->array_schema->capacity == 0u) return CODEC_SCHEMA_INVALID_ARRAY;
    return multiply_size(field->array_schema->capacity, item_size, result);
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
    if (*count > field->array_schema->capacity) return CODEC_INVALID_COUNT;
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

/* 按 tag 在线性字段表中查找字段下标。 */
static size_t find_field(const tlv_message_schema_t* schema, uint16_t tag) {
    size_t index;
    for (index = 0; index < schema->field_count; ++index) {
        if (schema->fields[index].tag == tag) return index;
    }
    return schema->field_count;
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

/* 判断字段当前是否由 choice 选中。 */
/* 按本机成员类型读取存在标记，不进行码流字节序转换。 */
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

/* 布尔成员写入真值，整数成员按位或并保留其余标志位。 */
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

static codec_status_t field_is_active(const tlv_field_schema_t* field,
    const uint8_t* object,
    int* active) {
    uint64_t choice;

    if (field == NULL || object == NULL || active == NULL) {
        return CODEC_INVALID_VALUE;
    }
    /* 缺失字段不读取其值，长度计算和编码共用此判断。 */
    CODEC_TRY(field_is_present(field, object, active));
    if (!*active) {
        *active = 0;
        return CODEC_OK;
    }
    if (field->union_schema == NULL) {
        *active = 1;
        return CODEC_OK;
    }
    CODEC_TRY(read_choice(field->union_schema, object, &choice));
    *active = choice == field->union_schema->choice_value;
    return CODEC_OK;
}

/* 位图按字段数量分配，不受单个整数位宽限制。 */
static int field_seen(const uint8_t* seen_fields, size_t index) {
    return (seen_fields[index / 8u] & (uint8_t)(1u << (index % 8u))) != 0u;
}

/* 判断同一选择项是否已经解码过其他分支。 */
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

/* 校验 choice 的类型、范围、数组限制和存储区域。 */
static codec_status_t validate_field_choice(
    const tlv_message_schema_t* message,
    const tlv_field_schema_t* field, size_t field_size) {
    size_t choice_bytes;

    if (message == NULL || field == NULL) return CODEC_INVALID_ARGUMENT;
    if (field->union_schema == NULL) return CODEC_OK;
    if (field->array_schema != NULL
            || (field->union_schema->choice_type == TLV_VALUE_UINT8 && field->union_schema->choice_value > UINT8_MAX)
            || (field->union_schema->choice_type == TLV_VALUE_UINT16 && field->union_schema->choice_value > UINT16_MAX)
            || (field->union_schema->choice_type == TLV_VALUE_UINT32 && field->union_schema->choice_value > UINT32_MAX)
            || choice_size(field->union_schema->choice_type, &choice_bytes)
                   != CODEC_OK
            || field->union_schema->choice_offset > message->struct_size
            || choice_bytes > message->struct_size
                                       - field->union_schema->choice_offset
            || ranges_overlap(field->offset, field_size,
                              field->union_schema->choice_offset,
                              choice_bytes)) {
        return CODEC_SCHEMA_INVALID_UNION;
    }
    return CODEC_OK;
}

/* 检查单个字段的类型、布局及辅助描述。 */
static codec_status_t validate_field_schema(const tlv_message_schema_t* schema,
    const tlv_field_schema_t* field) {
    size_t field_size;
    codec_status_t status;
    if (field->present_schema != NULL) {
        const tlv_present_schema_t* present = field->present_schema;
        size_t present_size;
        if (present->type == TLV_VALUE_BOOL) {
            present_size = sizeof(bool);
            if (present->mask != 1u) return CODEC_SCHEMA_INVALID_PRESENCE;
        } else {
            if (uint_member_size(present->type, &present_size) != CODEC_OK)
                return CODEC_SCHEMA_INVALID_PRESENCE;
            if ((present->type == TLV_VALUE_UINT8 && present->mask > UINT8_MAX) ||
                (present->type == TLV_VALUE_UINT16 && present->mask > UINT16_MAX) ||
                (present->type == TLV_VALUE_UINT32 && present->mask > UINT32_MAX))
                return CODEC_SCHEMA_INVALID_PRESENCE;
        }
        if (present->offset > schema->struct_size ||
            present_size > schema->struct_size - present->offset || present->mask == 0u ||
            (present->mask & (present->mask - 1u)) != 0u)
            return CODEC_SCHEMA_INVALID_PRESENCE;
    }
    if (field->tag == 0u) return CODEC_SCHEMA_INVALID_FIELD;
    status = storage_size(field, &field_size);
    /* 存储大小溢出仍按原规则归为非法 schema，其他错误保留具体分类。 */
    if (status != CODEC_OK) return status == CODEC_OVERFLOW ? CODEC_INVALID_SCHEMA : status;
    if (field->offset > schema->struct_size || field_size > schema->struct_size - field->offset) {
        return CODEC_SCHEMA_FIELD_OUT_OF_BOUNDS;
    }
    if (field->type == TLV_VALUE_MESSAGE)
        CODEC_TRY(tlv_validate_schema(field->nested_schema));
    if (field->array_schema != NULL) {
        size_t count_bytes;
        if (count_size(field->array_schema, &count_bytes) != CODEC_OK)
            return CODEC_SCHEMA_INVALID_ARRAY;
        if (field->array_schema->count_offset > schema->struct_size
                || count_bytes > schema->struct_size - field->array_schema->count_offset
                || ranges_overlap(field->offset, field_size, field->array_schema->count_offset, count_bytes)) {
            return CODEC_SCHEMA_INVALID_ARRAY;
        }
    }
    CODEC_TRY(validate_field_choice(schema, field, field_size));
    return CODEC_OK;
}

/* 只排序字段下标，不修改调用方的描述；choice 按组和选择值排列。 */
static int field_order_less(const tlv_message_schema_t* schema,
    uint16_t left, uint16_t right, bool by_choice) {
    const tlv_field_schema_t* a = &schema->fields[left];
    const tlv_field_schema_t* b = &schema->fields[right];
    if (!by_choice) return a->offset < b->offset;
    if (a->union_schema->choice_offset != b->union_schema->choice_offset)
        return a->union_schema->choice_offset < b->union_schema->choice_offset;
    if (a->union_schema->choice_type != b->union_schema->choice_type)
        return a->union_schema->choice_type < b->union_schema->choice_type;
    return a->union_schema->choice_value < b->union_schema->choice_value;
}

static void sift_field_order(const tlv_message_schema_t* schema,
    uint16_t* order, size_t count, size_t root, bool by_choice) {
    while (root < count / 2u) {
        size_t child = root * 2u + 1u;
        uint16_t temporary;
        if (child + 1u < count && field_order_less(schema, order[child], order[child + 1u], by_choice))
            ++child;
        if (!field_order_less(schema, order[root], order[child], by_choice)) break;
        temporary = order[root];
        order[root] = order[child];
        order[child] = temporary;
        root = child;
    }
}

/* 堆排序保证 O(n log n)，不使用堆分配或递归排序。 */
static void sort_field_order(const tlv_message_schema_t* schema,
    uint16_t* order, size_t count, bool by_choice) {
    size_t index;
    for (index = count / 2u; index != 0u; --index)
        sift_field_order(schema, order, count, index - 1u, by_choice);
    for (index = count; index > 1u; --index) {
        uint16_t temporary = order[0];
        order[0] = order[index - 1u];
        order[index - 1u] = temporary;
        sift_field_order(schema, order, index - 1u, 0u, by_choice);
    }
}

/* 单字段与子消息已校验完毕，再使用临时索引检查当前层的字段关系。 */
static codec_status_t validate_field_layout(const tlv_message_schema_t* schema,
    size_t union_count, uint16_t max_tag) {
    uint8_t seen_tags[(size_t)max_tag / 8u + 1u];
    /* 非零且唯一的 uint16_t tag 保证字段下标也能用 uint16_t 表示。 */
    uint16_t data_order[schema->field_count];
    uint16_t union_order[union_count != 0u ? union_count : 1u];
    size_t union_index = 0u;
    size_t active_end = 0u;
    size_t index;
    const tlv_field_schema_t* active = NULL;
    memset(seen_tags, 0, sizeof(seen_tags));
    for (index = 0u; index < schema->field_count; ++index) {
        const tlv_field_schema_t* field = &schema->fields[index];
        if (field_seen(seen_tags, field->tag)) return CODEC_SCHEMA_DUPLICATE_TAG;
        seen_tags[field->tag / 8u] |= (uint8_t)(1u << (field->tag % 8u));
        data_order[index] = (uint16_t)index;
        if (field->union_schema != NULL)
            union_order[union_index++] = (uint16_t)index;
    }

    sort_field_order(schema, data_order, schema->field_count, false);
    for (index = 0u; index < schema->field_count; ++index) {
        const tlv_field_schema_t* field = &schema->fields[data_order[index]];
        size_t size;
        size_t end;
        CODEC_TRY(storage_size(field, &size));
        end = field->offset + size;
        if (active != NULL && field->offset < active_end) {
            if (!same_choice(field, active)) return CODEC_SCHEMA_FIELD_OVERLAP;
            if (end > active_end) active_end = end;
        } else {
            active = field;
            active_end = end;
        }
    }

    sort_field_order(schema, union_order, union_count, true);
    size_t data_index = 0u;
    const tlv_field_schema_t* previous = NULL;
    for (index = 0u; index < union_count; ++index) {
        const tlv_field_schema_t* field = &schema->fields[union_order[index]];
        const tlv_union_schema_t* choice = field->union_schema;
        size_t choice_bytes;
        if (same_choice(field, previous)) {
            const tlv_present_schema_t* a = field->present_schema;
            const tlv_present_schema_t* b = previous->present_schema;
            if (choice->choice_value == previous->union_schema->choice_value)
                return CODEC_SCHEMA_DUPLICATE_CHOICE;
            if ((a == NULL) != (b == NULL) ||
                (a != NULL && (a->offset != b->offset || a->type != b->type || a->mask != b->mask)))
                return CODEC_SCHEMA_PRESENCE_MISMATCH;
        }
        CODEC_TRY(choice_size(choice->choice_type, &choice_bytes));
        /* 已扫描的数据若不冲突，其末端不超过前一个 choice 的起点。 */
        while (data_index < schema->field_count) {
            const tlv_field_schema_t* data = &schema->fields[data_order[data_index]];
            size_t size;
            if (data->offset >= choice->choice_offset + choice_bytes) break;
            CODEC_TRY(storage_size(data, &size));
            if (data->offset + size > choice->choice_offset) return CODEC_SCHEMA_FIELD_OVERLAP;
            ++data_index;
        }
        previous = field;
    }
    return CODEC_OK;
}

/* 校验 schema 的类型、偏移、数组计数、choice、存储区域和重复 tag。 */
codec_status_t tlv_validate_schema(const tlv_message_schema_t* schema) {
    size_t index;
    size_t union_count = 0u;
    uint16_t max_tag = 0u;
    if (schema == NULL) return CODEC_INVALID_ARGUMENT;
    if (schema->struct_size == 0u || schema->fields == NULL ||
        schema->field_count == 0u || schema->field_count > UINT16_MAX)
        return CODEC_INVALID_SCHEMA;
    for (index = 0u; index < schema->field_count; ++index) {
        const tlv_field_schema_t* field = &schema->fields[index];
        CODEC_TRY(validate_field_schema(schema, field));
        if (field->tag > max_tag) max_tag = field->tag;
        if (field->union_schema != NULL) ++union_count;
    }
    if (schema->field_count == 1u) return CODEC_OK;
    return validate_field_layout(schema, union_count, max_tag);
}

/* 校验输入对象中的 choice 值是否存在对应字段。 */
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

/* 计算一个字段元素编码为 TLV value 后所需的实际字节数。 */
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

/* 计算消息按 schema 编码所需的 TLV payload 大小。 */
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

/* 公开入口检查参数，子消息使用内部长度计算。 */
codec_status_t tlv_encode_size(const tlv_message_schema_t* schema,
    const void* input, size_t* encoded_size) {
    if (schema == NULL || input == NULL || encoded_size == NULL) return CODEC_INVALID_ARGUMENT;
    return measure_message(schema, (const uint8_t*)input, encoded_size);
}

/* 将单个字段元素写为 TLV value，不写 tag 和 length。 */
/* 消息编码。 */
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

/* 直接编码消息；嵌套字段编码完成后回填实际长度。 */
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

/* 公开入口检查参数，内部递归共用写入游标。 */
codec_status_t tlv_encode(const tlv_message_schema_t* schema,
    const void* input, uint8_t* buffer,
    size_t buffer_size) {
    tlv_writer_t writer = {buffer, buffer_size, 0u};
    if (schema == NULL || input == NULL || buffer == NULL) return CODEC_INVALID_ARGUMENT;
    return encode_message(schema, (const uint8_t*)input, &writer);
}

/* 消息解码。 */
static codec_status_t decode_message(const tlv_message_schema_t* schema,
    const uint8_t* input, size_t input_size, uint8_t* object);

static codec_status_t decode_value(const tlv_field_schema_t* field,
    const tlv_item_t* item, uint8_t* destination) {
    size_t size;
    if (field == NULL || item == NULL || destination == NULL) return CODEC_INVALID_ARGUMENT;
    CODEC_TRY(element_size(field, &size));
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
                memcpy(destination, item->value, item->length);
            }
            destination[item->length] = '\0';
            return CODEC_OK;
        case TLV_VALUE_MESSAGE:
            return decode_message(field->nested_schema, item->value, item->length, destination);
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
    if (count >= field->array_schema->capacity) return CODEC_ARRAY_CAPACITY_EXCEEDED;
    CODEC_TRY(field_element(field, object, count, &value));
    CODEC_TRY(decode_value(field, item, (uint8_t*)value));
    return write_count(field->array_schema, object, count + 1u);
}

/* 按 schema 将 TLV payload 解码到调用方提供的消息对象。 */
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
        /* 仅在字段完整解码成功后置位，不影响同字节中的其他标记。 */
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

/* 公开入口检查目标容量，子消息共用调用方保证合法的结构描述递归解码。 */
codec_status_t tlv_decode(const tlv_message_schema_t* schema,
    const uint8_t* input, size_t input_size, void* buffer, size_t buffer_size) {
    if (input == NULL || buffer == NULL || schema == NULL) return CODEC_INVALID_ARGUMENT;
    if (buffer_size < schema->struct_size) return CODEC_BUFFER_TOO_SMALL;
    return decode_message(schema, input, input_size, (uint8_t*)buffer);
}
