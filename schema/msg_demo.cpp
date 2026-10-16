#include "msg_demo.h"

// 子结构体的字段编号独立于外层消息。
static const tlv_field_schema_t version_fields[] = {
    {.tag = 1, .offset = offsetof(version, major), .type = TLV_VALUE_UINT32},
    {.tag = 2, .offset = offsetof(version, minor), .type = TLV_VALUE_UINT32},
    {.tag = 3, .offset = offsetof(version, patch), .type = TLV_VALUE_UINT32}
};
static const tlv_message_schema_t version_schema = {
    .struct_size = sizeof(version),
    .field_count = sizeof(version_fields) / sizeof(version_fields[0]),
    .fields = version_fields
};

static const tlv_field_schema_t simple_fields[] = {
    {.tag = 1, .offset = offsetof(msg_simple, transId), .type = TLV_VALUE_UINT32},
    {.tag = 2, .offset = offsetof(msg_simple, name), .type = TLV_VALUE_STRING, .string_capacity = sizeof(((msg_simple *)0)->name)}
};
const tlv_message_schema_t msg_simple_schema = {
    .struct_size = sizeof(msg_simple),
    .field_count = sizeof(simple_fields) / sizeof(simple_fields[0]),
    .fields = simple_fields
};

static const tlv_field_schema_t nested_fields[] = {
    {.tag = 1, .offset = offsetof(msg_nested, transId), .type = TLV_VALUE_UINT32},
    {.tag = 2, .offset = offsetof(msg_nested, client_version), .type = TLV_VALUE_MESSAGE, .nested_schema = &version_schema}
};
const tlv_message_schema_t msg_nested_schema = {
    .struct_size = sizeof(msg_nested),
    .field_count = sizeof(nested_fields) / sizeof(nested_fields[0]),
    .fields = nested_fields
};

// 计数不单独编码，解码每个重复字段时自动递增。
static const tlv_array_schema_t values_array = {
    .capacity = ARRAY_CAPACITY,
    .count_offset = offsetof(msg_array, count),
    .count_type = TLV_VALUE_UINT32
};
static const tlv_field_schema_t array_fields[] = {
    {.tag = 1, .offset = offsetof(msg_array, transId), .type = TLV_VALUE_UINT32},
    {.tag = 2, .offset = offsetof(msg_array, values), .type = TLV_VALUE_UINT32, .array_schema = &values_array}
};
const tlv_message_schema_t msg_array_schema = {
    .struct_size = sizeof(msg_array),
    .field_count = sizeof(array_fields) / sizeof(array_fields[0]),
    .fields = array_fields
};

// 两个分支共用选择成员，只编码被选中的字段。
static const tlv_union_schema_t version_choice = {
    .choice_offset = offsetof(msg_union, choice),
    .choice_type = TLV_VALUE_UINT32,
    .choice_value = UNION_VERSION
};
static const tlv_union_schema_t error_choice = {
    .choice_offset = offsetof(msg_union, choice),
    .choice_type = TLV_VALUE_UINT32,
    .choice_value = UNION_ERROR
};
static const tlv_field_schema_t union_fields[] = {
    {.tag = 1, .offset = offsetof(msg_union, transId), .type = TLV_VALUE_UINT32},
    {.tag = 2, .offset = offsetof(msg_union, result.server_version), .type = TLV_VALUE_MESSAGE, .nested_schema = &version_schema, .union_schema = &version_choice},
    {.tag = 3, .offset = offsetof(msg_union, result.error_message), .type = TLV_VALUE_STRING, .string_capacity = sizeof(((msg_union *)0)->result.error_message), .union_schema = &error_choice}
};
const tlv_message_schema_t msg_union_schema = {
    .struct_size = sizeof(msg_union),
    .field_count = sizeof(union_fields) / sizeof(union_fields[0]),
    .fields = union_fields
};
