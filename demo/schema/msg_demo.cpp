#include "msg_demo.h"

// version：子消息的 tag 编号独立于外层消息。
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

// msg_simple：整数与固定容量字符串。
static const tlv_field_schema_t simple_fields[] = {
    {.tag = 1, .offset = offsetof(msg_simple, transId), .type = TLV_VALUE_UINT32},
    {.tag = 2, .offset = offsetof(msg_simple, name), .type = TLV_VALUE_STRING, .string_capacity = sizeof(((msg_simple *)0)->name)}
};
const tlv_message_schema_t msg_simple_schema = {
    .struct_size = sizeof(msg_simple),
    .field_count = sizeof(simple_fields) / sizeof(simple_fields[0]),
    .fields = simple_fields
};

// msg_nested：通过 nested_schema 引用 version 的描述。
static const tlv_field_schema_t nested_fields[] = {
    {.tag = 1, .offset = offsetof(msg_nested, transId), .type = TLV_VALUE_UINT32},
    {.tag = 2, .offset = offsetof(msg_nested, client_version), .type = TLV_VALUE_MESSAGE, .nested_schema = &version_schema}
};
const tlv_message_schema_t msg_nested_schema = {
    .struct_size = sizeof(msg_nested),
    .field_count = sizeof(nested_fields) / sizeof(nested_fields[0]),
    .fields = nested_fields
};

// msg_array：values 使用重复 tag，count 由数组描述管理。
static const tlv_array_schema_t values_array = {
    .capacity = ARRAY_CAPACITY,
    .count_offset = offsetof(msg_array, count),
    .count_type = TLV_VALUE_UINT16
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

// msg_union：两个分支共用 choice，分别使用不同 tag 和选择值。
static const tlv_union_schema_t version_choice = {
    .choice_offset = offsetof(msg_union, choice),
    .choice_type = TLV_VALUE_UINT8,
    .choice_value = UNION_VERSION
};
static const tlv_union_schema_t error_choice = {
    .choice_offset = offsetof(msg_union, choice),
    .choice_type = TLV_VALUE_UINT8,
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

// msg_present：各类可选字段使用 present 中的不同位；union 分支共用存在位。
static const tlv_present_schema_t hello_present = {
    .offset = offsetof(msg_present, present), .type = TLV_VALUE_UINT8, .mask = PRESENT_HELLO
};
static const tlv_present_schema_t version_present = {
    .offset = offsetof(msg_present, present), .type = TLV_VALUE_UINT8, .mask = PRESENT_VERSION
};
static const tlv_present_schema_t values_present = {
    .offset = offsetof(msg_present, present), .type = TLV_VALUE_UINT8, .mask = PRESENT_ARRAY
};
static const tlv_present_schema_t result_present = {
    .offset = offsetof(msg_present, present), .type = TLV_VALUE_UINT8, .mask = PRESENT_UNION
};
static const tlv_array_schema_t present_values_array = {
    .capacity = ARRAY_CAPACITY, .count_offset = offsetof(msg_present, count), .count_type = TLV_VALUE_UINT16
};
static const tlv_union_schema_t present_version_choice = {
    .choice_offset = offsetof(msg_present, choice), .choice_type = TLV_VALUE_UINT8, .choice_value = UNION_VERSION
};
static const tlv_union_schema_t present_error_choice = {
    .choice_offset = offsetof(msg_present, choice), .choice_type = TLV_VALUE_UINT8, .choice_value = UNION_ERROR
};
static const tlv_field_schema_t present_fields[] = {
    {.tag = 1, .offset = offsetof(msg_present, transId), .type = TLV_VALUE_UINT32},
    {.tag = 2, .offset = offsetof(msg_present, hello), .type = TLV_VALUE_UINT32,
     .present_schema = &hello_present},
    {.tag = 3, .offset = offsetof(msg_present, client_version), .type = TLV_VALUE_MESSAGE,
     .nested_schema = &version_schema, .present_schema = &version_present},
    {.tag = 4, .offset = offsetof(msg_present, values), .type = TLV_VALUE_UINT32,
     .array_schema = &present_values_array, .present_schema = &values_present},
    {.tag = 5, .offset = offsetof(msg_present, result.server_version), .type = TLV_VALUE_MESSAGE,
     .nested_schema = &version_schema, .union_schema = &present_version_choice, .present_schema = &result_present},
    {.tag = 6, .offset = offsetof(msg_present, result.error_message), .type = TLV_VALUE_STRING,
     .string_capacity = sizeof(((msg_present *)0)->result.error_message),
     .union_schema = &present_error_choice, .present_schema = &result_present}
};
const tlv_message_schema_t msg_present_schema = {
    .struct_size = sizeof(msg_present),
    .field_count = sizeof(present_fields) / sizeof(present_fields[0]),
    .fields = present_fields
};
