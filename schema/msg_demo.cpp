#include "msg_demo.h"

// 子结构体的字段编号独立于外层消息。
static const tlv_field_schema_t version_fields[] = {
    {1, offsetof(version, major), TLV_VALUE_UINT32, 0, nullptr, nullptr, nullptr},
    {2, offsetof(version, minor), TLV_VALUE_UINT32, 0, nullptr, nullptr, nullptr},
    {3, offsetof(version, patch), TLV_VALUE_UINT32, 0, nullptr, nullptr, nullptr}
};
static const tlv_message_schema_t version_schema = {
    sizeof(version), sizeof(version_fields) / sizeof(version_fields[0]), version_fields
};

static const tlv_field_schema_t simple_fields[] = {
    {1, offsetof(msg_simple, transId), TLV_VALUE_UINT32, 0, nullptr, nullptr, nullptr},
    {2, offsetof(msg_simple, name), TLV_VALUE_STRING, sizeof(((msg_simple *)0)->name), nullptr, nullptr, nullptr}
};
const tlv_message_schema_t msg_simple_schema = {
    sizeof(msg_simple), sizeof(simple_fields) / sizeof(simple_fields[0]), simple_fields
};

static const tlv_field_schema_t nested_fields[] = {
    {1, offsetof(msg_nested, transId), TLV_VALUE_UINT32, 0, nullptr, nullptr, nullptr},
    {2, offsetof(msg_nested, client_version), TLV_VALUE_MESSAGE, 0, &version_schema, nullptr, nullptr}
};
const tlv_message_schema_t msg_nested_schema = {
    sizeof(msg_nested), sizeof(nested_fields) / sizeof(nested_fields[0]), nested_fields
};

// 计数不单独编码，解码每个重复字段时自动递增。
static const tlv_array_schema_t values_array = {
    ARRAY_CAPACITY, offsetof(msg_array, count), TLV_VALUE_UINT32
};
static const tlv_field_schema_t array_fields[] = {
    {1, offsetof(msg_array, transId), TLV_VALUE_UINT32, 0, nullptr, nullptr, nullptr},
    {2, offsetof(msg_array, values), TLV_VALUE_UINT32, 0, nullptr, &values_array, nullptr}
};
const tlv_message_schema_t msg_array_schema = {
    sizeof(msg_array), sizeof(array_fields) / sizeof(array_fields[0]), array_fields
};

// 两个分支共用选择成员，只编码被选中的字段。
static const tlv_union_schema_t version_choice = {
    offsetof(msg_union, choice), TLV_VALUE_UINT32, UNION_VERSION
};
static const tlv_union_schema_t error_choice = {
    offsetof(msg_union, choice), TLV_VALUE_UINT32, UNION_ERROR
};
static const tlv_field_schema_t union_fields[] = {
    {1, offsetof(msg_union, transId), TLV_VALUE_UINT32, 0, nullptr, nullptr, nullptr},
    {2, offsetof(msg_union, result.server_version), TLV_VALUE_MESSAGE, 0, &version_schema, nullptr, &version_choice},
    {3, offsetof(msg_union, result.error_message), TLV_VALUE_STRING, sizeof(((msg_union *)0)->result.error_message), nullptr, nullptr, &error_choice}
};
const tlv_message_schema_t msg_union_schema = {
    sizeof(msg_union), sizeof(union_fields) / sizeof(union_fields[0]), union_fields
};
