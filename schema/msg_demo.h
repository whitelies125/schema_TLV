#ifndef MSG_DEMO_H
#define MSG_DEMO_H

#include "tlv.h"

// 字符串容量包含结尾的空字符，数组容量按元素数量计算。
inline constexpr size_t NAME_CAPACITY = 128;
inline constexpr size_t ARRAY_CAPACITY = 8;
inline constexpr uint32_t UNION_VERSION = 1;
inline constexpr uint32_t UNION_ERROR = 2;

struct version {
    uint32_t major;
    uint32_t minor;
    uint32_t patch;
};

// 普通整数和字符串字段。
struct msg_simple {
    uint32_t transId;
    char name[NAME_CAPACITY];
};

// 嵌套结构体字段。
struct msg_nested {
    uint32_t transId;
    version client_version;
};

// 计数成员决定实际编码的数组元素数量。
struct msg_array {
    uint32_t transId;
    uint32_t count;
    uint32_t values[ARRAY_CAPACITY];
};

// 选择成员决定编码哪个分支，解码时根据字段编号恢复。
struct msg_union {
    uint32_t transId;
    uint32_t choice;
    union {
        version server_version;
        char error_message[NAME_CAPACITY];
    } result;
};

extern const tlv_message_schema_t msg_simple_schema;
extern const tlv_message_schema_t msg_nested_schema;
extern const tlv_message_schema_t msg_array_schema;
extern const tlv_message_schema_t msg_union_schema;

#endif
