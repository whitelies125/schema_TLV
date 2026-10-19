#ifndef MSG_DEMO_H
#define MSG_DEMO_H

#include "tlv.h"

// 字符串容量包含结尾的空字符，数组容量按元素数量计算。
inline constexpr size_t NAME_CAPACITY = 128;
inline constexpr size_t ARRAY_CAPACITY = 8;
inline constexpr uint32_t UNION_VERSION = 0;
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
    uint16_t count;
    uint32_t values[ARRAY_CAPACITY];
};

// 选择成员决定编码哪个分支，解码时根据字段编号恢复。
struct msg_union {
    uint32_t transId;
    uint8_t choice;
    union {
        version server_version;
        char error_message[NAME_CAPACITY];
    } result;
};

inline constexpr uint8_t PRESENT_HELLO = 0x01;
inline constexpr uint8_t PRESENT_VERSION = 0x02;
inline constexpr uint8_t PRESENT_ARRAY = 0x04;
inline constexpr uint8_t PRESENT_UNION = 0x08;

// 存在标记仅用于本地判断，不单独进入码流。
struct msg_present {
    uint32_t transId;
    uint8_t present;
    uint32_t hello;
    version client_version;
    uint16_t count;
    uint32_t values[ARRAY_CAPACITY];
    uint8_t choice;
    union {
        version server_version;
        char error_message[NAME_CAPACITY];
    } result;
};

extern const tlv_message_schema_t msg_present_schema;
extern const tlv_message_schema_t msg_simple_schema;
extern const tlv_message_schema_t msg_nested_schema;
extern const tlv_message_schema_t msg_array_schema;
extern const tlv_message_schema_t msg_union_schema;

#endif
