#ifndef MSG_DEMO_H
#define MSG_DEMO_H

#include "tlv.h"

// 示例容量：字符串按字节计且包含结尾 NUL，数组按元素计。
inline constexpr size_t NAME_CAPACITY = 128;
inline constexpr size_t ARRAY_CAPACITY = 8;
inline constexpr uint32_t UNION_VERSION = 0;
inline constexpr uint32_t UNION_ERROR = 2;

struct version {
    uint32_t major;
    uint32_t minor;
    uint32_t patch;
};

// 单值示例：整数和字符串。
struct msg_simple {
    uint32_t transId;
    char name[NAME_CAPACITY];
};

// 嵌套示例：子消息拥有独立的字段描述。
struct msg_nested {
    uint32_t transId;
    version client_version;
};

// 数组示例：count 控制编码元素数，解码时累加恢复。
struct msg_array {
    uint32_t transId;
    uint16_t count;
    uint32_t values[ARRAY_CAPACITY];
};

// union 示例：编码按 choice 选分支，解码按 tag 恢复 choice。
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

// presence 示例：分别控制单值、子消息、数组和 union 的存在状态。
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
