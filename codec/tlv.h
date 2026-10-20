#ifndef TLV_H
#define TLV_H

#include <stddef.h>
#include <stdint.h>

/* 返回状态：成功为 CODEC_OK，失败为负值；嵌套消息的错误原样向上传递。
 * 错误码不附带码流偏移或字段路径，未细分的错误使用通用分类。
 */
typedef enum codec_status {
    CODEC_OK = 0,
    CODEC_FAILED = -1,             /* 未分类的内部错误。 */
    CODEC_INVALID_ARGUMENT = -2,   /* 必需参数为空或无效。 */
    CODEC_INVALID_SCHEMA = -3,     /* 遇到不支持的类型或缺失的必要描述。 */
    CODEC_BUFFER_TOO_SMALL = -4,   /* 输出结构体或编码缓冲区容量不足。 */
    CODEC_TRUNCATED_DATA = -5,     /* 未细分的码流截断错误。 */
    CODEC_INVALID_VALUE = -6,      /* 未细分的消息值错误。 */
    CODEC_INVALID_DATA = -7,       /* 未细分的码流数据错误。 */
    CODEC_OVERFLOW = -8,           /* 长度计算或数值转换溢出。 */

    CODEC_TRUNCATED_HEADER = -9,   /* 剩余输入不足一个 TLV 头。 */
    CODEC_TRUNCATED_VALUE = -10,   /* 声明的 value 长度超过剩余输入。 */
    CODEC_FIELD_LENGTH_MISMATCH = -11, /* 整数或 BOOL 的 value 长度与类型不符。 */
    CODEC_INVALID_BOOL = -12,      /* BOOL 码流值不是 0 或 1。 */
    CODEC_DUPLICATE_FIELD = -13,   /* 非数组字段重复出现。 */
    CODEC_UNION_CONFLICT = -14,    /* 同一 union 出现不同分支。 */
    CODEC_INVALID_COUNT = -15,     /* 编码对象的数组 count 超过容量。 */
    CODEC_INVALID_CHOICE = -16,    /* 编码对象的 choice 没有对应分支。 */
    CODEC_STRING_NOT_TERMINATED = -17, /* 编码字符串在容量内没有结尾 NUL。 */
    CODEC_ARRAY_CAPACITY_EXCEEDED = -18, /* 解码数组没有空间接收下一个元素。 */
    CODEC_STRING_CAPACITY_EXCEEDED = -19, /* 目标空间不足以容纳字符串和结尾 NUL。 */

    CODEC_STRING_CONTAINS_NUL = -29 /* STRING 的 value 中包含 NUL。 */
} codec_status_t;

#ifdef __cplusplus
extern "C" {
#endif

/* 字段值类型；多字节整数在码流中使用固定宽度小端表示。 */
typedef enum tlv_value_type {
    TLV_VALUE_INT8 = 1,
    TLV_VALUE_INT16,
    TLV_VALUE_INT32,
    TLV_VALUE_INT64,
    TLV_VALUE_UINT8,
    TLV_VALUE_UINT16,
    TLV_VALUE_UINT32,
    TLV_VALUE_UINT64,
    /* 本地使用已初始化的 C99 bool/_Bool，或兼容 ABI 下的 C++ bool；码流为单字节 0/1。 */
    TLV_VALUE_BOOL,
    /* 本地为 NUL 结尾字符串；码流不含 NUL，解码时补充，空串 value 长度为 0。 */
    TLV_VALUE_STRING,
    TLV_VALUE_MESSAGE,
} tlv_value_type_t;

typedef struct tlv_message_schema tlv_message_schema_t;

/* 数组以重复 tag 编码；本地 count 控制元素数，解码时自动累加。 */
typedef struct tlv_array_schema {
    size_t capacity;     /* 最大元素数。 */
    size_t count_offset; /* count 相对所属消息结构体的字节偏移。 */
    tlv_value_type_t count_type; /* 本地 count 类型：UINT8 / UINT16 / UINT32 / UINT64。 */
} tlv_array_schema_t;

/* 编码按 choice 选择分支；解码按 tag 恢复 choice，0 也是有效分支值。 */
typedef struct tlv_union_schema {
    size_t              choice_offset; /* choice 相对所属消息结构体的字节偏移。 */
    tlv_value_type_t choice_type;   /* 本地 choice 类型：UINT8 / UINT16 / UINT32 / UINT64。 */
    uint64_t            choice_value;  /* 当前分支的选择值，须能用 choice_type 表示。 */
} tlv_union_schema_t;

/* 可选字段的本地 presence，不单独进入码流；字段解码成功后设置对应标记。
 * BOOL 使用原生 bool（C99 需包含 <stdbool.h>），整数使用对应的无符号类型。
 * 同一 union 的各分支使用一致的存在描述；不同字段可使用同一整数的不同位。
 * 空数组不产生重复 tag，因此无法通过解码区分存在但为空与缺失。
 */
typedef struct tlv_present_schema {
    size_t offset;        /* presence 相对所属消息结构体的字节偏移。 */
    tlv_value_type_t type; /* 本地类型：BOOL / UINT8 / UINT16 / UINT32 / UINT64。 */
    uint64_t mask;        /* 整数使用非零单个位掩码；BOOL 必须为 1。 */
} tlv_present_schema_t;

/* 单个字段的本地布局及编码方式；所有 offset 均相对所属消息结构体。 */
typedef struct tlv_field_schema {
    uint16_t                   tag;             /* TLV 字段编号，不能为 0。 */
    size_t                     offset;          /* 字段数据的字节偏移。 */
    tlv_value_type_t           type;            /* 单值或数组元素的类型。 */
    size_t                     string_capacity; /* STRING 的单元素字节容量，含结尾 NUL；其他类型忽略。 */
    const tlv_message_schema_t* nested_schema;   /* MESSAGE 的子描述；其他类型忽略。 */
    const tlv_array_schema_t*   array_schema;    /* 数组描述；NULL 表示单值。 */
    const tlv_union_schema_t*   union_schema;    /* union 分支描述；NULL 表示不受 choice 控制。 */
    const tlv_present_schema_t* present_schema; /* 存在描述；NULL 表示不受 presence 控制。 */
} tlv_field_schema_t;

/* 一层消息的描述；子消息使用独立的字段表和 tag 编号。 */
struct tlv_message_schema {
    size_t                       struct_size;  /* 本地消息结构体的 sizeof。 */
    size_t                       field_count;  /* 本层字段描述数量。 */
    const tlv_field_schema_t* fields;           /* 本层字段描述表。 */
};

/*
 * 编解码接口的共同约定：
 * - 调用方负责 schema 的布局、类型、容量和组合语义正确且符合预期。
 * - schema 及其引用的描述在使用期间必须有效且保持不变。
 * - 库不检查布局重叠、辅助成员共享等关系，不保证任意描述组合都能正确往返编解码。
 * - 非法描述不保证被发现或安全失败；消息值、码流长度、输出容量和溢出仍在运行时检查。
 */

/*
 * 计算消息对象 input 按 schema 编码后的 TLV payload 字节数。
 * 成功时写入 encoded_size；不写码流，不分配内存。
 * schema、input 和 encoded_size 均须非 NULL。
 */
codec_status_t tlv_encode_size(const tlv_message_schema_t* schema,
    const void* input, size_t* encoded_size);

/*
 * 将消息对象 input 按 schema 编码到 buffer，buffer_size 为可写字节容量。
 * 空间足够时可直接调用，无需先测长；写入时逐次检查容量，不分配内存。
 * schema、input 和 buffer 均须非 NULL；written 可为 NULL。
 * written 非空时，成功写入实际字节数，失败置零；失败输出应丢弃。
 * 编码期间 input 必须保持不变，且不能与输出缓冲区重叠。
 * written 指向的存储不得与 schema、input 或输出缓冲区重叠。
 */
codec_status_t tlv_encode(const tlv_message_schema_t* schema,
    const void* input, uint8_t* buffer,
    size_t buffer_size, size_t* written);

/*
 * 将 input/input_size 指定的不含帧头的 TLV payload 按 schema 解码到消息对象 buffer。
 * schema、input 和 buffer 均须非 NULL；buffer_size 不得小于 schema->struct_size。
 * 不分配或初始化 buffer；调用方按用途初始化目标对象、数组 count 和 presence。
 * 未知 tag 跳过，缺失字段保留原值；非数组字段重复或 union 分支冲突时报错。
 * 失败时 buffer 可能已被部分修改，调用方应丢弃失败结果。
 */
codec_status_t tlv_decode(const tlv_message_schema_t* schema,
    const uint8_t* input, size_t input_size,
    void* buffer, size_t buffer_size);

#ifdef __cplusplus
}
#endif

#endif
