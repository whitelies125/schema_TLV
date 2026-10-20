#ifndef TLV_H
#define TLV_H

#include <stddef.h>
#include <stdint.h>

/* 成功返回 CODEC_OK；失败返回具体错误码，未细分的错误保留通用分类。
 * 子消息的错误逐层原样返回，不提供字节偏移或字段路径。
 */
typedef enum codec_status {
    CODEC_OK = 0,
    CODEC_FAILED = -1,             /* 未分类的内部错误。 */
    CODEC_INVALID_ARGUMENT = -2,   /* 必需参数为空或无效。 */
    CODEC_INVALID_SCHEMA = -3,     /* 消息描述不合法，或未细分的 schema 错误。 */
    CODEC_BUFFER_TOO_SMALL = -4,   /* 输出结构体或编码缓冲区容量不足。 */
    CODEC_TRUNCATED_DATA = -5,     /* 未细分的码流截断错误。 */
    CODEC_INVALID_VALUE = -6,      /* 未细分的消息值错误。 */
    CODEC_INVALID_DATA = -7,       /* 未细分的码流数据错误。 */
    CODEC_OVERFLOW = -8,           /* 长度计算或数值转换溢出。 */

    CODEC_TRUNCATED_HEADER = -9,   /* 剩余输入不足一个 TLV 头。 */
    CODEC_TRUNCATED_VALUE = -10,   /* 声明的 value 长度超过剩余输入。 */
    CODEC_FIELD_LENGTH_MISMATCH = -11, /* 整数或 BOOL 的码流长度与类型不符。 */
    CODEC_INVALID_BOOL = -12,      /* BOOL 码流值不是 0 或 1。 */
    CODEC_DUPLICATE_FIELD = -13,   /* 非数组字段重复出现。 */
    CODEC_UNION_CONFLICT = -14,    /* 同一 union 出现不同分支。 */
    CODEC_INVALID_COUNT = -15,     /* 编码对象的数组 count 超过容量。 */
    CODEC_INVALID_CHOICE = -16,    /* 编码对象的 choice 没有对应分支。 */
    CODEC_STRING_NOT_TERMINATED = -17, /* 编码字符串在容量内没有结尾 NUL。 */
    CODEC_ARRAY_CAPACITY_EXCEEDED = -18, /* 解码数组没有空间接收下一个元素。 */
    CODEC_STRING_CAPACITY_EXCEEDED = -19, /* 解码字符串空间不足，包含结尾 NUL。 */

    CODEC_SCHEMA_INVALID_FIELD = -20, /* tag 为 0、类型不支持或类型相关描述不匹配。 */
    CODEC_SCHEMA_FIELD_OUT_OF_BOUNDS = -21, /* 字段存储区域超出结构体。 */
    CODEC_SCHEMA_INVALID_ARRAY = -22, /* 容量、count 描述不合法或与自身数据重叠。 */
    CODEC_SCHEMA_INVALID_UNION = -23, /* 数组与 union 同时配置、选择器不合法或与自身数据重叠。 */
    CODEC_SCHEMA_INVALID_PRESENCE = -24, /* presence 类型、掩码或范围不合法。 */
    CODEC_SCHEMA_DUPLICATE_TAG = -25, /* 同层字段 tag 重复。 */
    CODEC_SCHEMA_FIELD_OVERLAP = -26, /* 不允许的数据区域重叠，或选择器与其他字段数据重叠。 */
    CODEC_SCHEMA_DUPLICATE_CHOICE = -27, /* 同一 union 的分支选择值重复。 */
    CODEC_SCHEMA_PRESENCE_MISMATCH = -28 /* 同一 union 的分支 presence 描述不一致。 */
} codec_status_t;

#ifdef __cplusplus
extern "C" {
#endif

typedef enum tlv_value_type {
    TLV_VALUE_INT8 = 1,
    TLV_VALUE_INT16,
    TLV_VALUE_INT32,
    TLV_VALUE_INT64,
    TLV_VALUE_UINT8,
    TLV_VALUE_UINT16,
    TLV_VALUE_UINT32,
    TLV_VALUE_UINT64,
    TLV_VALUE_BOOL, /* 本地成员为有效、已初始化的 C99 bool/_Bool 或兼容 ABI 下的 C++ bool；码流为单字节 0/1。 */
    TLV_VALUE_STRING,
    TLV_VALUE_MESSAGE,
} tlv_value_type_t;

typedef struct tlv_message_schema tlv_message_schema_t;

typedef struct tlv_array_schema {
    size_t capacity;     /* 最大元素数量，不是字节数。 */
    size_t count_offset; /* 计数成员相对所属结构体的偏移。 */
    tlv_value_type_t count_type; /* 计数成员类型，支持 UINT8 / UINT16 / UINT32 / UINT64。 */
} tlv_array_schema_t;

typedef struct tlv_union_schema {
    size_t              choice_offset; /* choice 成员相对所属结构体的偏移。 */
    tlv_value_type_t choice_type;   /* 选择成员类型，支持 UINT8 / UINT16 / UINT32 / UINT64。 */
    uint64_t            choice_value;  /* 当前 tag 对应的选择值，必须能用选择成员类型表示。 */
} tlv_union_schema_t;

/* 可选字段的本地存在标记，不单独编码；BOOL 使用原生 bool 成员（C99 需包含 <stdbool.h>），
 * 其他类型使用对应的无符号整数成员。
 * 可与数组或联合体组合；同一联合体的各分支须配置一致的存在描述。
 * 空数组不产生字段，不能区分存在但为空与缺失。
 */
typedef struct tlv_present_schema {
    size_t offset;        /* 标志成员相对字段所属结构体的偏移。 */
    tlv_value_type_t type; /* BOOL 或 UINT8 / UINT16 / UINT32 / UINT64。 */
    uint64_t mask;        /* 整数使用非零单个位掩码；BOOL 必须为 1。 */
} tlv_present_schema_t;

typedef struct tlv_field_schema {
    uint16_t                   tag;             /* TLV 字段编号，不能为 0。 */
    size_t                     offset;          /* 字段成员相对所属结构体起始地址的字节偏移。 */
    tlv_value_type_t           type;            /* 字段值类型；数组字段表示单个元素的类型。 */
    size_t                     string_capacity; /* 单个字符串的缓冲区容量，包含结尾 '\0'；其他类型为 0。 */
    const tlv_message_schema_t* nested_schema;   /* 嵌套消息的结构描述，仅 MESSAGE 类型使用；其他类型为 NULL。 */
    const tlv_array_schema_t*   array_schema;    /* 数组的容量与计数描述；仅 数组 类型使用；其他类型为 NULL。 */
    const tlv_union_schema_t*   union_schema;    /* 联合体分支的选择描述；仅 union 类型使用；其他类型为 NULL。 */
    const tlv_present_schema_t* present_schema; /* 存在位描述；NULL 表示编码不受存在位控制。 */
} tlv_field_schema_t;

struct tlv_message_schema {
    size_t                       struct_size;  /* 对应 C 结构体的 sizeof。 */
    size_t                       field_count;
    const tlv_field_schema_t* fields;
};

/*
 * 校验 schema 及其引用的嵌套描述，不读取消息数据、不修改描述、不分配堆内存。
 * 当前层的字段关系检查为 O(n log n)，使用与字段数量成比例的临时栈空间。
 * schema 为 NULL 时返回 CODEC_INVALID_ARGUMENT；其他情况沿用现有校验规则。
 */
codec_status_t tlv_validate_schema(const tlv_message_schema_t* schema);

/*
 * 以下编解码接口要求 schema 合法，其引用的所有描述在使用期间有效且保持不变。
 * 动态 schema 构造完成或修改后，应先调用 tlv_validate_schema() 并确认成功。
 * 静态不可变 schema 可以在测试中校验，运行时无需重复校验。
 * 接口不执行完整 schema 校验，不保证能够发现未验证或校验失败的非法描述；
 * 调用方不得将这些描述传入编解码接口。消息值、长度和缓冲区检查仍在每次调用时执行。
 */

/*
 * 计算 input 按 schema 编码为 TLV payload 后所需的精确字节数。
 * 不写入码流、不分配内存；成功时将结果写入 encoded_size。
 *
 * schema:       描述 input 消息字段布局和 TLV tag/type 的 schema。
 * input:        待编码的调用方消息结构体。
 * encoded_size: 输出参数，返回所需 TLV payload 字节数。
 */
codec_status_t tlv_encode_size(const tlv_message_schema_t* schema,
    const void* input, size_t* encoded_size);

/*
 * 将 input 按 schema 编码为 TLV payload 并写入调用方提供的 buffer。
 * buffer_size 必须不小于 tlv_encode_size() 的计算结果；不分配内存。
 * 编码时逐次检查容量，不预计算整条消息长度；失败后应丢弃输出。
 * 消息与 schema 在编码期间必须保持不变，输入对象与输出缓冲区不能重叠。
 *
 * schema:      描述 input 消息字段布局和 TLV tag/type 的 schema。
 * input:       待编码的调用方消息结构体。
 * buffer:      调用方提供的 TLV payload 输出 buffer。
 * buffer_size: buffer 的可写字节数。
 */
codec_status_t tlv_encode(const tlv_message_schema_t* schema,
    const void* input, uint8_t* buffer,
    size_t buffer_size);

/*
 * 将 input/input_size 指定的 TLV payload 按 schema 解码到调用方 buffer。
 * 入口检查 buffer_size 不小于 schema->struct_size；不分配或初始化 buffer。
 * 按 schema 字段数量使用栈上位图记录出现状态，每 8 个字段占一个字节，向上取整。
 *
 * schema:      描述目标消息字段布局和期望 TLV tag/type 的 schema。
 * input:       待解码 TLV payload 的起始地址，不包含帧 HEAD。
 * input_size:  input 中可读取的 payload 字节数。
 * buffer:      调用方提供的目标消息结构体 buffer。
 * buffer_size: buffer 的可写字节数。
 */
codec_status_t tlv_decode(const tlv_message_schema_t* schema,
    const uint8_t* input, size_t input_size,
    void* buffer, size_t buffer_size);

#ifdef __cplusplus
}
#endif

#endif
