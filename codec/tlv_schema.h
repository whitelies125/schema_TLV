#ifndef TLV_SCHEMA_H
#define TLV_SCHEMA_H

#include <stddef.h>
#include <stdint.h>

/* schema 描述消息对象的内存布局，以及对象字段与 TLV 的对应关系。
 * - 本地对象：调用方提供的结构体；offset、capacity 和 sizeof 均描述其内存。
 * - 码流：连续的 [tag: uint16][length: uint32][value]，头部整数使用小端序。
 * - 字段：字段表中的一项；单值字段产生一个 TLV，数组字段按元素产生同 tag TLV。
 * - value：单个 TLV 的数据部分；length 只计 value 的字节数，不含 6 字节头部。
 * count、choice 和 presence 是对象中的控制成员，本身不因这些描述而写入码流。
 * 调用方保证描述与实际对象匹配；库不提供完整的 schema 布局校验。
 */

/* 返回状态：成功为 CODEC_OK，失败为负值；嵌套消息的错误原样向上传递。
 * 错误码不附带码流偏移或字段路径，未细分的错误使用通用分类。
 */
typedef enum codec_status {
    CODEC_OK = 0,
    CODEC_INVALID_ARGUMENT = -1,   /* 必需参数为空或无效。 */
    CODEC_INVALID_SCHEMA = -2,     /* 遇到不支持的类型或缺失的必要描述。 */
    CODEC_BUFFER_TOO_SMALL = -3,   /* 输出结构体或编码缓冲区容量不足。 */
    CODEC_INVALID_VALUE = -4,      /* 未细分的消息值错误。 */
    CODEC_OVERFLOW = -5,           /* 长度计算或数值转换溢出。 */
    CODEC_TRUNCATED_HEADER = -6,   /* 剩余输入不足一个 TLV 头。 */
    CODEC_TRUNCATED_VALUE = -7,   /* 声明的 value 长度超过剩余输入。 */
    CODEC_FIELD_LENGTH_MISMATCH = -8, /* 整数或 BOOL 的 value 长度与类型不符。 */
    CODEC_INVALID_BOOL = -9,      /* BOOL 码流值不是 0 或 1。 */
    CODEC_INVALID_COUNT = -10,     /* 编码对象的数组 count 超过容量。 */
    CODEC_STRING_NOT_TERMINATED = -11, /* 编码字符串在容量内没有结尾 NUL。 */
    CODEC_ARRAY_CAPACITY_EXCEEDED = -12, /* 解码数组没有空间接收下一个元素。 */
    CODEC_STRING_CAPACITY_EXCEEDED = -13, /* 目标空间不足以容纳字符串和结尾 NUL。 */
    CODEC_STRING_CONTAINS_NUL = -14 /* STRING 的 value 中包含 NUL。 */
} codec_status_t;

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
    /* 本地为 char[N]，以 NUL 结尾；编码不含结尾 NUL，解码拒绝内嵌 NUL 并补结尾 NUL。 */
    TLV_VALUE_STRING,
    /* 本地为内嵌子结构体；value 是按 nested_schema 编码的完整子消息。 */
    TLV_VALUE_MESSAGE,
} tlv_value_type_t;

typedef struct tlv_message_schema tlv_message_schema_t;

/* 数组存储在消息结构体内，元素连续排列；元素步长由字段类型确定。
 * 编码读取前 count 个元素，每个元素产生一个同 tag TLV；count=0 时不产生 TLV。
 * 解码写入下标为 count 的元素，成功后递增 count；不会自动将 count 清零。
 * MESSAGE 数组的每个 TLV 对应一个独立子对象，调用方应预先初始化这些对象。
 */
typedef struct tlv_array_schema {
    size_t           capacity;     /* 最大元素数。 */
    size_t           count_offset; /* count 相对所属消息结构体的字节偏移。 */
    tlv_value_type_t count_type;    /* count 成员类型：UINT8 / UINT16 / UINT32 / UINT64。 */
} tlv_array_schema_t;

/* 描述一个字段属于哪个 union 分支；choice 是所属消息中的分支选择成员。
 * 同一 union 的分支引用同一个 choice 成员，choice_value 唯一且能用 choice_type 表示。
 * 编码仅选择 choice == choice_value 的分支；没有匹配项时跳过整个 union，0 也可作为分支值。
 * 解码由收到的 tag 确定分支：同分支沿用原内容；切换分支时清零新分支及其数组 count。
 * 配置 presence 但标记未置位时，也按首次进入分支处理；各分支须使用一致的 presence 描述。
 * 调用方保证原有已选中分支已初始化；未收到任何分支时保留原 choice。
 */
typedef struct tlv_union_schema {
    size_t           choice_offset; /* choice 相对所属消息结构体的字节偏移。 */
    tlv_value_type_t choice_type;   /* 本地 choice 类型：UINT8 / UINT16 / UINT32 / UINT64。 */
    uint64_t         choice_value;  /* 当前分支的选择值，须能用 choice_type 表示。 */
} tlv_union_schema_t;

/* presence 是字段的存在标记：编码时未置位则跳过字段，解码成功后置位。
 * BOOL 使用原生 bool（C99 需包含 <stdbool.h>），整数使用对应的无符号类型。
 * 同一 union 的各分支使用一致的存在描述；不同字段可使用同一整数的不同位。
 * 空数组不产生重复 tag，因此无法通过解码区分存在但为空与缺失。
 */
typedef struct tlv_present_schema {
    size_t           offset; /* presence 相对所属消息结构体的字节偏移。 */
    tlv_value_type_t type;   /* presence 成员类型：BOOL / UINT8 / UINT16 / UINT32 / UINT64。 */
    uint64_t         mask;   /* 整数标记使用可由 type 表示的单个位；BOOL 必须为 1。 */
} tlv_present_schema_t;

/* 单个字段的布局和编码规则；本项及辅助描述中的 offset 均相对所属消息对象起始地址。
 * 编码先检查 presence，再匹配 union choice，最后读取字段值或数组 count。
 */
typedef struct tlv_field_schema {
    uint16_t                    tag;             /* TLV 字段编号：非零，同层字段表中唯一。 */
    size_t                      offset;          /* 单值成员或数组首元素的字节偏移。 */
    tlv_value_type_t            type;            /* 单值或数组元素的类型。 */
    size_t                      string_capacity; /* STRING 的单元素字节容量，含结尾 NUL；其他类型忽略。 */
    const tlv_message_schema_t* nested_schema;   /* MESSAGE 必须提供子消息描述；其他类型忽略。 */
    const tlv_array_schema_t*   array_schema;    /* 数组描述；NULL 表示单值。 */
    const tlv_union_schema_t*   union_schema;    /* union 分支描述；NULL 表示不受 choice 控制。 */
    const tlv_present_schema_t* present_schema;  /* 存在标记描述；NULL 表示不受 presence 控制。 */
} tlv_field_schema_t;

/* 一层消息的描述；子消息有独立的字段表和 tag 编号。
 * 单值 MESSAGE 的重复 tag 合并到同一对象，缺失的子字段保留原值。
 */
struct tlv_message_schema {
    size_t                    struct_size; /* 本地消息结构体的 sizeof。 */
    size_t                    field_count; /* 本层字段描述数量。 */
    const tlv_field_schema_t* fields;      /* 本层字段描述表。 */
};

#endif
