#include "c/tlv.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int checks;
#define CHECK(expr) do { ++checks; if (!(expr)) { \
    fprintf(stderr, "line %d: %s\n", __LINE__, #expr); exit(1); \
} } while (0)

typedef struct message {
    uint32_t value;
    bool enabled;
    char text[8];
} message;

static const tlv_field_schema_t fields[] = {
    {1, offsetof(message, value), TLV_VALUE_UINT32, 0, NULL, NULL, NULL, NULL},
    {2, offsetof(message, enabled), TLV_VALUE_BOOL, 0, NULL, NULL, NULL, NULL},
    {3, offsetof(message, text), TLV_VALUE_STRING, 8, NULL, NULL, NULL, NULL}
};
static const tlv_message_schema_t schema = {sizeof(message), 3, fields};

static void basic_cases(void) {
    const message input = {0x12345678, true, "hello"};
    message output = {0};
    uint8_t buffer[64];
    size_t size = 0, written = 0, i;
    /* 固定码流独立验证小端整数、单字节 BOOL 和不含结尾 NUL 的字符串。 */
    const uint8_t expected[] = {
        1,0,4,0,0,0,0x78,0x56,0x34,0x12,
        2,0,1,0,0,0,1,
        3,0,5,0,0,0,'h','e','l','l','o'
    };
    CHECK(tlv_encode_size(&schema, &input, &size) == CODEC_OK);
    CHECK(size == sizeof(expected));
    CHECK(tlv_encode(&schema, &input, buffer, sizeof(buffer), &written) == CODEC_OK);
    CHECK(written == size && memcmp(buffer, expected, size) == 0);
    CHECK(tlv_decode(&schema, expected, sizeof(expected), &output, sizeof(output)) == CODEC_OK);
    CHECK(output.value == input.value && output.enabled && strcmp(output.text, input.text) == 0);
    /* 每个不足容量均须失败，并将 written 清零。 */
    for (i = 0; i < size; ++i) {
        written = 99;
        CHECK(tlv_encode(&schema, &input, buffer, i, &written) == CODEC_BUFFER_TOO_SMALL);
        CHECK(written == 0);
    }
    /* 独立构造非法报文，避免往返测试掩盖同源错误。 */
    {
        const uint8_t header[] = {1,0,4,0,0};
        const uint8_t value[] = {1,0,4,0,0,0,1};
        const uint8_t boolean[] = {2,0,1,0,0,0,2};
        const uint8_t wrong_length[] = {2,0,2,0,0,0,0,1};
        CHECK(tlv_decode(&schema, header, sizeof(header), &output, sizeof(output)) == CODEC_TRUNCATED_HEADER);
        CHECK(tlv_decode(&schema, value, sizeof(value), &output, sizeof(output)) == CODEC_TRUNCATED_VALUE);
        CHECK(tlv_decode(&schema, boolean, sizeof(boolean), &output, sizeof(output)) == CODEC_INVALID_BOOL);
        CHECK(tlv_decode(&schema, wrong_length, sizeof(wrong_length), &output, sizeof(output)) == CODEC_FIELD_LENGTH_MISMATCH);
    }
    /* 缺失字段保留已有值，未知 tag 跳过，重复标量取最后一个值。 */
    {
        const uint8_t payload[] = {99,0,1,0,0,0,7, 1,0,4,0,0,0,1,0,0,0, 1,0,4,0,0,0,2,0,0,0};
        output = input;
        CHECK(tlv_decode(&schema, payload, sizeof(payload), &output, sizeof(output)) == CODEC_OK);
        CHECK(output.value == 2 && output.enabled && strcmp(output.text, "hello") == 0);
    }
    {
        message invalid = input;
        memset(invalid.text, 'x', sizeof(invalid.text));
        size = 99;
        CHECK(tlv_encode_size(&schema, &invalid, &size) == CODEC_STRING_NOT_TERMINATED);
        CHECK(size == 99);
    }

}

static void arrays(void) {
    typedef struct { uint8_t count; uint32_t values[2]; } list;
    const tlv_array_schema_t array = {2, offsetof(list, count), TLV_VALUE_UINT8};
    const tlv_field_schema_t field = {1, offsetof(list, values), TLV_VALUE_UINT32,
        0, NULL, &array, NULL, NULL};
    const tlv_message_schema_t desc = {sizeof(list), 1, &field};
    list input = {0, {10, 20}}, output = {0};
    uint8_t buffer[32];
    size_t size = 99, written = 99;
    const uint8_t one[] = {1,0,4,0,0,0,7,0,0,0};
    /* 空数组不产生 TLV；恰好满容量可以往返。 */
    CHECK(tlv_encode_size(&desc, &input, &size) == CODEC_OK && size == 0);
    input.count = 2;
    CHECK(tlv_encode(&desc, &input, buffer, sizeof(buffer), &written) == CODEC_OK);
    CHECK(written == 20);
    CHECK(tlv_decode(&desc, buffer, written, &output, sizeof(output)) == CODEC_OK);
    CHECK(output.count == 2 && output.values[0] == 10 && output.values[1] == 20);
    /* 从已有 count 追加，超限后不应覆盖数组之外的内存。 */
    output.count = 1;
    output.values[0] = 42;
    CHECK(tlv_decode(&desc, one, sizeof(one), &output, sizeof(output)) == CODEC_OK);
    CHECK(output.count == 2 && output.values[0] == 42 && output.values[1] == 7);
    CHECK(tlv_decode(&desc, one, sizeof(one), &output, sizeof(output)) == CODEC_ARRAY_CAPACITY_EXCEEDED);
    CHECK(output.count == 2 && output.values[0] == 42 && output.values[1] == 7);
    input.count = 3;
    size = written = 99;
    CHECK(tlv_encode_size(&desc, &input, &size) == CODEC_INVALID_COUNT && size == 99);
    CHECK(tlv_encode(&desc, &input, buffer, sizeof(buffer), &written) == CODEC_INVALID_COUNT && written == 0);
}

static void strings(void) {
    message input = {0}, output = {0};
    uint8_t buffer[64];
    size_t written;
    const uint8_t empty[] = {3,0,0,0,0,0};
    const uint8_t embedded[] = {3,0,3,0,0,0,'a',0,'b'};
    const uint8_t too_long[] = {3,0,8,0,0,0,'1','2','3','4','5','6','7','8'};
    /* 空字符串补 NUL；长度等于容量减一时仍可完整存储。 */
    strcpy(output.text, "old");
    CHECK(tlv_decode(&schema, empty, sizeof(empty), &output, sizeof(output)) == CODEC_OK);
    CHECK(output.text[0] == '\0');
    strcpy(input.text, "1234567");
    CHECK(tlv_encode(&schema, &input, buffer, sizeof(buffer), &written) == CODEC_OK);
    CHECK(tlv_decode(&schema, buffer, written, &output, sizeof(output)) == CODEC_OK);
    CHECK(strcmp(output.text, "1234567") == 0);
    CHECK(tlv_decode(&schema, embedded, sizeof(embedded), &output, sizeof(output)) == CODEC_STRING_CONTAINS_NUL);
    CHECK(tlv_decode(&schema, too_long, sizeof(too_long), &output, sizeof(output)) == CODEC_STRING_CAPACITY_EXCEEDED);
}

static void unions_and_presence(void) {
    typedef struct {
        uint8_t choice, present;
        union { uint32_t number; char text[8]; } value;
    } selected;
    const tlv_present_schema_t presence = {offsetof(selected, present), TLV_VALUE_UINT8, 1};
    const tlv_union_schema_t number = {offsetof(selected, choice), TLV_VALUE_UINT8, 0};
    const tlv_union_schema_t text = {offsetof(selected, choice), TLV_VALUE_UINT8, 1};
    const tlv_field_schema_t members[] = {
        {1, offsetof(selected, value.number), TLV_VALUE_UINT32, 0, NULL, NULL, &number, &presence},
        {2, offsetof(selected, value.text), TLV_VALUE_STRING, 8, NULL, NULL, &text, &presence}
    };
    const tlv_message_schema_t desc = {sizeof(selected), 2, members};
    selected input = {0}, output = {0};
    uint8_t buffer[32];
    size_t size = 99, written;
    const uint8_t switch_back[] = {2,0,1,0,0,0,'x', 1,0,4,0,0,0,7,0,0,0};
    const uint8_t invalid[] = {2,0,2,0,0,0,'x',0};
    /* 未标记字段跳过；choice=0 也是合法分支。 */
    input.value.number = 42;
    CHECK(tlv_encode_size(&desc, &input, &size) == CODEC_OK && size == 0);
    input.present = 1;
    CHECK(tlv_encode(&desc, &input, buffer, sizeof(buffer), &written) == CODEC_OK && written == 10);
    output.present = 2;
    CHECK(tlv_decode(&desc, buffer, written, &output, sizeof(output)) == CODEC_OK);
    CHECK(output.choice == 0 && output.present == 3 && output.value.number == 42);
    /* 数字到字符串再回数字，最终状态由最后一个分支决定。 */
    CHECK(tlv_decode(&desc, switch_back, sizeof(switch_back), &output, sizeof(output)) == CODEC_OK);
    CHECK(output.choice == 0 && output.present == 3 && output.value.number == 7);
    output.present = 2;
    CHECK(tlv_decode(&desc, invalid, sizeof(invalid), &output, sizeof(output)) == CODEC_STRING_CONTAINS_NUL);
    CHECK(output.choice == 0 && output.present == 2);
}

static void nested_messages(void) {
    typedef struct { message child; } parent;
    const tlv_field_schema_t field = {1, offsetof(parent, child), TLV_VALUE_MESSAGE,
        0, &schema, NULL, NULL, NULL};
    const tlv_message_schema_t desc = {sizeof(parent), 1, &field};
    parent output = {{99, true, "old"}};
    /* 重复子消息合并，未出现的子字段保留。 */
    const uint8_t merged[] = {
        1,0,10,0,0,0, 1,0,4,0,0,0,7,0,0,0,
        1,0,7,0,0,0, 2,0,1,0,0,0,0
    };
    const uint8_t malformed[] = {1,0,7,0,0,0, 2,0,1,0,0,0,2};
    CHECK(tlv_decode(&desc, merged, sizeof(merged), &output, sizeof(output)) == CODEC_OK);
    CHECK(output.child.value == 7 && !output.child.enabled && strcmp(output.child.text, "old") == 0);
    CHECK(tlv_decode(&desc, malformed, sizeof(malformed), &output, sizeof(output)) == CODEC_INVALID_BOOL);
}

static void public_contract(void) {
    message input = {7, true, "old"}, output = input;
    uint8_t buffer[64] = {0};
    size_t size = 99;
    CHECK(tlv_encode_size(NULL, &input, &size) == CODEC_INVALID_ARGUMENT);
    CHECK(tlv_encode_size(&schema, NULL, &size) == CODEC_INVALID_ARGUMENT);
    CHECK(tlv_encode_size(&schema, &input, NULL) == CODEC_INVALID_ARGUMENT);
    CHECK(tlv_encode(NULL, &input, buffer, sizeof(buffer), NULL) == CODEC_INVALID_ARGUMENT);
    CHECK(tlv_encode(&schema, NULL, buffer, sizeof(buffer), NULL) == CODEC_INVALID_ARGUMENT);
    CHECK(tlv_encode(&schema, &input, NULL, 0, NULL) == CODEC_INVALID_ARGUMENT);
    CHECK(tlv_encode(&schema, &input, buffer, sizeof(buffer), NULL) == CODEC_OK);
    CHECK(tlv_decode(NULL, buffer, 0, &output, sizeof(output)) == CODEC_INVALID_ARGUMENT);
    CHECK(tlv_decode(&schema, NULL, 0, &output, sizeof(output)) == CODEC_INVALID_ARGUMENT);
    CHECK(tlv_decode(&schema, buffer, 0, NULL, sizeof(output)) == CODEC_INVALID_ARGUMENT);
    CHECK(tlv_decode(&schema, buffer, 0, &output, sizeof(output) - 1) == CODEC_BUFFER_TOO_SMALL);
    CHECK(tlv_decode(&schema, buffer, 0, &output, sizeof(output)) == CODEC_OK);
    CHECK(output.value == 7 && output.enabled && strcmp(output.text, "old") == 0);
}

/* 每种整数宽度分别校验边界值和固定小端字节，不依赖往返结果。 */
#define INTEGER_CASE(ctype, kind, val, ...) do { \
    ctype input = (val), output = 0; \
    const uint8_t expected[] = {1,0,sizeof(ctype),0,0,0,__VA_ARGS__}; \
    const tlv_field_schema_t field = {1,0,kind,0,NULL,NULL,NULL,NULL}; \
    const tlv_message_schema_t desc = {sizeof(ctype),1,&field}; \
    uint8_t buffer[14]; size_t written = 0; \
    CHECK(tlv_encode(&desc,&input,buffer,sizeof(buffer),&written) == CODEC_OK); \
    CHECK(written == sizeof(expected) && memcmp(buffer,expected,written) == 0); \
    CHECK(tlv_decode(&desc,expected,sizeof(expected),&output,sizeof(output)) == CODEC_OK); \
    CHECK(output == input); \
} while (0)

static void integer_boundaries(void) {
    INTEGER_CASE(int8_t, TLV_VALUE_INT8, INT8_MIN, 0x80);
    INTEGER_CASE(int8_t, TLV_VALUE_INT8, INT8_MAX, 0x7f);
    INTEGER_CASE(int16_t, TLV_VALUE_INT16, INT16_MIN, 0,0x80);
    INTEGER_CASE(int16_t, TLV_VALUE_INT16, INT16_MAX, 0xff,0x7f);
    INTEGER_CASE(int32_t, TLV_VALUE_INT32, INT32_MIN, 0,0,0,0x80);
    INTEGER_CASE(int32_t, TLV_VALUE_INT32, INT32_MAX, 0xff,0xff,0xff,0x7f);
    INTEGER_CASE(int64_t, TLV_VALUE_INT64, INT64_MIN, 0,0,0,0,0,0,0,0x80);
    INTEGER_CASE(int64_t, TLV_VALUE_INT64, INT64_MAX, 0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x7f);
    INTEGER_CASE(uint8_t, TLV_VALUE_UINT8, UINT8_MAX, 0xff);
    INTEGER_CASE(uint16_t, TLV_VALUE_UINT16, UINT16_MAX, 0xff,0xff);
    INTEGER_CASE(uint32_t, TLV_VALUE_UINT32, UINT32_MAX, 0xff,0xff,0xff,0xff);
    INTEGER_CASE(uint64_t, TLV_VALUE_UINT64, UINT64_MAX, 0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff);
}

int main(void) {
    basic_cases();
    arrays();
    strings();
    unions_and_presence();
    nested_messages();
    public_contract();
    integer_boundaries();
    printf("PASS: %d checks\n", checks);
    return 0;
}
