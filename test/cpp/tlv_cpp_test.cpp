#include "../../codec/c/tlv.h"
#include "msg_demo.h"
#include "../../codec/cpp/tlv.h"

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <vector>

namespace {
int checks = 0;
#define CHECK(expression) do { ++checks; if (!(expression)) { \
    std::fprintf(stderr, "line %d: %s\n", __LINE__, #expression); std::exit(1); \
} } while (false)
using bytes = std::vector<std::uint8_t>;
const std::uint8_t* c_data(std::span<const std::uint8_t> input) {
    static const std::uint8_t empty = 0;
    return input.empty() ? &empty : input.data();
}

template<class T> int compare_decode(const tlv_message_schema_t& schema,
    std::span<const std::uint8_t> input, const T* initial = nullptr) {
    T c_output, cpp_output;
    std::memset(&c_output, 0, sizeof(T));
    std::memset(&cpp_output, 0, sizeof(T));
    if (initial) {
        std::memcpy(&c_output, initial, sizeof(T));
        std::memcpy(&cpp_output, initial, sizeof(T));
    }
    auto status = tlv::decode(schema, input, cpp_output);
    const auto c_status = tlv_decode(&schema, c_data(input), input.size(), &c_output, sizeof(T));
    CHECK((status ? CODEC_OK : status.error()) == c_status);
    // 包括失败时的部分修改，也要求两版一致。
    CHECK(std::memcmp(&c_output, &cpp_output, sizeof(T)) == 0);
    return c_status;
}

template<class T> bytes wire(const tlv_message_schema_t& schema, const T& input) {
    auto size = tlv::encode_size(schema, input);
    std::size_t c_size = 0;
    const auto c_status = tlv_encode_size(&schema, &input, &c_size);
    CHECK((size ? CODEC_OK : size.error()) == c_status);
    CHECK(size && *size == c_size);
    bytes encoded(c_size), c_encoded(c_size + 1);
    auto written = tlv::encode(schema, input, encoded);
    std::size_t c_written = 99;
    CHECK(tlv_encode(&schema, &input, c_encoded.data(), c_size, &c_written) == CODEC_OK);
    CHECK(written && *written == c_written && *written == c_size);
    CHECK(std::equal(encoded.begin(), encoded.end(), c_encoded.begin()));
    CHECK(compare_decode<T>(schema, encoded) == CODEC_OK);
    // 逐字节缩短输出容量，比较错误以及部分写入结果。
    for (std::size_t capacity = 0; capacity < c_size; ++capacity) {
        bytes left(c_size + 1, 0xcc), right = left;
        auto result = tlv::encode(schema, input, std::span(left).first(capacity));
        c_written = 99;
        const auto status = tlv_encode(&schema, &input, right.data(), capacity, &c_written);
        CHECK(!result && result.error() == status && status == CODEC_BUFFER_TOO_SMALL);
        CHECK(c_written == 0 && left == right);
    }
    return encoded;
}

template<class T> void encoding_error(const tlv_message_schema_t& schema, const T& input,
    codec_status_t expected) {
    std::size_t size = 99;
    auto measured = tlv::encode_size(schema, input);
    CHECK(!measured && measured.error() == expected);
    CHECK(tlv_encode_size(&schema, &input, &size) == expected && size == 99);
    std::array<std::uint8_t, 4096> left{}, right{};
    auto encoded = tlv::encode(schema, input, left);
    std::size_t written = 99;
    CHECK(!encoded && encoded.error() == expected);
    CHECK(tlv_encode(&schema, &input, right.data(), right.size(), &written) == expected);
    CHECK(written == 0 && left == right);
}
void append(bytes& output, std::initializer_list<std::uint8_t> tail) {
    output.insert(output.end(), tail);
}

void examples() {
    wire(msg_simple_schema, msg_simple{1, "demo-client"});
    wire(msg_simple_schema, msg_simple{1, ""});
    wire(msg_nested_schema, msg_nested{2, {1, 2, 3}});
    wire(msg_array_schema, msg_array{3, 3, {10, 20, 30}});
    wire(msg_array_schema, msg_array{3, 0, {}});
    for (std::uint8_t presence = 0; presence < 16; ++presence) {
        for (auto choice : {UNION_VERSION, UNION_ERROR, 99u}) {
            msg_present input{};
            input.transId = 5;
            input.present = presence;
            input.client_version = {1, 2, 3};
            input.count = 3;
            input.values[0] = 10; input.values[1] = 20; input.values[2] = 30;
            input.choice = static_cast<std::uint8_t>(choice);
            if (choice == UNION_VERSION) input.result.server_version = {4, 5, 6};
            else std::strcpy(input.result.error_message, "busy");
            wire(msg_present_schema, input);
        }
    }
    msg_union input{};
    input.transId = 4;
    for (auto choice : {UNION_VERSION, UNION_ERROR, 99u}) {
        input.choice = static_cast<std::uint8_t>(choice);
        if (choice == UNION_VERSION) input.result.server_version = {4, 5, 6};
        else std::strcpy(input.result.error_message, "server busy");
        wire(msg_union_schema, input);
    }
}

void scalars_and_containers() {
    struct scalars {
        std::int8_t i8; std::int16_t i16; std::int32_t i32; std::int64_t i64;
        std::uint8_t u8; std::uint16_t u16; std::uint32_t u32; std::uint64_t u64;
        bool flag;
    };
    const tlv_field_schema_t fields[] = {
        {1, offsetof(scalars, i8), TLV_VALUE_INT8, 0, nullptr, nullptr, nullptr, nullptr},
        {2, offsetof(scalars, i16), TLV_VALUE_INT16, 0, nullptr, nullptr, nullptr, nullptr},
        {3, offsetof(scalars, i32), TLV_VALUE_INT32, 0, nullptr, nullptr, nullptr, nullptr},
        {4, offsetof(scalars, i64), TLV_VALUE_INT64, 0, nullptr, nullptr, nullptr, nullptr},
        {5, offsetof(scalars, u8), TLV_VALUE_UINT8, 0, nullptr, nullptr, nullptr, nullptr},
        {6, offsetof(scalars, u16), TLV_VALUE_UINT16, 0, nullptr, nullptr, nullptr, nullptr},
        {7, offsetof(scalars, u32), TLV_VALUE_UINT32, 0, nullptr, nullptr, nullptr, nullptr},
        {8, offsetof(scalars, u64), TLV_VALUE_UINT64, 0, nullptr, nullptr, nullptr, nullptr},
        {9, offsetof(scalars, flag), TLV_VALUE_BOOL, 0, nullptr, nullptr, nullptr, nullptr}
    };
    const tlv_message_schema_t schema{sizeof(scalars), std::size(fields), fields};
    for (bool flag : {false, true}) {
        const scalars input{-128, -32768, INT32_MIN, INT64_MIN, UINT8_MAX, UINT16_MAX,
            UINT32_MAX, UINT64_MAX, flag};
        auto encoded = wire(schema, input);
        CHECK(encoded[13] == 0 && encoded[14] == 0x80);
        for (auto invalid : {2, 255}) {
            encoded.back() = static_cast<std::uint8_t>(invalid);
            CHECK((compare_decode<scalars>(schema, encoded) == CODEC_INVALID_BOOL));
        }
        encoded.pop_back();
        encoded[encoded.size() - 4] = 0;
        CHECK((compare_decode<scalars>(schema, encoded) == CODEC_FIELD_LENGTH_MISMATCH));
    }
    struct containers {
        std::uint8_t flags_count; bool flags[3];
        std::uint32_t names_count; char names[3][8];
        std::uint64_t versions_count; version versions[3];
        bool has_enabled; bool enabled;
    };
    const tlv_field_schema_t version_fields[] = {
        {1, offsetof(version, major), TLV_VALUE_UINT32, 0, nullptr, nullptr, nullptr, nullptr},
        {2, offsetof(version, minor), TLV_VALUE_UINT32, 0, nullptr, nullptr, nullptr, nullptr},
        {3, offsetof(version, patch), TLV_VALUE_UINT32, 0, nullptr, nullptr, nullptr, nullptr}
    };
    const tlv_message_schema_t version_schema{sizeof(version), 3, version_fields};
    const tlv_array_schema_t flags{3, offsetof(containers, flags_count), TLV_VALUE_UINT8};
    const tlv_array_schema_t names{3, offsetof(containers, names_count), TLV_VALUE_UINT32};
    const tlv_array_schema_t versions{3, offsetof(containers, versions_count), TLV_VALUE_UINT64};
    const tlv_present_schema_t enabled{offsetof(containers, has_enabled), TLV_VALUE_BOOL, 1};
    const tlv_field_schema_t container_fields[] = {
        {1, offsetof(containers, flags), TLV_VALUE_BOOL, 0, nullptr, &flags, nullptr, nullptr},
        {2, offsetof(containers, names), TLV_VALUE_STRING, 8, nullptr, &names, nullptr, nullptr},
        {3, offsetof(containers, versions), TLV_VALUE_MESSAGE, 0, &version_schema, &versions, nullptr, nullptr},
        {4, offsetof(containers, enabled), TLV_VALUE_BOOL, 0, nullptr, nullptr, nullptr, &enabled}
    };
    const tlv_message_schema_t container_schema{sizeof(containers), 4, container_fields};
    const containers input{3, {true, false, true}, 3, {"", "one", "two"},
        2, {{1, 2, 3}, {4, 5, 6}}, true, false};
    wire(container_schema, input);
}

void errors_and_state() {
    const auto encoded = wire(msg_simple_schema, msg_simple{1, "hello"});
    for (std::size_t size = 0; size < encoded.size(); ++size)
        compare_decode<msg_simple>(msg_simple_schema, std::span(encoded).first(size));
    auto invalid = encoded;
    invalid.insert(invalid.end(), encoded.begin(), encoded.end());
    CHECK(compare_decode<msg_simple>(msg_simple_schema, invalid) == CODEC_DUPLICATE_FIELD);
    invalid = encoded; invalid.back() = 0;
    CHECK(compare_decode<msg_simple>(msg_simple_schema, invalid) == CODEC_STRING_CONTAINS_NUL);
    msg_simple long_string{};
    std::memset(long_string.name, 'x', sizeof(long_string.name));
    encoding_error(msg_simple_schema, long_string, CODEC_STRING_NOT_TERMINATED);
    long_string.name[127] = 0;
    invalid = wire(msg_simple_schema, long_string);
    invalid[12] = 128; invalid.push_back('x');
    CHECK(compare_decode<msg_simple>(msg_simple_schema, invalid) == CODEC_STRING_CAPACITY_EXCEEDED);

    msg_array overfull{}; overfull.count = 9;
    encoding_error(msg_array_schema, overfull, CODEC_INVALID_COUNT);
    overfull.count = 8;
    invalid = wire(msg_array_schema, overfull);
    append(invalid, {2, 0, 4, 0, 0, 0, 7, 0, 0, 0});
    CHECK(compare_decode<msg_array>(msg_array_schema, invalid) == CODEC_ARRAY_CAPACITY_EXCEEDED);
    msg_union selected{}; selected.result.server_version = {1, 2, 3};
    invalid = wire(msg_union_schema, selected);
    append(invalid, {3, 0, 0, 0, 0, 0});
    CHECK(compare_decode<msg_union>(msg_union_schema, invalid) == CODEC_UNION_CONFLICT);
    invalid = wire(msg_nested_schema, msg_nested{1, {1, 2, 3}});
    invalid[18] = 3;
    CHECK(compare_decode<msg_nested>(msg_nested_schema, invalid) == CODEC_FIELD_LENGTH_MISMATCH);
    invalid = encoded;
    append(invalid, {255, 255, 2, 0, 0, 0, 0xff, 0xff});
    CHECK(compare_decode<msg_simple>(msg_simple_schema, invalid) == CODEC_OK);

    msg_simple preserved{88, "keep"};
    CHECK(tlv::decode(msg_simple_schema, {}, preserved));
    CHECK(preserved.transId == 88 && std::strcmp(preserved.name, "keep") == 0);
    CHECK(tlv::decode(msg_simple_schema, std::span(encoded).first(10), preserved));
    CHECK(preserved.transId == 1 && std::strcmp(preserved.name, "keep") == 0);
    msg_array appended{0, 1, {99}};
    const auto values = wire(msg_array_schema, msg_array{1, 2, {1, 2}});
    CHECK(compare_decode<msg_array>(msg_array_schema, values, &appended) == CODEC_OK);
    CHECK(tlv::decode(msg_array_schema, values, appended));
    CHECK(appended.count == 3 && appended.values[0] == 99 && appended.values[2] == 2);

    msg_present absent{}, empty_array{};
    empty_array.present = PRESENT_ARRAY;
    CHECK(wire(msg_present_schema, absent) == wire(msg_present_schema, empty_array));
    // 缺失字段不读取超范围 count 或无效的 union 字符串。
    absent.count = UINT16_MAX; absent.choice = UNION_ERROR;
    std::memset(absent.result.error_message, 'x', sizeof(absent.result.error_message));
    wire(msg_present_schema, absent);
    msg_present output{};
    CHECK(!tlv::decode(msg_present_schema, bytes{2, 0, 1, 0, 0, 0, 1}, output));
    CHECK(output.present == 0);
    CHECK(!tlv::decode(msg_present_schema, bytes{6, 0, 1, 0, 0, 0, 0}, output));
    CHECK(output.present == 0 && output.choice == 0);
    msg_present previous{};
    previous.choice = 99; previous.present = 0x80;
    CHECK(compare_decode<msg_present>(msg_present_schema, bytes{2, 0, 4, 0, 0, 0, 0, 0, 0, 0}, &previous) == CODEC_OK);

    // 同一字节的不同位置变异，与 C 实现对照错误码和失败后的对象状态。
    msg_present mutation{};
    mutation.present = 15; mutation.count = 2; mutation.choice = UNION_ERROR;
    mutation.client_version = {1, 2, 3}; mutation.values[0] = 10; mutation.values[1] = 20;
    std::strcpy(mutation.result.error_message, "busy");
    const auto original = wire(msg_present_schema, mutation);
    for (std::size_t i = 0; i < original.size(); ++i) {
        for (auto byte : {0, 1, 2, 127, 255}) {
            auto changed = original; changed[i] = static_cast<std::uint8_t>(byte);
            compare_decode<msg_present>(msg_present_schema, changed);
        }
    }
}

void public_contract() {
    static_assert(tlv::message_object<msg_present>);
    static_assert(!tlv::message_object<std::vector<int>>);
    static_assert(!tlv::message_object<msg_present*>);
    static_assert(!tlv::message_object<std::nullptr_t>);
    msg_simple object{};
    CHECK(tlv::encode_size(msg_simple_schema, nullptr).error() == CODEC_INVALID_ARGUMENT);
    CHECK(tlv::encode(msg_simple_schema, nullptr, {}).error() == CODEC_INVALID_ARGUMENT);
    CHECK(tlv::decode(msg_simple_schema, {}, nullptr, 0).error() == CODEC_INVALID_ARGUMENT);
    CHECK(tlv::decode(msg_simple_schema, {}, &object, sizeof(object) - 1).error() == CODEC_BUFFER_TOO_SMALL);
    std::uint8_t tiny = 0;
    CHECK(tlv::encode_size(msg_simple_schema, tiny).error() == CODEC_BUFFER_TOO_SMALL);
    CHECK(tlv::encode(msg_simple_schema, tiny, {}).error() == CODEC_BUFFER_TOO_SMALL);
    CHECK(tlv::decode(msg_simple_schema, {}, tiny).error() == CODEC_BUFFER_TOO_SMALL);
    const tlv_message_schema_t empty{sizeof(object), 0, nullptr};
    CHECK(tlv::encode_size(empty, object).value() == 0);
    CHECK(tlv::encode(empty, object, {}).value() == 0);
    CHECK(tlv::decode(empty, {}, object));
    CHECK(tlv::decode(empty, bytes{42, 0, 0, 0, 0, 0}, object));
    const auto data = wire(msg_simple_schema, object);
    CHECK(tlv::encode_size(msg_simple_schema, &object).value() == data.size());
    bytes buffer(data.size());
    CHECK(tlv::encode(msg_simple_schema, &object, buffer).value() == data.size());
}

void metadata_boundaries() {
    struct counted { std::uint8_t count; std::uint32_t values[256]; } initial{};
    const tlv_array_schema_t array{256, offsetof(counted, count), TLV_VALUE_UINT8};
    const tlv_field_schema_t value{1, offsetof(counted, values), TLV_VALUE_UINT32, 0,
        nullptr, &array, nullptr, nullptr};
    const tlv_message_schema_t schema{sizeof(counted), 1, &value};
    initial.count = 255;
    // 元素可以写入，但 count 无法表示 256；保留 C 版的部分修改及溢出结果。
    CHECK(compare_decode<counted>(schema, bytes{1, 0, 4, 0, 0, 0, 7, 0, 0, 0}, &initial) == CODEC_OVERFLOW);

    struct flagged { std::uint64_t present; std::uint32_t number; } flags{};
    for (auto type : {TLV_VALUE_UINT8, TLV_VALUE_UINT16, TLV_VALUE_UINT32, TLV_VALUE_UINT64}) {
        const tlv_present_schema_t presence{offsetof(flagged, present), type, 2};
        const tlv_field_schema_t field{1, offsetof(flagged, number), TLV_VALUE_UINT32, 0,
            nullptr, nullptr, nullptr, &presence};
        const tlv_message_schema_t present_schema{sizeof(flagged), 1, &field};
        // 按本地类型写入标记，避免依赖宿主大小端。
        flags = {};
        const std::uint8_t p8 = 0x82;
        const std::uint16_t p16 = 0x82;
        const std::uint32_t p32 = 0x82;
        const std::uint64_t p64 = 0x82;
        if (type == TLV_VALUE_UINT8) std::memcpy(&flags.present, &p8, sizeof(p8));
        if (type == TLV_VALUE_UINT16) std::memcpy(&flags.present, &p16, sizeof(p16));
        if (type == TLV_VALUE_UINT32) std::memcpy(&flags.present, &p32, sizeof(p32));
        if (type == TLV_VALUE_UINT64) std::memcpy(&flags.present, &p64, sizeof(p64));
        flags.number = 42;
        const auto encoded = wire(present_schema, flags);
        CHECK(compare_decode<flagged>(present_schema, encoded, &flags) == CODEC_OK);
    }
}

void many_fields() {
    struct large { std::uint32_t values[300]; } input{};
    std::array<tlv_field_schema_t, 300> fields{};
    for (std::size_t i = 0; i < fields.size(); ++i) {
        fields[i].tag = static_cast<std::uint16_t>(i + 1);
        fields[i].offset = offsetof(large, values) + i * sizeof(std::uint32_t);
        fields[i].type = TLV_VALUE_UINT32;
        input.values[i] = static_cast<std::uint32_t>(i * 17);
    }
    const tlv_message_schema_t schema{sizeof(large), fields.size(), fields.data()};
    // 单独编码一次，避免重复执行与字段规模无关的全部短缓冲区组合。
    auto size = tlv::encode_size(schema, input);
    CHECK(size && *size == 3000);
    bytes encoded(*size), c_encoded(*size);
    CHECK(tlv::encode(schema, input, encoded).value() == *size);
    std::size_t written = 0;
    CHECK(tlv_encode(&schema, &input, c_encoded.data(), c_encoded.size(), &written) == CODEC_OK);
    CHECK(encoded == c_encoded && written == *size);
    CHECK(compare_decode<large>(schema, encoded) == CODEC_OK);
    large output{};
    CHECK(tlv::decode(schema, encoded, output));
    CHECK(output.values[299] == input.values[299]);
    encoded.insert(encoded.end(), c_encoded.end() - 10, c_encoded.end());
    CHECK(compare_decode<large>(schema, encoded) == CODEC_DUPLICATE_FIELD);
    // 嵌套消息也单独走堆去重表。
    struct outer { large child; } nested{input};
    const tlv_field_schema_t child{1, offsetof(outer, child), TLV_VALUE_MESSAGE, 0, &schema,
        nullptr, nullptr, nullptr};
    const tlv_message_schema_t parent{sizeof(outer), 1, &child};
    auto total = tlv::encode_size(parent, nested);
    CHECK(total && *total == 3006);
    bytes payload(*total);
    CHECK(tlv::encode(parent, nested, payload));
    CHECK(compare_decode<outer>(parent, payload) == CODEC_OK);
}
} // namespace

int main() {
    examples();
    scalars_and_containers();
    errors_and_state();
    public_contract();
    metadata_boundaries();
    many_fields();
    std::printf("PASS: %d checks\n", checks);
}
