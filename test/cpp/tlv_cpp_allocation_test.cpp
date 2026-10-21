#include "tlv.h"

#include <array>
#include <cstdio>
#include <cstdlib>
#include <new>

namespace {
bool reject_allocation = false;
struct no_allocation {
    no_allocation() { reject_allocation = true; }
    ~no_allocation() { reject_allocation = false; }
};
int checks = 0;
#define CHECK(expression) do { ++checks; if (!(expression)) { \
    std::fprintf(stderr, "line %d: %s\n", __LINE__, #expression); std::exit(1); \
} } while (false)
}

// 独立测试程序中替换分配函数，验证库的分配边界及错误返回。
void* operator new(std::size_t size) {
    if (reject_allocation) throw std::bad_alloc{};
    if (auto* allocation = std::malloc(size == 0 ? 1 : size)) return allocation;
    throw std::bad_alloc{};
}
void* operator new[](std::size_t size) { return ::operator new(size); }
void operator delete(void* allocation) noexcept { std::free(allocation); }
void operator delete[](void* allocation) noexcept { std::free(allocation); }
void operator delete(void* allocation, std::size_t) noexcept { std::free(allocation); }
void operator delete[](void* allocation, std::size_t) noexcept { std::free(allocation); }

int main() {
    struct message { std::uint32_t values[300]; } input{}, output{};
    std::array<tlv_field_schema_t, 300> fields{};
    for (std::size_t i = 0; i < fields.size(); ++i) {
        fields[i].tag = static_cast<std::uint16_t>(i + 1);
        fields[i].offset = offsetof(message, values) + i * sizeof(std::uint32_t);
        fields[i].type = TLV_VALUE_UINT32;
        input.values[i] = static_cast<std::uint32_t>(i + 1);
    }
    const tlv_message_schema_t schema{sizeof(message), fields.size(), fields.data()};
    std::array<std::uint8_t, 3000> buffer{};
    {
        no_allocation blocked;
        CHECK(tlv::encode_size(schema, input).value() == buffer.size());
        CHECK(tlv::encode(schema, input, buffer).value() == buffer.size());
        const tlv_message_schema_t local{sizeof(message), 256, fields.data()};
        CHECK(tlv::decode(local, std::span(buffer).first(2560), output));
        CHECK(output.values[255] == 256 && output.values[256] == 0);
        const tlv_message_schema_t heap{sizeof(message), 257, fields.data()};
        auto failed = tlv::decode(heap, std::span(buffer).first(2570), output);
        CHECK(!failed && failed.error() == CODEC_FAILED);
        CHECK(output.values[256] == 0);
    }
    CHECK(tlv::decode(schema, buffer, output));
    CHECK(output.values[299] == 300);

    // 外层去重表用栈，嵌套层分配失败也必须由顶层 expected 返回。
    struct parent { message child; } nested{input}, decoded{};
    const tlv_field_schema_t child{1, offsetof(parent, child), TLV_VALUE_MESSAGE, 0,
        &schema, nullptr, nullptr, nullptr};
    const tlv_message_schema_t parent_schema{sizeof(parent), 1, &child};
    std::array<std::uint8_t, 3006> nested_buffer{};
    CHECK(tlv::encode(parent_schema, nested, nested_buffer));
    {
        no_allocation blocked;
        auto failed = tlv::decode(parent_schema, nested_buffer, decoded);
        CHECK(!failed && failed.error() == CODEC_FAILED);
        CHECK(decoded.child.values[0] == 0);
    }
    CHECK(tlv::decode(parent_schema, nested_buffer, decoded));
    CHECK(decoded.child.values[299] == 300);
    std::printf("PASS: %d allocation checks\n", checks);
}
