#include "msg_demo.h"

#include <cstdlib>

#include <cstring>
#include <cstdio>
#include <print>
#include <vector>

// 四种消息共用相同的编码、解码步骤，调用方提供已清零的目标对象。
static bool encode_decode(const tlv_message_schema_t &schema, const void *input, void *output) {
    size_t encoded_size = 0;
    auto status = tlv_encode_size(&schema, input, &encoded_size);
    if (status != CODEC_OK) {
        std::println(stderr, "encode_size failed: {}", static_cast<int>(status));
        return false;
    }
    std::vector<uint8_t> payload(encoded_size);
    status = tlv_encode(&schema, input, payload.data(), payload.size());
    if (status != CODEC_OK) {
        std::println(stderr, "encode failed: {}", static_cast<int>(status));
        return false;
    }
    status = tlv_decode(&schema, payload.data(), payload.size(), output, schema.struct_size);
    if (status != CODEC_OK) {
        std::println(stderr, "decode failed: {}", static_cast<int>(status));
        return false;
    }
    return true;
}

static int simple_demo() {
    const msg_simple input{1, "demo-client"};
    msg_simple decoded{};
    if (!encode_decode(msg_simple_schema, &input, &decoded)) return EXIT_FAILURE;
    std::println("msg_simple decoded:");
    std::println("  transId: {}", decoded.transId);
    std::println("  name: {}", decoded.name);
    return 0;
}

static int nested_demo() {
    const msg_nested input{2, {1, 2, 3}};
    msg_nested decoded{};
    if (!encode_decode(msg_nested_schema, &input, &decoded)) return EXIT_FAILURE;
    std::println("msg_nested decoded:");
    std::println("  transId: {}", decoded.transId);
    std::println("  client_version: {}.{}.{}", decoded.client_version.major,
                 decoded.client_version.minor, decoded.client_version.patch);
    return 0;
}

static int array_demo() {
    const msg_array input{3, 3, {10, 20, 30}};
    // 数组解码会累加计数，因此必须先清零。
    msg_array decoded{};
    if (!encode_decode(msg_array_schema, &input, &decoded)) return EXIT_FAILURE;
    std::println("msg_array decoded:");
    std::println("  transId: {}", decoded.transId);
    std::println("  count: {}", decoded.count);
    for (uint32_t i = 0; i < decoded.count; ++i)
        std::println("  values[{}]: {}", i, decoded.values[i]);
    return 0;
}

static int union_demo(uint32_t choice) {
    msg_union input{};
    input.transId = 4;
    input.choice = choice;
    // 设置选择值，并初始化对应的联合体成员。
    if (choice == UNION_VERSION)
        input.result.server_version = {4, 5, 6};
    else
        std::strcpy(input.result.error_message, "server busy");
    msg_union decoded{};
    if (!encode_decode(msg_union_schema, &input, &decoded)) return EXIT_FAILURE;
    std::println("msg_union decoded:");
    std::println("  transId: {}", decoded.transId);
    std::println("  choice: {}", decoded.choice);
    if (decoded.choice == UNION_VERSION) {
        const auto &value = decoded.result.server_version;
        std::println("  server_version: {}.{}.{}", value.major, value.minor, value.patch);
    } else if (decoded.choice == UNION_ERROR) {
        std::println("  error_message: {}", decoded.result.error_message);
    }
    return 0;
}

int main() {
    if (simple_demo()) return EXIT_FAILURE;
    if (nested_demo()) return EXIT_FAILURE;
    if (array_demo()) return EXIT_FAILURE;
    if (union_demo(UNION_VERSION)) return EXIT_FAILURE;
    return union_demo(UNION_ERROR);
}
