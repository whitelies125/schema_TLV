#include "msg_demo.h"
#include "tlv.h"

#include <array>
#include <cstdio>
#include <cstring>

int main() {
    // 消息和 schema 与 C 版完全相同，只切换编解码入口。
    msg_present input{};
    input.transId = 5;
    input.present = PRESENT_HELLO | PRESENT_VERSION | PRESENT_ARRAY | PRESENT_UNION;
    input.client_version = {1, 2, 3};
    input.count = 3;
    input.values[0] = 10; input.values[1] = 20; input.values[2] = 30;
    input.choice = UNION_ERROR;
    std::strcpy(input.result.error_message, "server busy");
    std::array<std::uint8_t, 512> buffer{};
    const auto size = tlv::encode_size(msg_present_schema, input);
    const auto written = tlv::encode(msg_present_schema, input, buffer);
    if (!size || !written || *size != *written) return 1;
    msg_present decoded{};
    const auto status = tlv::decode(msg_present_schema, std::span(buffer).first(*written), decoded);
    if (!status || decoded.present != input.present || decoded.count != input.count ||
        decoded.choice != input.choice || std::strcmp(decoded.result.error_message, "server busy") != 0) return 1;
    std::printf("C++ TLV: %zu bytes, transId=%u, count=%u, result=%s\n",
        *written, decoded.transId, decoded.count, decoded.result.error_message);
}
