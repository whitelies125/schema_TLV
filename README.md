# schema_TLV

基于 schema 的 TLV 编解码库。C99 和 C++23 两版共用消息结构体、schema 和错误码，
调用方切换实现时不需要修改消息定义或已有 schema。

```text
codec/
  tlv_schema.h      # 共用错误码、类型及 schema 描述
  c/                # C99 编解码库：tlv.h、tlv.c
  cpp/              # C++23 编解码库：tlv.h、tlv.cpp
demo/
  schema/           # 两版共用的消息及 schema 示例
  c/                # C 版演示程序（使用 C++23 编写）
  cpp/              # C++ 版演示程序
test/
  c/                # C 专用测试目录，当前暂无独立测试源文件
  cpp/              # 兼容性测试、分配行为测试
```

## 构建与链接

```sh
cmake -S . -B build
cmake --build build
ctest --test-dir build --output-on-failure
```

CMake 提供两个静态库目标：`tlv_c` 和 `tlv_cpp`，自动公开各自 codec 目录及 common 目录。
C 调用方包含 `codec/c/tlv.h`，C++ 调用方包含 `codec/cpp/tlv.h`。两者文件名相同，
仅使用一版时通过对应 include 目录包含 `tlv.h`；同时使用两版时应明确指定路径。手工编译时需要将 `codec/` 和对应的
`codec/c/` 或 `codec/cpp/` 加入头文件搜索路径，并链接相应静态库；C++ 版要求 C++23，无需反射编译选项。
C++ 编解码库不调用 C 编解码函数，也不需要链接 C 库。

`demo` 使用 C 版，`demo_cpp` 使用 C++ 版；二者直接使用 `demo/schema/` 中的同一份消息和 schema。
`tlv_cpp_test` 对照两版的编码字节、错误码及解码结果；`tlv_cpp_allocation_test` 验证临时空间分配行为。

## 共用消息和 schema

消息仍采用定长数组、外部 count、原生 union、choice 和 presence 等 C 风格布局。
已有的 `tlv_message_schema_t`、字段及辅助描述可直接交给两版，不需要转换。
错误码数值、schema 类型名、成员顺序和含义保持不变。

```cpp
#include "codec/c/tlv.h"    // C 接口；仅使用 C++ 版时可以省略
#include "codec/cpp/tlv.h"

#include <array>

struct message {
    uint32_t id;
    char name[128];
};

const tlv_field_schema_t fields[] = {
    {1, offsetof(message, id), TLV_VALUE_UINT32, 0, nullptr, nullptr, nullptr, nullptr},
    {2, offsetof(message, name), TLV_VALUE_STRING, 128, nullptr, nullptr, nullptr, nullptr}
};
const tlv_message_schema_t schema{sizeof(message), 2, fields};

int main() {
    const message input{1, "client"};
    std::array<uint8_t, 256> buffer{};

    // C++ 入口：span 借用缓冲区，expected 返回结果或共用 CODEC_* 错误码。
    auto size = tlv::encode_size(schema, input);
    auto written = tlv::encode(schema, input, buffer);
    if (!size || !written || *size != *written) return 1;
    message output{};  // 调用方初始化对象，解码不会自动清零
    auto status = tlv::decode(schema, std::span(buffer).first(*written), output);
    if (!status) return 1;

    // 切换到 C 入口：消息和 schema 原样复用。
    size_t c_written = 0;
    if (tlv_encode(&schema, &input, buffer.data(), buffer.size(), &c_written) != CODEC_OK)
        return 1;
}
```

C++ 的低层接口也支持 `const void*` 输入，以及 `void* + output_size` 输出。
对象引用重载要求标准布局且可平凡复制，自动获取地址和大小，并检查对象不小于 schema 描述。
原先的 C++ `schema<T>`、`field/alternative` 和 STL 容器消息接口已移除。

## 编解码约定

- TLV 头为 `uint16 tag + uint32 length`，均使用小端；按 schema 顺序编码，嵌套消息直接写入并回填长度。
- STRING 本地容量包含结尾 NUL；编码停在首个 NUL，码流不包含结尾 NUL。解码拒绝内嵌 NUL，不验证 UTF-8。
- BOOL 本地使用原生 bool，码流为单字节 0/1；非法字节返回 `CODEC_INVALID_BOOL`。
- 数组使用重复 tag，不传输 count；空数组不产生 tag。需要区分缺失与存在但为空时，使用外层消息包装。
- presence 优先于 choice 和 count；choice=0 可以选中分支，未知 choice 不编码该 union。
- 未知 tag 跳过；非数组重复字段、union 分支冲突分别返回对应错误。
- 解码保留缺失字段，按已有 count 追加数组；成功后依次更新 count、presence、choice。
- 编码输入与输出不得重叠；编解码失败输出可能已部分修改，调用方应丢弃失败结果。
- 调用方负责 schema 布局、类型、辅助成员关系及生命周期；库不进行完整布局校验。

测长和编码不分配堆内存。C++ 解码每层去重表在 256 字段以内使用 32 字节栈缓冲区，
超过 256 字段时用 vector 按需分配；分配失败返回 `CODEC_FAILED`。消息数据本身始终由调用方提供。
C++ 接受空 span 表示零长度输入或输出，空 payload 保留目标原值；显式对象空指针报参数错误。
C 接口继续要求输入及输出缓冲区指针非空，包括零长度场景。
