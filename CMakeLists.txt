cmake_minimum_required(VERSION 3.22)

project(heap-tracer)

add_library(malloc SHARED hook.c)
# 添加钩子库的编译选项
target_compile_options(malloc PRIVATE
    -fPIC                   # 生成位置无关代码（必须）
    -g                      # 调试符号
    -O0                     # 禁用优化
    -fno-omit-frame-pointer # 确保帧指针可用
    -rdynamic
)

# 添加链接库
target_link_libraries(malloc PRIVATE
    dl      # -ldl
    unwind
)
