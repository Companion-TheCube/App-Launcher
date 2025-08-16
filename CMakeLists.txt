cmake_minimum_required(VERSION 3.16)
project(thecube_app_launcher CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(app-launcher
  src/app_launcher.cpp
)

find_package(nlohmann_json CONFIG REQUIRED)
target_link_libraries(app-launcher PRIVATE nlohmann_json::nlohmann_json)

# Harden a bit (optional)
target_compile_options(app-launcher PRIVATE -fno-exceptions -fno-rtti -fstack-protector-strong -D_FORTIFY_SOURCE=2)
target_link_options(app-launcher PRIVATE -Wl,-z,relro,-z,now)
