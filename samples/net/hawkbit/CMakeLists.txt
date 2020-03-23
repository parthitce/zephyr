# Copyright (c) 2020 Linumiz
#
# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.13.1)

# This application has its own Kconfig options.
set(KCONFIG_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/Kconfig)

include($ENV{ZEPHYR_BASE}/cmake/app/boilerplate.cmake NO_POLICY_SCOPE)
project(hawkbit)

target_include_directories(app PRIVATE $ENV{ZEPHYR_BASE}/lib/hawkbit/include)
FILE(GLOB app_sources src/*.c)
target_sources(app PRIVATE ${app_sources})
target_sources_ifdef(CONFIG_NET_DHCPV4 app PRIVATE src/dhcp.c)

include($ENV{ZEPHYR_BASE}/samples/net/common/common.cmake)

set(gen_dir ${ZEPHYR_BINARY_DIR}/include/generated/)

generate_inc_file_for_target(
    app
    src/globalsign_r2.der
    ${gen_dir}/globalsign_r2.der.inc
    )

