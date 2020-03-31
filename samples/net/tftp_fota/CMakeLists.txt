#
# Copyright (c) 2020 Linumiz
#
# SPDX-License-Identifier: Apache-2.0
#

cmake_minimum_required(VERSION 3.8.2)

include($ENV{ZEPHYR_BASE}/cmake/app/boilerplate.cmake NO_POLICY_SCOPE)
include($ENV{ZEPHYR_BASE}/../nrf/cmake/boilerplate.cmake)
project(https_client)

target_sources(app PRIVATE src/main.c)
