/*
 * Copyright (c) 2020 Linumiz
 * Author: Parthiban Nallathambi <parthiban@linumiz.com>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef ZEPHYR_INCLUDE_DRIVERS_CLOCK_CONTROL_XMC_CLOCK_CONTROL_H_
#define ZEPHYR_INCLUDE_DRIVERS_CLOCK_CONTROL_XMC_CLOCK_CONTROL_H_

#include <drivers/clock_control.h>

/* common clock control device name for all XMC chips */
#define STM32_CLOCK_CONTROL_NAME "xmc-ccu"

struct xmc_pclken {
	u32_t bus;
	u32_t rst;
};

#endif /* ZEPHYR_INCLUDE_DRIVERS_CLOCK_CONTROL_XMC_CLOCK_CONTROL_H_ */
