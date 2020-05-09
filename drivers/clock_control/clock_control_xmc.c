/*
 * Copyright (c) 2020 Linumiz
 * Author: Parthiban Nallathambi <parthiban@linumiz.com>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define DT_DRV_COMPAT infineon_xmc_ccu

#include <drivers/clock_control.h>
#include <drivers/clock_control/xmc_clock_control.h>

#include <xmc_scu.h>
#include <xmc4_scu.h>
#include <xmc_device.h>
#include <XMC4500.h>

#define LOG_LEVEL CONFIG_CLOCK_CONTROL_LOG_LEVEL
#include <logging/log.h>
LOG_MODULE_REGISTER(clock_control_ccu);

static int xmc_ccu_on(struct device *dev, clock_control_subsys_t sub_system)
{
	struct xmc_pclken *pclken = (struct xmc_pclken *)(sub_system);

	ARG_UNUSED(dev);

#if defined(CLOCK_GATING_SUPPORTED)
	XMC_SCU_CLOCK_UngatePeripheralClock(pclken->bus);
	while (XMC_SCU_CLOCK_IsPeripheralClockGated(pclken->bus));
#endif
#if defined(PERIPHERAL_RESET_SUPPORTED)
	XMC_SCU_RESET_DeassertPeripheralReset(pclken->rst);
	while (XMC_SCU_RESET_IsPeripheralResetAsserted(pclken->rst));
#endif
	return 0;
}

static int xmc_ccu_off(struct device *dev, clock_control_subsys_t sub_system)
{
	struct xmc_pclken *pclken = (struct xmc_pclken *)(sub_system);

	ARG_UNUSED(dev);

#if defined(PERIPHERAL_RESET_SUPPORTED)
	XMC_SCU_RESET_AssertPeripheralReset(pclken->rst);
#endif
#if defined(CLOCK_GATING_SUPPORTED)
	XMC_SCU_CLOCK_GatePeripheralClock(pclken->bus);
#endif
	return 0;
}

static int xmc_ccu_get_rate(struct device *dev,
			     clock_control_subsys_t sub_system,
			     u32_t *rate)
{
	ARG_UNUSED(dev);
	ARG_UNUSED(sub_system);

	/* TODO: can't use this API for USB, SDMMC, EBU, WDT */
	*rate = XMC_SCU_CLOCK_GetPeripheralClockFrequency();
	return 0;
}

static int xmc_ccu_init(struct device *dev)
{
	/* Default: PLL - 120MHz, fSYS - 120MHz */
	const XMC_SCU_CLOCK_CONFIG_t config =
	{
		.syspll_config.mode = CONFIG_CLOCK_XMC_PLL_MODE,
#if defined(CONFIG_CLOCK_XMC_PLL_CLK_SRC_OSCHP) && CONFIG_CLOCK_XMC_PLL_MODE == 1
		.syspll_config.p_div = CONFIG_CLOCK_XMC_PLL_P_DIVISOR,
		.syspll_config.n_div = CONFIG_CLOCK_XMC_PLL_N_MULTIPLIER,
		.syspll_config.k_div = CONFIG_CLOCK_XMC_PLL_K2_DIVISOR,
#elif CONFIG_CLOCK_XMC_PLL_MODE == 2
		.syspll_config.k_div = CLOCK_XMC_PLL_K1_DIVISOR,
#endif

#if defined(CONFIG_CLOCK_XMC_PLL_CLK_SRC_OSCHP)
		.syspll_config.clksrc = XMC_SCU_CLOCK_SYSPLLCLKSRC_OSCHP,
#else
		.syspll_config.clksrc = XMC_SCU_CLOCK_SYSPLLCLKSRC_OFI,
#endif

#if defined(CONFIG_CLOCK_XMC_SYS_CLK_SRC_PLL)
		.fsys_clksrc = XMC_SCU_CLOCK_SYSCLKSRC_PLL,
#elif defined(CONFIG_CLOCK_XMC_SYS_CLK_SRC_OFI)
		.fsys_clksrc = XMC_SCU_CLOCK_SYSCLKSRC_OFI,
#endif

		.fsys_clkdiv = CONFIG_CLOCK_XMC_SYS_CLK_DIV,
		.fcpu_clkdiv = CONFIG_CLOCK_XMC_CPU_CLK_DIV,
		.fccu_clkdiv = CONFIG_CLOCK_XMC_CCU_CLK_DIV,
		.fperipheral_clkdiv = CONFIG_CLOCK_XMC_PB_CLK_DIV,

		/* TODO: enable_osculp with pm_control for low power clock */
		.enable_oschp = true,
		.calibration_mode = XMC_SCU_CLOCK_FOFI_CALIBRATION_MODE_FACTORY,
	};

	XMC_SCU_CLOCK_Init(&config);

	return 0;
}

static const struct clock_control_driver_api xmc_ccu_driver_api = {
	.on = xmc_ccu_on,
	.off = xmc_ccu_off,
	.get_rate = xmc_ccu_get_rate,
};

DEVICE_AND_API_INIT(xmc_ccu, DT_INST_LABEL(0),
		    &xmc_ccu_init,
		    NULL, NULL,
		    PRE_KERNEL_1, CONFIG_CLOCK_CONTROL_XMC_DEVICE_INIT_PRIORITY,
		    &xmc_ccu_driver_api);
