/*
 * Copyright (c) 2020 Linumiz
 * Author: Parthiban Nallathambi <parthiban@linumiz.com>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define DT_DRV_COMPAT	infineon_xmc4xxx_uart

#include <xmc_gpio.h>
#include <xmc_uart.h>
#include <drivers/uart.h>

struct uart_xmc4xxx_data {
	XMC_UART_CH_CONFIG_t config;
};

#define DEV_CFG(dev) \
	((const struct uart_device_config * const)(dev)->config->config_info)
#define DEV_DATA(dev) \
	((struct uart_xmc4xxx_data * const)(dev)->driver_data)

static int uart_xmc4xxx_poll_in(struct device *dev, unsigned char *c)
{
	const struct uart_device_config *config = DEV_CFG(dev);

	*(uint16_t *)c = XMC_UART_CH_GetReceivedData((XMC_USIC_CH_t *)config->base);

	return 0;
}

static void uart_xmc4xxx_poll_out(struct device *dev, unsigned char c)
{
	const struct uart_device_config *config = DEV_CFG(dev);

	XMC_UART_CH_Transmit((XMC_USIC_CH_t *)config->base, (uint16_t)c);
}

static int uart_xmc4xxx_init(struct device *dev)
{
	const struct uart_device_config *config = DEV_CFG(dev);
	struct uart_xmc4xxx_data *data = DEV_DATA(dev);
	XMC_USIC_CH_t *uart = (XMC_USIC_CH_t *)config->base;

	data->config.data_bits = 8U;
	data->config.stop_bits = 1U;

	/* configure PIN 1.4 and 1.5 as UART */
	XMC_UART_CH_Init(uart, &(data->config));
	XMC_GPIO_SetMode(P1_4, XMC_GPIO_MODE_INPUT_TRISTATE);
	XMC_UART_CH_SetInputSource(uart, XMC_UART_CH_INPUT_RXD,
				   USIC0_C0_DX0_P1_4);
	XMC_UART_CH_Start(uart);

	XMC_GPIO_SetMode(P1_5, XMC_GPIO_MODE_OUTPUT_PUSH_PULL | P1_5_AF_U0C0_DOUT0);

	return 0;
}

static const struct uart_driver_api uart_xmc4xxx_driver_api = {
	.poll_in = uart_xmc4xxx_poll_in,
	.poll_out = uart_xmc4xxx_poll_out,
};

#define XMC4XXX_INIT(index)						\
static struct uart_xmc4xxx_data xmc4xxx_data_##index = {		\
	.config.baudrate = DT_INST_PROP(index, current_speed)		\
};									\
									\
static const struct uart_device_config xmc4xxx_config_##index = {	\
	.base = (void *)DT_INST_REG_ADDR(index),			\
};									\
									\
	DEVICE_AND_API_INIT(uart_xmc4xxx_##index, DT_INST_LABEL(index),	\
			    &uart_xmc4xxx_init, &xmc4xxx_data_##index,	\
			    &xmc4xxx_config_##index, PRE_KERNEL_1,	\
			    CONFIG_KERNEL_INIT_PRIORITY_DEVICE,		\
			    &uart_xmc4xxx_driver_api)			\

DT_INST_FOREACH(XMC4XXX_INIT)
