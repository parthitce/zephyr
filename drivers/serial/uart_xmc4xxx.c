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

struct uart_xmc4xxx_config {
	struct uart_device_config uconf;
	struct xmc_pclken pclken;
};

struct uart_xmc4xxx_data {
	struct uart_config config;
	struct device *clock;
};

#define DEV_CFG(dev) \
	((const struct uart_xmc4xxx_config * const)(dev)->config_info)
#define DEV_DATA(dev) \
	((struct uart_xmc4xxx_data * const)(dev)->driver_data)
#define UART_STRUCT(dev) \
	((XMC_USIC_CH_t *)(DEV_CFG(dev))->uconf.base)

static int uart_xmc4xxx_poll_in(struct device *dev, unsigned char *c)
{
	const struct uart_xmc4xxx_config *config = DEV_CFG(dev);
	XMC_USIC_CH_t *uart = UART_STRUCT(dev);

	*(uint16_t *)c = XMC_UART_CH_GetReceivedData(uart);

	return 0;
}

static void uart_xmc4xxx_poll_out(struct device *dev, unsigned char c)
{
	const struct uart_xmc4xxx_config *config = DEV_CFG(dev);
	XMC_USIC_CH_t *uart = UART_STRUCT(dev);

	XMC_UART_CH_Transmit(uart, (uint16_t)c);
}

static int uart_xmc4xxx_init(struct device *dev)
{
	const struct uart_xmc4xxx_config *config = DEV_CFG(dev);
	struct uart_xmc4xxx_data *data = DEV_DATA(dev);
	XMC_USIC_CH_t *uart = UART_STRUCT(dev);

	data->config.data_bits = 8U;
	data->config.stop_bits = 1U;

	/* configure PIN 0.0 and 0.1 as UART */
	XMC_UART_CH_Init(uart, &(data->config));
	XMC_GPIO_SetMode(P0_0, XMC_GPIO_MODE_INPUT_TRISTATE);
	XMC_UART_CH_SetInputSource(uart, XMC_UART_CH_INPUT_RXD,
				   USIC1_C1_DX0_P0_0);
	XMC_UART_CH_Start(uart);

	XMC_GPIO_SetMode(P0_1,
			 XMC_GPIO_MODE_OUTPUT_PUSH_PULL | P0_1_AF_U1C1_DOUT0);

	return 0;
}

static const struct uart_driver_api uart_xmc4xxx_driver_api = {
	.poll_in = uart_xmc4xxx_poll_in,
	.poll_out = uart_xmc4xxx_poll_out,
};

#define XMC4XXX_INIT(index)						\
static struct uart_xmc4xxx_data xmc4xxx_data_##index = {		\
	.config = {							\
		.baudrate = DT_INST_PROP(index, current_speed)		\
		.stop_bits = DT_INST_PROP(index, stop_bits)		\
		.data_bits = DT_INST_PROP(index, data_bits)		\
		.parity = DT_INST_PROP(index, parity)			\
	}								\
};									\
									\
static const struct uart_xmc4xxx_config xmc4xxx_config_##index = {	\
	.uconf = {							\
		.base = (void *)DT_INST_REG_ADDR(index)			\
	},								\
	.pclken = { .bus = DT_INST_CLOCKS_CELL(index, bus),		\
		    .rst = DT_INST_CLOCKS_CELL(index, rst)		\
	}								\
};									\
									\
DEVICE_AND_API_INIT(uart_xmc4xxx_##index, DT_INST_LABEL(index),		\
		    &uart_xmc4xxx_init, &xmc4xxx_data_##index,		\
		    &xmc4xxx_config_##index, PRE_KERNEL_1,		\
		    CONFIG_KERNEL_INIT_PRIORITY_DEVICE,			\
		    &uart_xmc4xxx_driver_api);

DT_INST_FOREACH_STATUS_OKAY(XMC4XXX_INIT)
