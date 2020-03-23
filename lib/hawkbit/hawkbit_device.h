/*
 * Copyright (c) 2020 Linumiz
 *
 * SPDX-License-Identiier: Apache-2.0
 */

#ifndef __HAWKBIT_DEVICE_H__
#define __HAWKBIT_DEVICE_H__

#include <zephyr.h>
#include <drivers/hwinfo.h>

#define DEVICE_ID_MAX_SIZE 8 

bool hawkbit_get_device_identity(char *id, int id_max_len);

#endif /* __HAWKBIT_DEVICE_H__ */
