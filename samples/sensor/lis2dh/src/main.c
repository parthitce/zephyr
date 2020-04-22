/*
 * Copyright (c) 2019 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <zephyr.h>
#include <device.h>
#include <drivers/sensor.h>

#define ACTIVE_MODE	1
#define SLEEP_MODE	0

void sleep_modeCallback(void) 
{
	printf("print from sleep mode callback \n");
}

void active_modeCallback(void)
{
	printf("print from active mode callback \n");
}

void mode_changed(void (*ptr)())
{
	(*ptr)();
}
void (*ptr1)() = &sleep_modeCallback;
void (*ptr2)() = &active_modeCallback;


static u32_t time, prev_time, t;
static bool mode;

static void fetch_and_display(struct device *sensor)
{
	int rc = sensor_sample_fetch(sensor);
	if (rc < 0) {
		printf("Unabe to fetch sample: %d \n", rc);
	}

	time = k_uptime_get_32();		
	t = time - prev_time;

	printf("t: %d \n", t);

	prev_time = time;

	if ((t < 80) && (mode == SLEEP_MODE)) {
		mode_changed(active_modeCallback);
		mode = ACTIVE_MODE;
	} else if ((t > 80) && (mode == ACTIVE_MODE)) {
		mode_changed(sleep_modeCallback);
		mode = SLEEP_MODE;
	}
}

#ifdef CONFIG_LIS2DH_TRIGGER
static void trigger_handler(struct device *dev,
			    struct sensor_trigger *trig)
{
	fetch_and_display(dev);
}

static void motion_handler(struct device *dev,
			   struct sensor_trigger *trig)
{
        int rc = sensor_sample_fetch(dev);
        if (rc < 0) {
                printf("Unabe to fetch sample: %d \n", rc);
        }

	printf("print from motion handler \n");
	if (trig->type == SENSOR_TRIG_TAP) {
		printf("Single tap \n");
	} else if (trig->type == SENSOR_TRIG_DOUBLE_TAP) {
		printf("Double tap \n");
	}
}
#endif

void main(void)
{
	struct device *sensor = device_get_binding(DT_LABEL(DT_INST(0, st_lis2dh)));

	if (sensor == NULL) {
		printf("Could not get %s device\n",
		       DT_LABEL(DT_INST(0, st_lis2dh)));
		return;
	}

#if CONFIG_LIS2DH_TRIGGER
	{
		struct sensor_trigger trig, trig1;
		int rc;

		trig.type = SENSOR_TRIG_DATA_READY;
		trig.chan = SENSOR_CHAN_ACCEL_XYZ;


		rc = sensor_trigger_set(sensor, &trig, trigger_handler);

		if (rc != 0) {
			printf("Failed to set trigger: %d\n", rc);
			return;
		}

		
		trig1.type = SENSOR_TRIG_DELTA,
		trig1.chan = SENSOR_CHAN_ALL,
		
		rc = sensor_trigger_set(sensor, &trig1, motion_handler);

		if (rc != 0) {
			printf("Failed to set trigger: %d\n", rc);
			return;
		}

	
                static struct sensor_value motion_threshold;

                motion_threshold.val1 = 14;
                motion_threshold.val2 = 226600;
                rc = sensor_attr_set(sensor, SENSOR_CHAN_ACCEL_XYZ, SENSOR_ATTR_SLOPE_TH, &motion_threshold);
                if (rc) {
                        printk("Unable to set motion threshold\n");
                }


                static struct sensor_value motion_duration;

                motion_duration.val1 = 10;
                motion_duration.val2 = 0;

                rc = sensor_attr_set(sensor, SENSOR_CHAN_ACCEL_XYZ, SENSOR_ATTR_SLOPE_DUR, &motion_duration);
                if (rc) {
                        printk("Unable to set motion duration \n");
                }

                static struct sensor_value activity_threshold;

                activity_threshold.val1 = 5;
                activity_threshold.val2 = 226600;
                rc = sensor_attr_set(sensor, SENSOR_CHAN_ACTIVITY, SENSOR_ATTR_ACTIVITY_TH, &activity_threshold);
                if (rc) {
                        printk("Unable to set Activity Threshold\n");
                }


                static struct sensor_value activity_duration;

                activity_duration.val1 = 5;
                activity_duration.val2 = 0;

                rc = sensor_attr_set(sensor, SENSOR_CHAN_ACCEL_XYZ, SENSOR_ATTR_ACTIVITY_DUR, &activity_duration);
                if (rc) {
                        printk("Unable to set Activity duration \n");
                }


		
		printf("Waiting for triggers\n");
	}
#else /* CONFIG_LIS2DH_TRIGGER */
	/*printf("Polling at 0.5 Hz\n");
	while (true) {
		fetch_and_display(sensor);
		k_sleep(K_MSEC(2000));
	}*/
#endif /* CONFIG_LIS2DH_TRIGGER */
}
