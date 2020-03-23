/*
 * Copyright (c) 2020 Linumiz
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @brief Hawkbit Firmware Over-the-Air for Zephyr Project.
 * @defgroup hawkbit Hawkbit Firmware Over-the-Air
 * @ingroup lib
 * @{
 */

#ifndef _HAWKBIT_H_
#define _HAWKBIT_H_


#define HAWKBIT_JSON_URL	"/default/controller/v1"


/**
 * @brief Response message from Hawkbit.
 * 
 * @details These messages are used to inform the server and the
 * user about the process status of the Hawkbit and also 
 * used to standardize the errors that may occur.
 *
 */

enum hawkbit_response {
	HAWKBIT_NETWORKING_ERROR = 0,
	HAWKBIT_UNCONFIRMED_IMAGE,
	HAWKBIT_METADATA_ERROR,
	HAWKBIT_DOWNLOAD_ERROR,
	HAWKBIT_INSTALL_ERROR,
	HAWKBIT_FLASH_INIT_ERROR,
	HAWKBIT_OK,
	HAWKBIT_UPDATE_INSTALLED,
	HAWKBIT_NO_UPDATE,
	HAWKBIT_CANCEL_UPDATE,
};

/**
 * @brief Init the flash partition
 *
 * @return 0 on success 
 */
int hawkbit_init(void);

/**
 * @brief Runs Hawkbit probe and Hawkbit update automatically
 *
 * @details The hawkbit_autohandler handles the whole process
 * in pre-determined time intervals.
 */
void hawkbit_autohandler(void);

/**
 * @brief The Hawkbit probe verify if there is some update to be performed.
 *
 * @return HAWKBIT_UPDATE_INSTALLED has an update available.
 * @return HAWKBIT_NO_UPDATE no update available.
 * @return HAWKBIT_NETWORKING_ERROR fail to connect to the Hawkbit server.
 * @return HAWKBIT_INCOMPATIBLE_HARDWARE if Incompatible hardware.
 * @return HAWKBIT_METADATA_ERROR fail to parse or to encode the metadata.
 */
enum hawkbit_response hawkbit_probe(void);

/**
 * @brief Apply the update package.
 *
 * @details Must be used after the Hawkbit probe, if you have updates to
 * be made, will perform the installation of the new image and the hardware
 * will rebooting.
 *
 * @return Return HAWKBIT_OK if success
 * @return HAWKBIT_NETWORKING_ERROR if fail to connect to the server.
 * @return HAWKBIT_DOWNLOAD_ERROR fail while downloading the update package.
 * @return HAWKBIT_INSTALL_ERROR fail while installing the update package.
 * @return HAWKBIT_FLASH_INIT_ERROR fail to initilialize the flash.
 */
enum hawkbit_response hawkbit_update(void);

/**
 * @}
 */

#endif /* _HAWKBIT_H_ */
