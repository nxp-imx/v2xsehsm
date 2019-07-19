
#ifndef ADAPTLIB_H
#define ADAPTLIB_H

#include "v2xSe.h"
#include "../hsmstub/hsmstub.h"

#define VERSION_GENERATION	3
#define VERSION_MAJOR		1
#define VERSION_MINOR		0

/* Length V2XSE_PLATFORM_IDENTITY = 16 bytes */
#define PLATFORMINFO_STRING "HSM0IMX800000001"

/* Length V2XSE_SERIAL_NUMBER = 24 bytes */
#define SERIALNUM_BYTES 	\
	{0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3}

#define V2XSE_STATE_INIT	0
#define V2XSE_STATE_CONNECTED	1
#define V2XSE_STATE_ACTIVATED	2

#define STORAGE_PATH "/etc/v2x_hsm_adaptation/"

#define NUM_STORAGE_SLOTS	10000

extern uint8_t	v2xsePhase;
extern uint32_t key_store_nonce;
extern uint32_t maKeyHandle;
extern TypeCurveId_t maCurveId;
extern uint32_t rtKeyHandle[NUM_STORAGE_SLOTS];
extern TypeCurveId_t rtCurveId[NUM_STORAGE_SLOTS];
extern uint32_t baKeyHandle[NUM_STORAGE_SLOTS];
extern TypeCurveId_t baCurveId[NUM_STORAGE_SLOTS];

#define MAGIC_KEYSTORE_IDENTIFIER	0x87131966
#define MAX_KEYSTORE_UPDATES		0xffff

#define HSM_SESSION_PRIORITY	0
#define HSM_OPERATING_MODE	0

#define VERIFY_STATUS_CODE_PTR() {				\
	if (!pHsmStatusCode)					\
		return V2XSE_FAILURE;				\
}

#define ENFORCE_STATE_INIT() {					\
	if (v2xseState != V2XSE_STATE_INIT) {			\
		if (v2xseState == V2XSE_STATE_CONNECTED)	\
			return V2XSE_FAILURE_CONNECTED;		\
		if (v2xseState == V2XSE_STATE_ACTIVATED)	\
			return V2XSE_FAILURE_ACTIVATED;		\
		return V2XSE_FAILURE;				\
	}							\
}

#define ENFORCE_STATE_NOT_INIT() {				\
	if (v2xseState == V2XSE_STATE_INIT) {			\
		*pHsmStatusCode = V2XSE_UNDEFINED_ERROR;	\
		return V2XSE_DEVICE_NOT_CONNECTED;		\
	}							\
}

#define ENFORCE_STATE_ACTIVATED() {				\
	if (v2xseState != V2XSE_STATE_ACTIVATED) {		\
		*pHsmStatusCode = V2XSE_UNDEFINED_ERROR;	\
		return V2XSE_DEVICE_NOT_CONNECTED;		\
	}							\
}

#define ENFORCE_POINTER_NOT_NULL(ptr) {				\
	if (!ptr) {						\
		*pHsmStatusCode = V2XSE_UNDEFINED_ERROR;	\
		return V2XSE_FAILURE;				\
	}							\
}

#define ENFORCE_NORMAL_OPERATING_PHASE() {			\
	if (v2xsePhase != V2XSE_NORMAL_OPERATING_PHASE) {	\
		*pHsmStatusCode = V2XSE_UNDEFINED_ERROR;	\
		return V2XSE_FAILURE;				\
	}							\
}

#endif
