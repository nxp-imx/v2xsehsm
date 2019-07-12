
#include "v2xSe.h"

#define VERSION_GENERATION	3
#define VERSION_MAJOR		1
#define VERSION_MINOR		0

/* Length V2XSE_PLATFORM_IDENTITY = 16 bytes */
#define PLATFORMINFO_STRING "HSM0IMX800000001"

/* Length V2XSE_SERIAL_NUMBER = 24 bytes */
#define SERIALNUM_BYTES {0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3}

#define V2XSE_STATE_INIT	0
#define V2XSE_STATE_CONNECTED	1
#define V2XSE_STATE_ACTIVATED	2

#define STORAGE_PATH "/etc/v2x_hsm_adaptation/"

#define NUM_STORAGE_SLOTS	10000

extern uint8_t	v2xsePhase;

#define ENFORCE_STATE_INIT() {					\
	if (v2xseState != V2XSE_STATE_INIT) {			\
		if (v2xseState == V2XSE_STATE_CONNECTED)	\
			return V2XSE_FAILURE_CONNECTED;		\
		if (v2xseState == V2XSE_STATE_ACTIVATED)	\
			return V2XSE_FAILURE_ACTIVATED;		\
		return V2XSE_FAILURE;				\
	}							\
}
