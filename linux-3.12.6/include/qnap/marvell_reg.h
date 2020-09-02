#ifndef __MARVELL_REG_H__
#define __MARVELL_REG_H__
#define MV_BIT(x)                        (1L << (x))
#define GP_OUT_SET(nr)		MV_BIT(nr)
#define ACTGP_OUT_EN            MV_BIT(5)
#define GP_OUT_EN(nr)		(MV_BIT(8+nr))
#define VENDOR_UNI_REG_2        0x44
//
/* Product device id */
#define MV_VENDOR_ID                           0x11AB

#define DEVICE_ID_THORLITE_2S1P             0x6121
#define DEVICE_ID_THORLITE_0S1P             0x6101
#define DEVICE_ID_THORLITE_1S1P             0x6111
#define DEVICE_ID_THOR_4S1P                 0x6141
#define DEVICE_ID_THOR_4S1P_NEW             0x6145
/* Revision ID starts from B1 */
#define DEVICE_ID_THORLITE_2S1P_WITH_FLASH  0x6122

typedef unsigned int MV_U32;


#endif /* __MARVELL_REG_H__ */
