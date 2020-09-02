#ifndef __I2C_MV9235
#define __I2C_MV9235

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/spinlock.h>
#include <linux/i2c.h>
#include <linux/interrupt.h>
#include <linux/mv643xx_i2c.h>
#include <linux/platform_device.h>
#include <linux/io.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/of_irq.h>
#include <linux/clk.h>
#include <linux/err.h>
#include <linux/delay.h>

#include <linux/printk.h>
#include <linux/device.h>
#include <linux/pci.h>
#include <linux/list.h>
#include <linux/libata.h>


/* CONFIG_I2C_MV9235 */
#if IS_ENABLED(CONFIG_I2C_MV9235)
extern int mv9235_i2c_init(struct pci_dev *pdev, void __iomem *pci_bar5); //defined in drivers/i2c/busses/i2c-mv9235.c
extern int mv9235_i2c_remove(struct pci_dev *pdev, void __iomem *bar5);//defined in drivers/i2c/busses/i2c-mv9235.c
#else /* CONFIG_I2C_MV9235 */
static inline int mv9235_i2c_init(struct pci_dev *pdev, void __iomem *pci_bar5)
{ return 0; }
static inline int mv9235_i2c_remove(struct pci_dev *pdev, void __iomem *bar5)
{ return 0; }
#endif /* CONFIG_I2C_MV9235 */

#endif
