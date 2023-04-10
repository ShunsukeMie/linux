/* SPDX-License-Identifier: GPL-2.0 */
#ifndef LINUX_COMPILER_H
#define LINUX_COMPILER_H

#include "../../../include/linux/compiler_types.h"

#define WRITE_ONCE(var, val) \
	(*((volatile typeof(val) *)(&(var))) = (val))

#define READ_ONCE(var) (*((volatile typeof(var) *)(&(var))))

#define __aligned(x) __attribute((__aligned__(x)))

#define __same_type(a, b) __builtin_types_compatible_p(typeof(a), typeof(b))

#endif
