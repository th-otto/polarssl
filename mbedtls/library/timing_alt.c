#include "common.h"

#ifdef __MINT__ /* whole file */

#include "mbedtls/timing.h"

#include <unistd.h>
#include <sys/time.h>
#include <mint/osbind.h>

static int used_system = 0;
#define SYSTEM_MINT  0  /* MiNT */
#define SYSTEM_OTHER 1  /* Other than MiNT (TOS, MagiC) */

void timing_set_system(int value)
{
	used_system = value;
}

struct _hr_time
{
	struct timeval start;
};

static int hardclock_init = 0;
static struct timeval tv_init;
static long time_init = 0;

unsigned long mbedtls_timing_get_timer(struct mbedtls_timing_hr_time *val, int reset)
{
	unsigned long delta;
	struct _hr_time *t = (struct _hr_time *) val;
	
	if (used_system == SYSTEM_MINT)
	{
		struct timeval offset;

		gettimeofday(&offset, NULL);
		
		if (hardclock_init == 0)
		{
			tv_init = offset;
			hardclock_init = 1;
		}
			
		if (reset)
		{
			t->start.tv_sec = offset.tv_sec;
			t->start.tv_usec = offset.tv_usec;
			delta = 0;
		} else
		{
			delta = (offset.tv_sec - t->start.tv_sec) * 1000 + (offset.tv_usec - t->start.tv_usec) / 1000;
		}
	} else
	{
		long time_cur = Gettime();

		if (hardclock_init == 0)
		{
			time_init = time_cur;
			hardclock_init = 1;
		}

		if (reset)
		{
			t->start.tv_sec = time_cur;
			t->start.tv_usec = 0;
			delta = 0;
		} else
		{
			delta = (time_cur - t->start.tv_sec) * 1000;
		}
	}
	
	return delta;
}

void mbedtls_net_usleep(unsigned long usec)
{
	struct timeval tv;
	
	tv.tv_sec = usec / 1000000;
	tv.tv_usec = usec % 1000000;
	
	select( 0, NULL, NULL, NULL, &tv );
}

/*
 * Set delays to watch
 */
void mbedtls_timing_set_delay(void *data, uint32_t int_ms, uint32_t fin_ms)
{
    mbedtls_timing_delay_context *ctx = (mbedtls_timing_delay_context *) data;

    ctx->int_ms = int_ms;
    ctx->fin_ms = fin_ms;

    if (fin_ms != 0) {
        (void) mbedtls_timing_get_timer(&ctx->timer, 1);
    }
}

/*
 * Get number of delays expired
 */
int mbedtls_timing_get_delay(void *data)
{
    mbedtls_timing_delay_context *ctx = (mbedtls_timing_delay_context *) data;
    unsigned long elapsed_ms;

    if (ctx->fin_ms == 0) {
        return -1;
    }

    elapsed_ms = mbedtls_timing_get_timer(&ctx->timer, 0);

    if (elapsed_ms >= ctx->fin_ms) {
        return 2;
    }

    if (elapsed_ms >= ctx->int_ms) {
        return 1;
    }

    return 0;
}

/*
 * Get the final delay.
 */
uint32_t mbedtls_timing_get_final_delay(const mbedtls_timing_delay_context *data)
{
    return data->fin_ms;
}
#endif /* __MINT__ */
