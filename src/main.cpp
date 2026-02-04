/*
 * Copyright (c) 2016 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <cstdio>
#include <zephyr/kernel.h>
#include <zephyr/drivers/gpio.h>
#include <nrfx.h>
#include <hal/nrf_rtc.h>
#include <hal/nrf_power.h>
#include <hal/nrf_clock.h>
#include "Connectivity/Connectivity.h"

/* 1000 msec = 1 sec */
#define SLEEP_TIME_MS   250

/* The devicetree node identifier for the "led0" alias. */
#define LED0_NODE DT_ALIAS(led0)

/*
 * A build error on this line means your board is unsupported.
 * See the sample documentation for information on how to fix this.
 */
static const struct gpio_dt_spec led = GPIO_DT_SPEC_GET(LED0_NODE, gpios);

int state=1; // 0 - idle, 1 - searching, 2 - connecting, 3 - handshake


#define RTC_INSTANCE NRF_RTC1      // użyj RTC1, by nie rozwalać systemowego RTC0
#define LFCLK_FREQ   32768UL
#define WAKE_SECONDS (1 * 60)     // 10 minut
#define WAKE_TICKS   (LFCLK_FREQ * WAKE_SECONDS)


static void lfclk_start(void)
{
    // włącz zegar 32.768 kHz (LFCLK)
    nrf_clock_task_trigger(NRF_CLOCK, NRF_CLOCK_TASK_LFCLKSTART);
    while (!nrf_clock_event_check(NRF_CLOCK, NRF_CLOCK_EVENT_LFCLKSTARTED)) {
        /* czekaj aż wystartuje */
    }
    nrf_clock_event_clear(NRF_CLOCK, NRF_CLOCK_EVENT_LFCLKSTARTED);
}

static void rtc_setup_for_wakeup(void)
{
    // zatrzymaj RTC na wszelki wypadek
    nrf_rtc_task_trigger(RTC_INSTANCE, NRF_RTC_TASK_STOP);

    // wyczyść zdarzenia
    nrf_rtc_event_clear(RTC_INSTANCE, NRF_RTC_EVENT_COMPARE_0);
    nrf_rtc_event_clear(RTC_INSTANCE, NRF_RTC_EVENT_TICK);
    nrf_rtc_event_clear(RTC_INSTANCE, NRF_RTC_EVENT_OVERFLOW);

    // ustaw preskaler na 0 → 32768 ticków na sekundę
    nrf_rtc_prescaler_set(RTC_INSTANCE, 0);

    // ustaw wartość compare = WAKE_TICKS
    nrf_rtc_cc_set(RTC_INSTANCE, 0, WAKE_TICKS);

    // włącz event COMPARE0
    nrf_rtc_event_enable(RTC_INSTANCE, NRF_RTC_EVENT_COMPARE_0);

    // skonfiguruj, że event COMPARE0 ma wybudzać z SYSTEM OFF
    // Pamiętaj: na nRF52840 zdarzenia peryferiów mogą budzić układ.
    // Wystarczy, że event jest włączony, a peryferium aktywne.

    // wystartuj RTC
    nrf_rtc_task_trigger(RTC_INSTANCE, NRF_RTC_TASK_START);
}

static void go_to_system_off(void)
{
    // Upewnij się, że wszystkie logi poszły:
    k_sleep(K_MSEC(100));

    printk("Wchodzę w SYSTEM OFF, obudzenie za 1 minute (reset)...\r\n");

    // Bariera pamięci
    __DSB();
    __ISB();

    // ustaw SYSTEMOFF → od tej instrukcji CPU „znika”
    nrf_power_system_off(NRF_POWER);

    // poniżej i tak nie dojdziemy :)
}


int main(void)
{
    printk("Hello!\r\n");
	int ret;
	bool led_state = true;

	if (!gpio_is_ready_dt(&led)) {
		return 0;
	}

	ret = gpio_pin_configure_dt(&led, GPIO_OUTPUT_ACTIVE);
	if (ret < 0) {
		return 0;
	}

    lfclk_start();

    k_sleep(K_MSEC(2000));

    rtc_setup_for_wakeup();
    go_to_system_off();

    /*Connectivity connectivity;
    connectivity.start(DEVICE_MODE_CONFIG, [](int, int, int, const std::string &){
        printk("onApiResponseCallback");
    });

    gpio_pin_toggle_dt(&led);

    while(1){
        connectivity.loop();
    }*/


/*
    static BLELNClient cli;

    cli.start("MGcentral", [](const std::string& msg){
        if(state==4 and msg=="$HDSH,OK"){
            printk("Handshake OK received! Connect successful!");
            state = 5;
        }
    });


    bt_addr_le_t found{};
    bool got=false;
    cli.startServerSearch(5000, "", [&](const bt_addr_le_t* addr){
        char buf[50];
        bt_addr_le_to_str(addr, buf, 49);
        printk("BLE Search: %s\r\n", buf);
        if (addr) { found = *addr; got=true; }
    });
    printk("Waiting 200ms...\r\n");
    k_sleep(K_MSEC(200));
    printk("Wait finished\r\n");

	while (1) {
        if(state==1){
            if(got){
                printk("Server found! Connecting...\r\n");
                cli.beginConnect(&found, [&](bool s, int code) {
                    if(s){
                        printk("Connected with server\r\n");
                        state = 3;
                    } else {
                        printk("Failed connecting with server: %d\r\n", code);
                    }
                });
                state = 2;
            }
        } else if(state==2){

        } else if(state==3){
            if(cli.discover()) {
                // 4) handshake
                if (!cli.handshake()) {
                    printk("handshake fail\r\n");
                } else {
                    // 5) send
                    printk("waiting for handshake success message\r\n");
                }
            } else {
                printk("discover fail\r\n");
            }
            state = 4;
        } else if(state ==4){

        }


		ret = gpio_pin_toggle_dt(&led);
		if (ret < 0) {
			return 0;
		}

		led_state = !led_state;
		k_msleep(SLEEP_TIME_MS);
	}*/


	return 0;
}
