/*
 * Copyright (c) 2016 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <cstdio>
#include <zephyr/kernel.h>
#include <zephyr/drivers/gpio.h>
#include "BLELN/BLELNClient.h"

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

int main(void)
{
	int ret;
	bool led_state = true;

	if (!gpio_is_ready_dt(&led)) {
		return 0;
	}

	ret = gpio_pin_configure_dt(&led, GPIO_OUTPUT_ACTIVE);
	if (ret < 0) {
		return 0;
	}


    static BLELNClient cli;

    cli.start("MGcentral", [](const std::string& msg){
        if(state==4 and msg=="$HDSH,OK"){
            printk("Handshake OK received! Connect successful!");
            state = 5;
        }
    });


    bt_addr_le_t found{};
    bool got=false;
    cli.startServerSearch(5000, BLELNBase::SERVICE_UUID, [&](const bt_addr_le_t* addr){
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
	}
	return 0;
}
