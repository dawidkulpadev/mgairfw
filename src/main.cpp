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
#include "Connectivity/Connectivity.h"
#include <zephyr/drivers/adc.h>
#include <zephyr/devicetree.h>

K_THREAD_STACK_DEFINE(g_connectivity_stack, 1024)

uint64_t lastWaterMarkPrint= 0;
Connectivity connectivity;
bool runConnectivity= false;
struct k_thread connectivity_thread{};


/* The devicetree node identifier for the "led0" alias. */
#define LED0_NODE DT_ALIAS(led0)

/*
 * A build error on this line means your board is unsupported.
 * See the sample documentation for information on how to fix this.
 */
static const struct gpio_dt_spec led = GPIO_DT_SPEC_GET(LED0_NODE, gpios);

int state=1; // 0 - idle, 1 - searching, 2 - connecting, 3 - handshake

static const struct adc_dt_spec adc_channel = ADC_DT_SPEC_GET(DT_PATH(zephyr_user));
static const struct gpio_dt_spec my_pin = GPIO_DT_SPEC_GET(DT_ALIAS(my_input_pin), gpios);

int16_t buf;
struct adc_sequence sequence = {
        .buffer = &buf,
        .buffer_size = sizeof(buf),
        // calibrate i resolution zostaną pobrane z DTS funkcją init
};

#define RTC_INSTANCE NRF_RTC1      // użyj RTC1, by nie rozwalać systemowego RTC0
#define LFCLK_FREQ   32768UL
#define WAKE_SECONDS (1 * 60)     // 10 minut
#define WAKE_TICKS   (LFCLK_FREQ * WAKE_SECONDS)

void printHello(){
    std::string out;
    bt_addr_le_t mac;
    size_t count = 1;
    bt_id_get(&mac, &count);

    printk("MioGiapicco Air Firmware  Copyright (C) 2026  Dawid Kulpa\n");
    printk("This program comes with ABSOLUTELY NO WARRANTY;\n");
    printk("This is free software, and you are welcome to redistribute it under certain conditions;\n");
    printk("You should have received a copy of the GNU General Public License along with this program. If not, see <http://www.gnu.org/licenses/>.\n");
    printk("Hardware code: %d, Firmware code: %d, MAC: %02X:%02X:%02X:%02X:%02X:%02X\r\n",
                  hw_id, fw_version, mac.a.val[0], mac.a.val[1], mac.a.val[2], mac.a.val[3], mac.a.val[4], mac.a.val[5]);
}

int main(void)
{
    int err;


	int ret;
	bool led_state = true;

	if (!gpio_is_ready_dt(&led)) {
		return 0;
	}

	ret = gpio_pin_configure_dt(&led, GPIO_OUTPUT_ACTIVE);
	if (ret < 0) {
		return 0;
	}

    if (!gpio_is_ready_dt(&my_pin)) {
        printk("Error: GPIO port not ready\n");
        return 0;
    }

    // 3. Konfigurujemy pin jako wejście (flagi z DTS: Pull-down itp. są tu automatycznie brane)
    ret = gpio_pin_configure_dt(&my_pin, GPIO_INPUT);
    if (ret != 0) {
        printk("Error: Could not configure pin\n");
        return 0;
    }


	if (!adc_is_ready_dt(&adc_channel)) {
        printk("ADC controller device not ready\n");
        return 0;
    }

    // 3. Konfigurujemy kanał danymi z Device Tree (.overlay)
    //    To ustawi gain, reference, acquisition time ORAZ PIN P0.05
    err = adc_channel_setup_dt(&adc_channel);
    if (err < 0) {
        printk("Setup failed: %d\n", err);
        return 0;
    }

    err = adc_sequence_init_dt(&adc_channel, &sequence);
    if (err < 0) {
        printk("Sequence init failed: %d\n", err);
        return 0;
    }

    printk("ADC reading starting on %s, channel %d\n",
           adc_channel.dev->name, adc_channel.channel_id);

    bt_enable(nullptr);

    settings_load();

    printHello();

    BLELNCert myCert("e1fac2b02f3b67dbd10e2b3e5539b4b5598f1dc9ec17b506a2cf08df25ce66860169ab8bb11e8c45a2c1d3d1ca5c6d4bd0220400751c766447c8ab232c3c35a6",
                     "f1b64c144a0789f56815ac8e900a216c4a713cd066f77cbd979a1205ef7a4f6bac99ccb4f06fbd03b2032698e72c00c58b2846e56a6712d537e7167e2fd1bfe3",
                     "39fda9f58c3654131476e0793c4afb6b7328df16603ec21f0d196e7e02103b93",
                     "363a0d2bf0d7f4bfe4a3b22ae111863d75dd5b9851246b5e5ee738d9832f6f7c97fea4b64c41df66023cba79d0e894d9bd5471b5cb47b6efa3510bf4caf65044");

    connectivity.start(DEVICE_MODE_CONFIG, [](int id, int errc, int httpCode, const std::string &msg){
    }, &myCert);
    runConnectivity= true;
    k_thread_create(&connectivity_thread, g_connectivity_stack, K_THREAD_STACK_SIZEOF(g_connectivity_stack),
                    [](void* p1, void*, void*) {
                        while(runConnectivity){
                            connectivity.loop();
                            if(lastWaterMarkPrint+10000 < k_uptime_get()) {
                                size_t unused_bytes = 0;
                                int ret = k_thread_stack_space_get(k_current_get(), &unused_bytes);
                                if(ret == 0){
                                    printk("[D] Connectivity loop stack free: %u\n\r", unused_bytes);
                                }
                                lastWaterMarkPrint= k_uptime_get();
                            }
                        }
                    }, nullptr, nullptr, nullptr, K_PRIO_COOP(8), 0, K_NO_WAIT);

    while(1){
        gpio_pin_set_dt(&led, GPIO_ACTIVE_LOW);
        err = adc_read_dt(&adc_channel, &sequence);
        if (err < 0) {
            printk("ADC read error: %d\n", err);
        } else {
            int32_t val_mv = buf;

            printk("Raw: %d\n", buf);

            // 6. Konwersja na mV
            err = adc_raw_to_millivolts_dt(&adc_channel, &val_mv);
            val_mv-=80;
            if (err < 0) {
                printk(" (value in mV not available)\n");
            } else {
                printk("Voltage: %d mV\n", val_mv*2);
            }
        }


        k_sleep(K_SECONDS(1));
        gpio_pin_set_dt(&led, GPIO_ACTIVE_HIGH);
        k_sleep(K_SECONDS(10));
    }
}
