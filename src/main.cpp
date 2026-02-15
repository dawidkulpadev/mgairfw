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
#include "bleln/BLELNCert.h"
#include "DeviceConfig.h"
#include <zephyr/drivers/adc.h>
#include <zephyr/devicetree.h>
#include <zephyr/bluetooth/addr.h>
#include <zephyr/bluetooth/bluetooth.h>
#include <zephyr/settings/settings.h>

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
static const struct gpio_dt_spec btn_pin = GPIO_DT_SPEC_GET(DT_ALIAS(my_input_pin), gpios);

int16_t buf;
struct adc_sequence sequence = {
        .buffer = &buf,
        .buffer_size = sizeof(buf),
        // calibrate i resolution zostaną pobrane z DTS funkcją init
};




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
           hw_id, fw_version,
           mac.a.val[5], mac.a.val[4], mac.a.val[3],
           mac.a.val[2], mac.a.val[1], mac.a.val[0]);
}

int main(void)
{
    int err;
    int ret;

    // Configure system LED
    if (!gpio_is_ready_dt(&led)) {
        return 0;
    }
    ret = gpio_pin_configure_dt(&led, GPIO_OUTPUT_ACTIVE);
    if (ret < 0) {
        return 0;
    }

    // Enable BLE
    bt_enable(nullptr);

    // Load devices config
    devicesConfig.loadFactoryData();
    devicesConfig.registerConfig();
    k_sleep(K_MSEC(1000));
    printk("settings_load()\n");
    settings_load();


    // Print Hello!
    printHello();

    // Config devices button
    if (!gpio_is_ready_dt(&btn_pin)) {
        printk("[E] main - Button port not ready\n");
        return 0;
    }
    ret = gpio_pin_configure_dt(&btn_pin, GPIO_INPUT);
    if (ret != 0) {
        printk("[E] main - Could not configure button pin\n");
        return 0;
    }

    if(gpio_pin_get_dt(&btn_pin)==1){
        printk("[W] main - Factory reset!\n");
        devicesConfig.factoryReset();
    }

    printk("Button: %d\n", gpio_pin_get_dt(&btn_pin));

    // Config ADC for battery measurement
	if (!adc_is_ready_dt(&adc_channel)) {
        printk("[E] main - ADC controller not ready\n");
        return 0;
    }
    err = adc_channel_setup_dt(&adc_channel);
    if (err < 0) {
        printk("[E] main - ADC setup failed: %d\n", err);
        return 0;
    }
    err = adc_sequence_init_dt(&adc_channel, &sequence);
    if (err < 0) {
        printk("[E] main - ADC sequence init failed: %d\n", err);
        return 0;
    }

    uint8_t devMode= DEVICE_MODE_NORMAL;
    if(devicesConfig.getUid()=="-1"){
        devMode= DEVICE_MODE_CONFIG;
    }

    connectivity.start(DEVICE_MODE_CONFIG, [](int id, int errc, int httpCode, const std::string &msg){

    });
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
        if(devMode==DEVICE_MODE_CONFIG){
            gpio_pin_toggle_dt(&led);
            k_sleep(K_SECONDS(3));
        } else {
            gpio_pin_set_dt(&led, GPIO_ACTIVE_LOW);
            err = adc_read_dt(&adc_channel, &sequence);
            if (err < 0) {
                printk("ADC read error: %d\n", err);
            } else {
                int32_t val_mv = buf;

                printk("Raw: %d\n", buf);

                // 6. Konwersja na mV
                err = adc_raw_to_millivolts_dt(&adc_channel, &val_mv);
                val_mv -= 80;
                if (err < 0) {
                    printk(" (value in mV not available)\n");
                } else {
                    printk("Voltage: %d mV\n", val_mv * 2);
                }
            }


            k_sleep(K_SECONDS(1));
            gpio_pin_set_dt(&led, GPIO_ACTIVE_HIGH);
            k_sleep(K_SECONDS(10));
        }
    }
}
