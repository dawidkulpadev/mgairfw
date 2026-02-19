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
#include "Connectivity/ConnectivityConfig.h"
#include "Connectivity/ConnectivityClient.h"
#include "DeviceConfig.h"
#include "Sht45Sensor.h"
#include <zephyr/drivers/adc.h>
#include <zephyr/devicetree.h>
#include <zephyr/bluetooth/addr.h>
#include <zephyr/bluetooth/bluetooth.h>
#include <zephyr/settings/settings.h>
#include <zephyr/pm/device.h>

static const struct device *const uart_dev = DEVICE_DT_GET(DT_CHOSEN(zephyr_console));
static const struct gpio_dt_spec led = GPIO_DT_SPEC_GET(DT_ALIAS(led0), gpios);
static const struct adc_dt_spec adc_channel = ADC_DT_SPEC_GET(DT_PATH(zephyr_user));
static const struct gpio_dt_spec btn_pin = GPIO_DT_SPEC_GET(DT_ALIAS(my_input_pin), gpios);

enum class SequenceState {MeasureBattery, MeasureAir, WaitingForBT, WaitingForAPIResponse, Finished, Failed};


void printHello();
int32_t measureBattery(struct adc_sequence &seq);
void sleepFor(uint16_t seconds);


int main(void)
{

    int err;
    int ret;

    int16_t buf;
    struct adc_sequence adcSequence = {
            .buffer = &buf,
            .buffer_size = sizeof(buf),
    };

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
    DeviceConfig::registerConfig();
    devicesConfig.loadFactoryData();
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
    err = adc_sequence_init_dt(&adc_channel, &adcSequence);
    if (err < 0) {
        printk("[E] main - ADC sequence init failed: %d\n", err);
        return 0;
    }

    uint8_t devMode= DEVICE_MODE_NORMAL;
    if(devicesConfig.getUid()=="-1"){
        devMode= DEVICE_MODE_CONFIG;
    }

    /**
         * If normal mode:
         * 1) Start connectivity to find and connect with server
         * 2) Meanwhile measure battery voltage
         * 3) Next make air measurements
         * 4) Now wait for server connection (for max 60s if white MAC is unknown, otherwise 20s)
         * 5) If connection is established:
         *      5.1) Send API request to server and wait max 15s for response
         *      5.2) If successful:
         *              5.2.1) go to sleep for 10min
         *      5.3) else:
         *              5.3.1) retry for max 3 times
         * 6) else:
         *      6.1) go to sleep for 10min
         */



    if(devMode==DEVICE_MODE_NORMAL){
        bool sht45Works= true;
        Sht45Sensor airSensor;
        if (!airSensor.init()) {
            sht45Works= false;
            printk("[E] main - failed sht45 init!\n");
        }

        while(1){ // Every loop iteration is one measurement-send-sleep sequence
            gpio_pin_set_dt(&led, 1);
            SequenceState sequenceState= SequenceState::MeasureBattery;
            int64_t sequenceStart= k_uptime_get();
            bool runSequence= true;

            double airHumiditySum= 0.0;
            double airTemperatureSum= 0.0;
            uint8_t airMesCnt=10;
            uint8_t airMesMaxTries= 50;

            int32_t batteryMesSum=0;
            uint8_t batteryMesCnt=10;

            ConnectivityClient::init([](int, int, int, const std::string &){

            });

            k_sleep(K_MSEC(5));
            ConnectivityClient::start();
            k_sleep(K_MSEC(5));
            ConnectivityClient::startServerSearch(60000);

            while(runSequence){
                if(sequenceState== SequenceState::MeasureBattery){
                    batteryMesSum+= measureBattery(adcSequence);
                    batteryMesCnt--;
                    k_sleep(K_MSEC(20));

                    if(batteryMesCnt==0){
                        printk("[D] main - battery: %d mV\n", batteryMesSum/10);
                        sequenceState= SequenceState::MeasureAir;
                    }
                } else if(sequenceState== SequenceState::MeasureAir){
                    double humB;
                    double tempB;
                    if(airSensor.read(tempB, humB)){
                        airHumiditySum+= humB;
                        airTemperatureSum+= tempB;
                        airMesCnt--;
                    }
                    k_sleep(K_MSEC(20));

                    airMesMaxTries--;

                    if(airMesMaxTries==0 or airMesCnt==0){
                        printk("[D] main - air: %.2f %%, %.2f *C\n", airHumiditySum/(10-airMesCnt), airTemperatureSum/(10-airMesCnt));
                        sequenceState= SequenceState::WaitingForBT;
                    }
                } else if(sequenceState== SequenceState::WaitingForBT){
                    if(ConnectivityClient::isConnected()){
                        sequenceState= SequenceState::Finished;
                    } else{
                        if((k_uptime_get()-sequenceStart) > 30000){
                            sequenceState= SequenceState::Finished;
                        }
                    }
                } else if(sequenceState== SequenceState::Finished){
                    printk("[D] main - sequence finished in %llu ms\n", k_uptime_get()-sequenceStart);
                    runSequence= false;
                } else if(sequenceState== SequenceState::Failed){
                    runSequence= false;
                }
            }

            // if timeout - kill bluetooth
            printk("[D] main - connectivity.stop()\n");
            ConnectivityClient::stop();


            //Go to sleep
            gpio_pin_set_dt(&led, 0);
            printk("[D] main - time to sleep...\n");
            sleepFor(60);
        }
    } else {
        ConnectivityConfig::init();
        ConnectivityConfig::start();

        while(1) {
            gpio_pin_toggle_dt(&led);
            k_sleep(K_SECONDS(3));
        }
    }
}

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

int32_t measureBattery(struct adc_sequence &seq){
    int err = adc_read_dt(&adc_channel, &seq);
    int32_t val_mv;
    int16_t raw;

    if (err < 0) {
        printk("ADC read error: %d\n", err);
        val_mv= -1;
    } else {
        raw = *reinterpret_cast<int16_t*>(seq.buffer);
        val_mv= raw;

        // 6. Konwersja na mV
        err = adc_raw_to_millivolts_dt(&adc_channel, &val_mv);
        val_mv += 80;
        if (err < 0) {
            val_mv= -val_mv;
        }
    }

    return val_mv;
}

void sleepFor(uint16_t seconds){
    pm_device_action_run(uart_dev, PM_DEVICE_ACTION_SUSPEND);
    k_sleep(K_SECONDS(seconds));
    pm_device_action_run(uart_dev, PM_DEVICE_ACTION_RESUME);
}

