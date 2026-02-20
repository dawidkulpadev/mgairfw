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
static const struct device *const i2c_dev = DEVICE_DT_GET(DT_NODELABEL(i2c1));

K_SEM_DEFINE(wake_sem, 0, 1);

enum class SequenceState {MeasureBattery, MeasureAir, WaitingForBT, WaitingForAPIResponse, Finished};

static struct gpio_callback button_cb_data;

void button_pressed(const struct device *dev, struct gpio_callback *cb, uint32_t pins) {
    k_sem_give(&wake_sem);
}


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

    // Config wakeup interrupt
    gpio_pin_interrupt_configure_dt(&btn_pin, GPIO_INT_EDGE_TO_ACTIVE);
    gpio_init_callback(&button_cb_data, button_pressed, BIT(btn_pin.pin));
    gpio_add_callback(btn_pin.port, &button_cb_data);

    uint8_t devMode= DEVICE_MODE_NORMAL;
    if(devicesConfig.getUid()=="-1"){
        devMode= DEVICE_MODE_CONFIG;
    }

    if(devMode==DEVICE_MODE_NORMAL){
        bool sht45Works= true;
        Sht45Sensor airSensor;
        int sequenceCnt=0;
        if (!airSensor.init()) {
            sht45Works= false;
            printk("[E] main - failed sht45 init!\n");
        }

        SequenceState sequenceState;

        ConnectivityClient::init([&sequenceState](int reqId, int errc, int httpCode, const std::string &msg){
            if(sequenceState==SequenceState::WaitingForAPIResponse){
                printk("[D] main - API response: id %d, errc %d, httpc %d, body: %s\n", reqId, errc, httpCode, msg.c_str());
                sequenceState= SequenceState::Finished;
            } else {
                printk("[W] main - Received API response but not waiting for response\n");
            }
        });

        k_sleep(K_SECONDS(3));

        while(1){ // Every loop iteration is one measurement-send-sleep sequence
            sequenceCnt++;
            printk("[I] main - Starting sequence no. %d", sequenceCnt);
            gpio_pin_set_dt(&led, 1);
            sequenceState = SequenceState::MeasureBattery;
            int64_t sequenceStart= k_uptime_get();
            bool runSequence= true;

            double airHumiditySum= 0.0;
            double airTemperatureSum= 0.0;
            uint8_t airMesCnt=10;
            uint8_t airMesMaxTries= 50;

            int32_t batteryMesSum=0;
            uint8_t batteryMesCnt=10;

            k_sleep(K_MSEC(10));
            ConnectivityClient::start();
            k_sleep(K_MSEC(10));
            ConnectivityClient::startServerSearch(30000);

            while(runSequence){
                if(sequenceState== SequenceState::MeasureBattery){
                    batteryMesSum+= measureBattery(adcSequence);
                    batteryMesCnt--;
                    k_sleep(K_MSEC(20));

                    if(batteryMesCnt==0){
                        gpio_pin_set_dt(&led, 0);
                        sequenceState= SequenceState::MeasureAir;
                    }
                } else if(sequenceState== SequenceState::MeasureAir){
                    if(sht45Works){
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
                            sequenceState= SequenceState::WaitingForBT;
                        }
                    } else {
                        sequenceState= SequenceState::WaitingForBT;
                    }
                } else if(sequenceState== SequenceState::WaitingForBT){
                    if(ConnectivityClient::isConnected()){
                        k_sleep(K_MSEC(2));
                        sequenceState= SequenceState::WaitingForAPIResponse;
                        char data[100];
                        snprintf(data, 100, R"("{"ah":%.1f,"at":%.1f,"btry":%d,"fv":%d}")",
                                 airHumiditySum/(10-airMesCnt),
                                 airTemperatureSum/(10-airMesCnt),
                                 (batteryMesSum/10)*2, fw_version);
                        ConnectivityClient::startAPITalk("device/air/post-data", 'P', data);
                    } else{
                        if((k_uptime_get()-sequenceStart) > 30000){
                            sequenceState= SequenceState::Finished;
                        }
                    }
                    k_sleep(K_MSEC(20));
                } else if(sequenceState== SequenceState::WaitingForAPIResponse){
                    if((k_uptime_get()-sequenceStart) > 40000){
                        sequenceState= SequenceState::Finished;
                    }
                    k_sleep(K_MSEC(20));
                } else if(sequenceState== SequenceState::Finished){
                    printk("[D] main - sequence finished in %llu ms\n", k_uptime_get()-sequenceStart);
                    runSequence= false;
                }
            }

            // if timeout - kill bluetooth
            ConnectivityClient::stop();


            //Go to sleep
            printk("[D] main - time to sleep...\n");
            sleepFor(20);
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
    pm_device_action_run(i2c_dev, PM_DEVICE_ACTION_SUSPEND);
    k_sem_take(&wake_sem, K_SECONDS(seconds));
    pm_device_action_run(uart_dev, PM_DEVICE_ACTION_RESUME);
    pm_device_action_run(i2c_dev, PM_DEVICE_ACTION_RESUME);
}

