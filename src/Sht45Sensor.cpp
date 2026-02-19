#include "Sht45Sensor.h"

#define SHT45_NODE DT_NODELABEL(sht45)

Sht45Sensor::Sht45Sensor() : dev(nullptr) {
}

bool Sht45Sensor::init() {
    dev = DEVICE_DT_GET(SHT45_NODE);

    if (!device_is_ready(dev)) {
        printk("[E] Sht45Sensor - Device is not ready!\n");
        return false;
    }

    return true;
}

bool Sht45Sensor::read(double &out_temp, double &out_hum) {
    if (dev == nullptr) {
        printk("NULL\n");
        return false;
    }

    int ret = sensor_sample_fetch(dev);
    if (ret < 0) {
        printk("RET0: %d\n", ret);
        return false;
    }

    struct sensor_value temp_val, hum_val;

    ret = sensor_channel_get(dev, SENSOR_CHAN_AMBIENT_TEMP, &temp_val);
    if (ret < 0) {
        printk("RET1: %d\n", ret);
        return false;
    }

    ret = sensor_channel_get(dev, SENSOR_CHAN_HUMIDITY, &hum_val);
    if (ret < 0) {
        printk("RET2: %d\n", ret);
        return false;
    }

    out_temp = sensor_value_to_double(&temp_val);
    out_hum = sensor_value_to_double(&hum_val);

    return true;
}