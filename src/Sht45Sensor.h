//
// Created by dkulpa on 18.02.2026.
//

#ifndef MGAIRFW_SHT45SENSOR_H
#define MGAIRFW_SHT45SENSOR_H

#include <zephyr/kernel.h>
#include <zephyr/drivers/sensor.h>
#include <zephyr/device.h>

class Sht45Sensor {
public:

    Sht45Sensor();
    bool init();
    bool read(double &out_temp, double &out_hum);

private:
    const struct device *dev;
};


#endif //MGAIRFW_SHT45SENSOR_H
