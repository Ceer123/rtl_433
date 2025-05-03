/** @file
    Circrane Pool Sensor decoder, tested with SH-PT-002.
    https://device.report/circrane

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
 */

#include "decoder.h"

/**
Circrane Pool Sensor decoder, tested with SH-PT-002.

Credit to HSkul

The transmitted code is 45 bits sent 8 times (single 0 bit at the end), except for the last transmission the ending zero bit is missing.  The messages are transmitted every 50 seconds.

10010011 1011   0000    TTTTTTTTTTTT 00000000   CCCCCCCC 0
-------------   ----    ------------ --------   -------- -
12 bit ID?      Unknown Tmperature   Humidity?  CRC?

The first 12 bits seem to be fixed so it may be the ID.
The next 4 bits are unknown and seem to be always 0000 
Temperature is 12 bits signed integer.  Divide by 10 to get temperature in Celcius
Next 8 bits are always 0 and I suspect that they are for humidity values for weather stations (no humidity here)
Finally there are 8 bits which I'm assuming are some sort of a CRC
Ends with a single 0 bit for the first 7 transmissions
So 20.3C transmission is this:

{45}93b00cb003d0, {45}93b00cb003d0, {45}93b00cb003d0, {45}93b00cb003d0, {45}93b00cb003d0, {45}93b00cb003d0, {45}93b00cb003d0, {44}93b00cb003d

https://triq.org/bitbench/#c=93b00cb003d&c=93b00b00038&c=93b0035003f&c=93b002f0019&c=93b000200ee&c=93b0ffa007f&c=93b0ff2006f&c=93b0fef00c8&c=93b0fec004d&c=&c=92600e9005b&c=92600f500d8&c=92600f6005d&c=92600f700de&c=92600f8004f&c=92600f900cc&c=92600ee007d&c=9260111007f&c=926010000cc&c=92600f20059&c=92600e6006d&c=92600e700ee&c=92600e8007f&c=92600e900fc&c=92600ea0079&c=92600eb00fa&c=92600ec007b&c=92600ed00f8&c=92600fd00c8&c=9260111007f&c=9260121002f&c=926012800bc&c=926011c00e8&c=926012000ac&c=926011f006d&c=926011800ec&c=926011400f8&c=926010d005b&c=926010a00da&c=926010800dc&c=926010600ce&c=926010400c8&c=92601030049&c=9260101004f&c=926010000cc&c=92600ff00ce&c=92600fe004d&c=92600fc004b&c=92600fb00ca&c=92600fa0049&c=92600f900cc&c=92600f8004f&c=92600f700de&c=92600f6005d&c=&c=&c=92600e6006d&c=92600e700ee&c=92600e8007f&c=92600e900fc&c=92600ea0079&c=92600eb00fa&c=92600ec007b&c=92600ed00f8&c=92600fd00c8&c=9260111007f&c=9260121002f&c=926012800bc&c=926011c00e8&c=926012000ac&c=926011f006d&c=926011800ec&c=926011400f8&c=926010d005b&c=926010a00da&c=926010800dc&c=926010600ce&c=926010400c8&c=92601030049&c=9260101004f&c=926010000cc&c=92600ff00ce&c=92600fe004d&c=92600fc004b&c=92600fb00ca&c=92600fa0049&c=92600f900cc&c=92600f8004f&c=92600f700de&c=92600f6005d&c=92600f500d8&c=92600f4005b&c=92600ef00fe&c=92600e4006b&c=92600e100ec&c=92600c20009&c=92600c0000f&c=92600bf000e&c=92600be008d&c=92600bc008b&c=92600bb000a&f=ID%3F12d%20%3F4h%20TEMP_C%3A12s%20HUM%3A8d%20CHK%3A8h%201x&z=1&cw=4

Sample packets from two different transmitters:
93b00b000380
93b0035003f0
93b002f00190
93b000200ee0
93b0ffa007f0
93b0ff2006f0
93b0fef00c80
93b0fec004d0

92600e6006d
92600e700ee
92600e8007f
92600e900fc
92600ea0079
92600eb00fa
92600ec007b
92600ed00f8
92600fd00c8
*/
static int circrane_decode(r_device *decoder, bitbuffer_t *bitbuffer)
{


    uint8_t *b; // bits of a row
    int r;

    // The message is repeated as 7 packets, require at least 4 repeated packets of 45 bits.
    r = bitbuffer_find_repeated_row(bitbuffer, 4, 45);
    if (r < 0 || bitbuffer->bits_per_row[r] > 45 + 16) {
        return DECODE_ABORT_LENGTH;
    }

    b = bitbuffer->bb[r];


    /*
     * Several tools are available to reverse engineer a message integrity
     * check:
     *
     * - reveng for CRC: http://reveng.sourceforge.net/
     *   - Guide: https://hackaday.com/2019/06/27/reverse-engineering-cyclic-redundancy-codes/
     * - revdgst: https://github.com/triq-org/revdgst/
     * - trial and error, e.g. via online calculators:
     *   - https://www.scadacore.com/tools/programming-calculators/online-checksum-calculator/
     */

    /*
     * Check message integrity (Parity example)
     *
     */
    // parity check: odd parity on bits [0 .. 67]
    // i.e. 8 bytes and a nibble.
    // int parity;
    // parity = b[0] ^ b[1] ^ b[2] ^ b[3] ^ b[4] ^ b[5] ^ b[6] ^ b[7]; // parity as byte
    // parity = (parity >> 4) ^ (parity & 0xF);                        // fold to nibble
    // parity ^= b[8] >> 4;                                            // add remaining nibble
    // parity = (parity >> 2) ^ (parity & 0x3);                        // fold to 2 bits
    // parity = (parity >> 1) ^ (parity & 0x1);                        // fold to 1 bit

    // if (!parity) {
    //     // Enable with -vv (verbose decoders)
    //     decoder_log(decoder, 1, __func__, "parity check failed");
    //     return DECODE_FAIL_MIC;
    // }

    /*
     * Check message integrity (Checksum example)
     */
    // if (((b[0] + b[1] + b[2] + b[3] - b[4]) & 0xFF) != 0) {
    //     // Enable with -vv (verbose decoders)
    //     decoder_log(decoder, 1, __func__, "checksum error");
    //     return DECODE_FAIL_MIC;
    // }

    /*
     * Check message integrity (CRC example)
     *
     * Example device uses CRC-8
     */
    // There are 6 data bytes and then a CRC8 byte
    // int chk = crc8(b, 7, 0x07, 0x00);
    // if (chk != 0) {
    //     // Enable with -vv (verbose decoders)
    //     decoder_log(decoder, 1, __func__, "bad CRC");

    //     // reject row
    //     return DECODE_FAIL_MIC;
    // }

    /*
     * Now that message "envelope" has been validated,
     * start parsing data.
     */
    int sensor_id = (b[0] << 4) | (b[1] >> 4);
    //The value is a 12 bit signed integer starting at b[2]
    uint16_t temp_raw = ((b[2] << 4) | (b[3] >> 4));
    // Now sign-extend from 12 bits to 16/32 bits
    if (temp_raw & 0x800) { // If sign bit (bit 11) is set
        temp_raw |= 0xF000; // Set the upper bits to 1
    }
    int16_t temp = (int16_t)temp_raw;
    float tempc = (float)temp * 0.1f;

    /* clang-format off */
    data_t *data = data_make(
            "model", "", DATA_STRING, "Circrane Pool Thermometer",
            "id",    "Sensor ID", DATA_INT,    sensor_id,
            "temperature_C",  "Temperature", DATA_FORMAT, "%.1f C", DATA_DOUBLE, tempc,
            "mic",   "", DATA_STRING, "NONE", // CRC, CHECKSUM, or PARITY
            NULL);
    /* clang-format on */
    decoder_output_data(decoder, data);

    // Return 1 if message successfully decoded
    return 1;
}

/*
 * List of fields that may appear in the output
 *
 * Used to determine what fields will be output in what
 * order for this device when using -F csv.
 *
 */
static char const *const output_fields[] = {
        "model",
        "id",
        "temperature_C",
        "mic", // remove if not applicable
        NULL,
};

r_device const circrane = {
        .name        = "Circrane decoder",
        .modulation  = OOK_PULSE_PPM,
        .short_width = 1948,  // short gap
        .long_width  = 3900,  // long gap
        .gap_limit   = 3950,  // some distance above long
        .reset_limit = 8828, // a bit longer than packet gap
        .decode_fn   = &circrane_decode,
        .disabled    = 1, // disabled and hidden, use 0 if there is a MIC, 1 otherwise
        .fields      = output_fields,
};
