#include "serial_out.h"

#include <esp_heap_caps.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <freertos/message_buffer.h>

namespace serial_out {

namespace {

MessageBufferHandle_t g_mb        = nullptr;
uint8_t*              g_storage   = nullptr;
StaticMessageBuffer_t g_control;
volatile uint32_t     g_dropped   = 0;
TaskHandle_t          g_task      = nullptr;

void output_task(void*) {
    // Owns Serial exclusively. Reads one full message at a time and drains
    // every byte to Serial with retry, so message boundaries are preserved.
    static uint8_t rx[MAX_MESSAGE];
    for (;;) {
        size_t n = xMessageBufferReceive(g_mb, rx, sizeof(rx), portMAX_DELAY);
        if (n == 0) continue;

        // Wait for enough contiguous CDC buffer space, then do a single
        // Serial.write for the whole message. This avoids the retry-loop
        // path where a partial-return-plus-retry can duplicate the tail on
        // some USBCDC driver versions. If space never comes (host truly
        // gone), drop the message rather than block forever.
        for (int spin = 0; spin < 200; ++spin) {
            if ((size_t)Serial.availableForWrite() >= n) break;
            vTaskDelay(pdMS_TO_TICKS(1));
        }
        if ((size_t)Serial.availableForWrite() >= n) {
            Serial.write(rx, n);  // single call, no retry
            // 1-tick yield lets the USB CDC ISR chew the ring before the
            // next message. Without this, back-to-back writes at high rate
            // can trip a byte-duplicate at USB packet boundaries on some
            // TinyUSB builds.
            vTaskDelay(pdMS_TO_TICKS(1));
        } else {
            g_dropped++;          // host absent -- drop rather than desync
        }
    }
}

} // namespace

bool init() {
    if (g_mb) return true;
    g_storage = (uint8_t*) heap_caps_malloc(BUFFER_BYTES, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!g_storage) g_storage = (uint8_t*) malloc(BUFFER_BYTES);
    if (!g_storage) return false;

    g_mb = xMessageBufferCreateStatic(BUFFER_BYTES, g_storage, &g_control);
    if (!g_mb) return false;

    // Pin to core 0 alongside the WiFi task. Stack 4 KB is comfortable for
    // Serial.write + a 4 KB rx buffer that lives in .bss (static).
    xTaskCreatePinnedToCore(&output_task, "ser_out", 4096, nullptr, 6, &g_task, 0);
    return true;
}

bool submit(const uint8_t* buf, size_t len) {
    if (!g_mb || len == 0 || len > MAX_MESSAGE) { g_dropped++; return false; }
    // Zero-tick send -- if the buffer is full we drop rather than block
    // the caller (usually pcap_writer_task which must keep draining rings).
    size_t sent = xMessageBufferSend(g_mb, buf, len, 0);
    if (sent != len) { g_dropped++; return false; }
    return true;
}

uint32_t dropped() { return g_dropped; }

} // namespace serial_out
