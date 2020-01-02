/*
 * QEMU Vulkan helpers
 *
 * Copyright (c) 2017 Alexandro Sanchez Bach
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#ifndef VK_HELPERS_H
#define VK_HELPERS_H

#ifdef _WIN32
#define VK_USE_PLATFORM_WIN32_KHR
#else
#define VK_USE_PLATFORM_XLIB_KHR
#define ARRAYSIZE ARRAY_SIZE
#endif
#include <vulkan/vulkan.h>

#include "qemu/osdep.h"
#include "qemu/thread.h"

typedef struct VulkanState {
    VkInstance instance;
    VkSurfaceKHR surface;
    VkDevice device;

    VkPhysicalDevice gpu;
    VkPhysicalDeviceProperties gpu_props;
    VkPhysicalDeviceFeatures gpu_features;
    VkPhysicalDeviceMemoryProperties mem_props;
    VkQueueFamilyProperties *queue_props;
    uint32_t queue_count;
    uint32_t graphics_queue_node_index;
    VkQueue queue;
    QemuMutex queue_mutex;
    VkDescriptorPool descriptor_pool;
    VkDebugUtilsMessengerEXT debug_messenger;

    uint32_t enabled_extension_count;
    uint32_t enabled_layer_count;
    char *extension_names[64];
} VulkanState;

void vk_init_instance(VulkanState* state, uint32_t extCount, const char **extNames);
void vk_init_device(VulkanState* state);

static inline uint32_t vk_find_memory_type(VulkanState* s, uint32_t typeFilter, VkMemoryPropertyFlags properties) {
    uint32_t i;
    for (i = 0; i < s->mem_props.memoryTypeCount; i++) {
        if ((typeFilter & (1 << i)) && (s->mem_props.memoryTypes[i].propertyFlags & properties) == properties) {
            return i;
        }
    }
    return -1; // TODO: Handle this!
}

#endif /* #define VK_HELPERS_H */
