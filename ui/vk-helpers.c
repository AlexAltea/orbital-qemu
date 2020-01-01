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

#include "ui/vk-helpers.h"
#include "qemu/osdep.h"
#include "qemu/error-report.h"

// Enables or disables validation layers
#define VK_DEBUG 1

#define countof(x) (sizeof(x) / sizeof((x)[0]))

#define ARRAYSIZE(_ARR)          ((int)(sizeof(_ARR)/sizeof(*_ARR)))
/* callbacks */
static 
VKAPI_ATTR VkBool32 VKAPI_CALL debugCallback(
        VkDebugUtilsMessageSeverityFlagBitsEXT messageSeverity,
        VkDebugUtilsMessageTypeFlagsEXT messageType,
        const VkDebugUtilsMessengerCallbackDataEXT* pCallbackData, void* pUserData)
{
    fprintf(stderr, "Validation Layer: %s\n", pCallbackData->pMessage);
    return VK_FALSE;
}

/* extensions */
static
VkResult CreateDebugUtilsMessengerEXT(
        VkInstance instance,
        const VkDebugUtilsMessengerCreateInfoEXT* pCreateInfo,
        const VkAllocationCallbacks* pAllocator,
        VkDebugUtilsMessengerEXT* pDebugMessenger)
{
    PFN_vkCreateDebugUtilsMessengerEXT func = (PFN_vkCreateDebugUtilsMessengerEXT)vkGetInstanceProcAddr(instance, "vkCreateDebugUtilsMessengerEXT");
    if (func != NULL) {
        return func(instance, pCreateInfo, pAllocator, pDebugMessenger);
    } else {
        return VK_ERROR_EXTENSION_NOT_PRESENT;
    }
}

/* helpers */
static
bool check_validation_layers(uint32_t reqLayerCount, const char **reqLayersStr)
{
    VkResult res;
    bool layerFound;
    uint32_t availableLayerCount = 0;
    uint32_t i, j;

    res = vkEnumerateInstanceLayerProperties(&availableLayerCount, NULL);
    assert(res == VK_SUCCESS);
    VkLayerProperties *availableLayers = malloc(availableLayerCount * sizeof(VkLayerProperties));
    res = vkEnumerateInstanceLayerProperties(&availableLayerCount, availableLayers);
    assert(res == VK_SUCCESS);

    for (i = 0; i < reqLayerCount; i++) {
        layerFound = false;
        for (j = 0; j < availableLayerCount; j++) {
            if (!strcmp(reqLayersStr[i], availableLayers[j].layerName)) {
                layerFound = true;
                break;
            }
        }
        if (!layerFound) {
            return false;
        }
    }
    return true;
}

static
void setup_debug_messages(VulkanState* s)
{
    VkDebugUtilsMessengerCreateInfoEXT createInfo = {};
    VkResult res;

    createInfo.sType = VK_STRUCTURE_TYPE_DEBUG_UTILS_MESSENGER_CREATE_INFO_EXT;
    createInfo.messageSeverity =
        VK_DEBUG_UTILS_MESSAGE_SEVERITY_VERBOSE_BIT_EXT |
        VK_DEBUG_UTILS_MESSAGE_SEVERITY_WARNING_BIT_EXT |
        VK_DEBUG_UTILS_MESSAGE_SEVERITY_ERROR_BIT_EXT;
    createInfo.messageType =
        VK_DEBUG_UTILS_MESSAGE_TYPE_GENERAL_BIT_EXT |
        VK_DEBUG_UTILS_MESSAGE_TYPE_VALIDATION_BIT_EXT |
        VK_DEBUG_UTILS_MESSAGE_TYPE_PERFORMANCE_BIT_EXT;
    createInfo.pfnUserCallback = debugCallback;

    res = CreateDebugUtilsMessengerEXT(s->instance, &createInfo, NULL, &s->debug_messenger);
    if (res != VK_SUCCESS) {
        error_report("setup_debug_messages: Failed to setup debug messenger\n");
        return;
    }
}

static
void vk_find_graphics_queue(VulkanState* s)
{
    uint32_t graphicsQueueNodeIndex = UINT32_MAX;
    uint32_t presentQueueNodeIndex = UINT32_MAX;
    uint32_t i;

    for (i = 0; i < s->queue_count; i++) {
        if ((s->queue_props[i].queueFlags & VK_QUEUE_GRAPHICS_BIT) != 0) {
            VkBool32 supportsPresent;
            vkGetPhysicalDeviceSurfaceSupportKHR(s->gpu, i, s->surface, &supportsPresent);
            if (graphicsQueueNodeIndex == UINT32_MAX) {
                graphicsQueueNodeIndex = i;
            }
            if (supportsPresent == VK_TRUE) {
                graphicsQueueNodeIndex = i;
                presentQueueNodeIndex = i;
                break;
            }
        }
    }
    if (presentQueueNodeIndex == UINT32_MAX) {
        for (i = 0; i < s->queue_count; ++i) {
            VkBool32 supportsPresent;
            vkGetPhysicalDeviceSurfaceSupportKHR(s->gpu, i, s->surface, &supportsPresent);
            if (supportsPresent == VK_TRUE) {
                presentQueueNodeIndex = i;
                break;
            }
        }
    }
    if (graphicsQueueNodeIndex == UINT32_MAX || presentQueueNodeIndex == UINT32_MAX) {
        error_report("vk_init_device: Could not find a graphics and a present queue\n");
        return;
    }
    if (graphicsQueueNodeIndex != presentQueueNodeIndex) {
        error_report("vk_init_device: Could not find a common graphics and a present queue\n");
        return;
    }
    s->graphics_queue_node_index = graphicsQueueNodeIndex;
}

/* interface */
void vk_init_instance(VulkanState* s, uint32_t extCount, const char **extNames)
{
    VkApplicationInfo applicationInfo = {};
    VkInstanceCreateInfo instanceInfo = {};
    uint32_t enabledLayerCount;
    uint32_t enabledExtensionCount;
    VkResult res;

    // Set Vulkan instance layers and extensions
    const char* instanceLayerNames[] = {
        "VK_LAYER_LUNARG_standard_validation",
    };

    applicationInfo.sType = VK_STRUCTURE_TYPE_APPLICATION_INFO;
    applicationInfo.pNext = NULL;
    applicationInfo.pApplicationName = "QEMU";
    applicationInfo.applicationVersion = 1;
    applicationInfo.pEngineName = "qemu-vk";
    applicationInfo.engineVersion = 1;
    applicationInfo.apiVersion = VK_API_VERSION_1_0;

    // Determine the actual number of layers/extensions
    if (VK_DEBUG) {
        enabledLayerCount = countof(instanceLayerNames);
        enabledExtensionCount = extCount;
    } else {
        enabledLayerCount = 0;
        enabledExtensionCount = extCount - 1; // HACK: Last extension is debug-related
    }
    assert(check_validation_layers(enabledLayerCount, instanceLayerNames));

    instanceInfo.sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO;
    instanceInfo.pNext = NULL;
    instanceInfo.flags = 0;
    instanceInfo.pApplicationInfo = &applicationInfo;
    instanceInfo.enabledLayerCount = enabledLayerCount;
    instanceInfo.ppEnabledLayerNames = instanceLayerNames;
    instanceInfo.enabledExtensionCount = enabledExtensionCount; 
    instanceInfo.ppEnabledExtensionNames = extNames;
    
    res = vkCreateInstance(&instanceInfo, NULL, &s->instance);
    if (res != VK_SUCCESS) {
        error_report("vkCreateInstance failed with code %d", res);
        return;
    }

    // Setup debugging
    if (VK_DEBUG) {
        setup_debug_messages(s);
    }
}

void vk_init_device(VulkanState* s)
{
    VkResult res;

    uint32_t gpu_count;
    res = vkEnumeratePhysicalDevices(s->instance, &gpu_count, NULL);
    if (res != VK_SUCCESS) {
        error_report("vkEnumeratePhysicalDevices failed with code %d", res);
        return;
    }
    assert(gpu_count >= 1);
    VkPhysicalDevice *physical_devices = malloc(sizeof(VkPhysicalDevice) * gpu_count);
    res = vkEnumeratePhysicalDevices(s->instance, &gpu_count, physical_devices);
    s->gpu = physical_devices[0];
    free(physical_devices);

    vkGetPhysicalDeviceFeatures(s->gpu, &s->gpu_features);
    vkGetPhysicalDeviceProperties(s->gpu, &s->gpu_props);
    vkGetPhysicalDeviceMemoryProperties(s->gpu, &s->mem_props);

    /* queue */
    vkGetPhysicalDeviceQueueFamilyProperties(s->gpu, &s->queue_count, NULL);
    s->queue_props = (VkQueueFamilyProperties *)malloc(s->queue_count * sizeof(VkQueueFamilyProperties));
    vkGetPhysicalDeviceQueueFamilyProperties(s->gpu, &s->queue_count, s->queue_props);
    assert(s->queue_count >= 1);
    vk_find_graphics_queue(s);

    float queue_priorities[1] = {0.0};
    VkDeviceQueueCreateInfo deviceQueue = {};
    deviceQueue.sType = VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO;
    deviceQueue.pNext = NULL;
    deviceQueue.queueFamilyIndex = s->graphics_queue_node_index;
    deviceQueue.queueCount = 1;
    deviceQueue.pQueuePriorities = queue_priorities;

    /* device */
    static const char *deviceExtensionNames[] = {
        VK_KHR_SWAPCHAIN_EXTENSION_NAME,
    };

    VkDeviceCreateInfo deviceInfo = {};
    deviceInfo.sType = VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO;
    deviceInfo.pNext = NULL;
    deviceInfo.queueCreateInfoCount = 1;
    deviceInfo.pQueueCreateInfos = &deviceQueue;
    deviceInfo.enabledExtensionCount = countof(deviceExtensionNames);
    deviceInfo.ppEnabledExtensionNames = deviceExtensionNames;
    deviceInfo.pEnabledFeatures = NULL;
    deviceInfo.ppEnabledLayerNames = NULL;
    res = vkCreateDevice(s->gpu, &deviceInfo, NULL, &s->device);
    if (res != VK_SUCCESS) {
        error_report("vkCreateInstance failed with code %d", res);
        return;
    }
    vkGetDeviceQueue(s->device, s->graphics_queue_node_index, 0, &s->queue);
    qemu_mutex_init(&s->queue_mutex);

    // Create Descriptor Pool
    {
        VkDescriptorPoolSize pool_sizes[] =
        {
            { VK_DESCRIPTOR_TYPE_SAMPLER, 1000 },
            { VK_DESCRIPTOR_TYPE_COMBINED_IMAGE_SAMPLER, 1000 },
            { VK_DESCRIPTOR_TYPE_SAMPLED_IMAGE, 1000 },
            { VK_DESCRIPTOR_TYPE_STORAGE_IMAGE, 1000 },
            { VK_DESCRIPTOR_TYPE_UNIFORM_TEXEL_BUFFER, 1000 },
            { VK_DESCRIPTOR_TYPE_STORAGE_TEXEL_BUFFER, 1000 },
            { VK_DESCRIPTOR_TYPE_UNIFORM_BUFFER, 1000 },
            { VK_DESCRIPTOR_TYPE_STORAGE_BUFFER, 1000 },
            { VK_DESCRIPTOR_TYPE_UNIFORM_BUFFER_DYNAMIC, 1000 },
            { VK_DESCRIPTOR_TYPE_STORAGE_BUFFER_DYNAMIC, 1000 },
            { VK_DESCRIPTOR_TYPE_INPUT_ATTACHMENT, 1000 }
        };
        VkDescriptorPoolCreateInfo pool_info = {};
        pool_info.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_POOL_CREATE_INFO;
        pool_info.flags = VK_DESCRIPTOR_POOL_CREATE_FREE_DESCRIPTOR_SET_BIT;
        pool_info.maxSets = 1000 * ARRAYSIZE(pool_sizes);
        pool_info.poolSizeCount = (uint32_t)ARRAYSIZE(pool_sizes);
        pool_info.pPoolSizes = pool_sizes;
        res = vkCreateDescriptorPool(s->device, &pool_info, NULL, &s->descriptor_pool);
        if (res != VK_SUCCESS) {
            error_report("vkCreateDescriptorPool failed with code %d", res);
            return;
        }
    }
}
