/*
 * QEMU-Orbital user interface
 *
 * Copyright (c) 2017-2018 Alexandro Sanchez Bach
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

#include "qemu/osdep.h"
#include "qemu-common.h"
#include "ui/console.h"
#include "ui/vk-helpers.h"
#include "qemu/thread.h"
#include "qemu/error-report.h"
#include "sysemu/sysemu.h"

#include <SDL2/SDL.h>
#include <SDL2/SDL_vulkan.h>
#include <vulkan/vulkan.h>

#define CIMGUI_DEFINE_ENUMS_AND_STRUCTS
#define IMGUI_IMPL_API
#include "imgui/cimgui_auto.h"
#include "imgui/imgui_impl_sdl.h"
#include "imgui/imgui_impl_vulkan.h"

#include "orbital.h"
#include "orbital-logs.h"
#include "orbital-stats.h"
#include "orbital-debug-gpu.h"
#include "orbital-procs.h"
#include "orbital-procs-list.h"
#include "orbital-style.h"

#include <time.h>

// Configuration
#define ORBITAL_WIDTH 1280
#define ORBITAL_HEIGHT 720

typedef struct OrbitalUI {
    /* window */
    bool active;
    enum WindowState {minimized, maximized} window_state;
    /* vulkan */
    VulkanState vk_state;
    /* sdl */
    QemuThread sdl_thread;
    SDL_Window* sdl_window;
    /* imgui */
    ImGui_ImplVulkanH_WindowData imgui_WindowData;
    struct orbital_stats_t *stats;
    struct orbital_logs_t *logs_uart;
    struct orbital_debug_gpu_t *gpu_debugger;
    struct orbital_procs_t *procs;
    struct orbital_procs_list_t *procs_list;
    bool show_stats;
    bool show_uart;
    bool show_gpu_debugger;
    bool show_executing_processes;
    bool show_process_list;
    bool show_trace_cp;
    bool show_trace_icc;
    bool show_trace_samu;
    bool show_mem_gpa;
    bool show_mem_gva;
    bool show_mem_gart;
    bool show_mem_iommu;

    struct timespec last_procs_update;
    float procs_updates_per_second; // Maximum rate, not accurate

    /* emulator */
    bool has_emu_image;
    VkImage emu_image;
} OrbitalUI;

// Global state
OrbitalUI ui;

bool orbital_display_active(void)
{
    return ui.active;
}

bool orbital_executing_processes_active(void)
{
    return ui.show_executing_processes;
}

bool orbital_process_list_active(void)
{
    return ui.show_process_list;
}

VulkanState* orbital_get_vkstate(void)
{
    return &ui.vk_state;
}

void orbital_log_uart(int index, char ch)
{
    (void)index; // Unused
    orbital_logs_logchr(ui.logs_uart, ch);
}

void orbital_log_event(int device, int component, int event)
{
    orbital_stats_log(ui.stats, device, component, event);
}

void orbital_debug_gpu_mmio(uint32_t *mmio)
{
    orbital_debug_gpu_set_mmio(ui.gpu_debugger, mmio);
}

void orbital_update_cpu_procs(int cpuid, struct orbital_procs_cpu_data *data)
{
    orbital_procs_update(ui.procs, cpuid, data);
}

void orbital_update_cpu_procs_list_clear(void)
{
    orbital_procs_list_clear(ui.procs_list);
}

void orbital_update_cpu_procs_list_add_proc(struct orbital_proc_data *p)
{
    orbital_procs_list_add_proc(ui.procs_list, p);
}

void orbital_update_cpu_procs_list_add_proc_thread(int owner_pid, struct thread *td)
{
    orbital_procs_list_add_proc_thread(ui.procs_list, owner_pid, td);
}

void orbital_update_main(void *vkImage)
{
    if (vkImage) {
        ui.emu_image = vkImage;
        ui.has_emu_image = true;
    } else {
        ui.emu_image = NULL;
        ui.has_emu_image = false;
    }
}

void orbital_update_cpu_procs_list_done()
{
    orbital_procs_list_done(ui.procs_list);
}

static void timespec_diff(struct timespec *start, struct timespec *stop,
                   struct timespec *result)
{
    if ((stop->tv_nsec - start->tv_nsec) < 0) {
        result->tv_sec = stop->tv_sec - start->tv_sec - 1;
        result->tv_nsec = stop->tv_nsec - start->tv_nsec + 1000000000;
    } else {
        result->tv_sec = stop->tv_sec - start->tv_sec;
        result->tv_nsec = stop->tv_nsec - start->tv_nsec;
    }

    return;
}

bool orbital_should_update_procs(void) {
    // TODO: Heavy performance impact, enable only when needed!
    //       In the future, enable conditionally.
    return false;

    struct timespec time_now;
    clock_gettime(CLOCK_MONOTONIC, &time_now);

    struct timespec time_diff;
    timespec_diff(&ui.last_procs_update, &time_now, &time_diff);

    uint64_t diff_abs = time_diff.tv_nsec + time_diff.tv_sec * 1000000;

    bool should_update = (float)diff_abs >= (1.0 / ui.procs_updates_per_second * 1000.0) * 1000000.0;

    if (should_update) {
        ui.last_procs_update.tv_sec = time_now.tv_sec;
        ui.last_procs_update.tv_nsec = time_now.tv_nsec;
    }
    return should_update;
}

static void check_vk_result(VkResult err)
{
    if (err == 0) return;
    error_report("VkResult %d\n", err);
    assert(0);
}

static void SetupVulkanWindowData(ImGui_ImplVulkanH_WindowData* wd, VulkanState* state, int width, int height)
{
    wd->Surface = state->surface;

    // Check for WSI support
    VkBool32 res;
    vkGetPhysicalDeviceSurfaceSupportKHR(state->gpu, state->graphics_queue_node_index, wd->Surface, &res);
    if (res != VK_TRUE)
    {
        fprintf(stderr, "Error no WSI support on physical device 0\n");
        exit(-1);
    }

    // Select Surface Format
    const VkFormat requestSurfaceImageFormat[] = {
        VK_FORMAT_B8G8R8A8_UNORM,
        VK_FORMAT_R8G8B8A8_UNORM,
        VK_FORMAT_B8G8R8_UNORM,
        VK_FORMAT_R8G8B8_UNORM
    };
    const VkColorSpaceKHR requestSurfaceColorSpace = VK_COLORSPACE_SRGB_NONLINEAR_KHR;
    wd->SurfaceFormat = ImGui_ImplVulkanH_SelectSurfaceFormat(
        state->gpu, wd->Surface, requestSurfaceImageFormat, (size_t)ARRAYSIZE(requestSurfaceImageFormat), requestSurfaceColorSpace);

    // Select Present Mode
    VkPresentModeKHR present_modes[] = {
#ifdef IMGUI_UNLIMITED_FRAME_RATE
        VK_PRESENT_MODE_MAILBOX_KHR,
        VK_PRESENT_MODE_IMMEDIATE_KHR,
        VK_PRESENT_MODE_FIFO_KHR
#else
        VK_PRESENT_MODE_FIFO_KHR
#endif
    };
    wd->PresentMode = ImGui_ImplVulkanH_SelectPresentMode(state->gpu, wd->Surface, &present_modes[0], ARRAYSIZE(present_modes));
    //printf("[vulkan] Selected PresentMode = %d\n", wd->PresentMode);

    // Create SwapChain, RenderPass, Framebuffer, etc.
    ImGui_ImplVulkanH_CreateWindowDataCommandBuffers(state->gpu, state->device, state->graphics_queue_node_index, wd, NULL);
    ImGui_ImplVulkanH_CreateWindowDataSwapChainAndFramebuffer(state->gpu, state->device, wd, NULL, width, height);
}


static void FrameRender(ImGui_ImplVulkanH_WindowData* wd, VulkanState* vks)
{
    VkResult err;

    VkSemaphore image_acquired_semaphore = wd->Frames[wd->FrameIndex].ImageAcquiredSemaphore;
    err = vkAcquireNextImageKHR(vks->device, wd->Swapchain, UINT64_MAX, image_acquired_semaphore, VK_NULL_HANDLE, &wd->FrameIndex);
    check_vk_result(err);

    ImGui_ImplVulkanH_FrameData* fd = &wd->Frames[wd->FrameIndex];
    {
        err = vkWaitForFences(vks->device, 1, &fd->Fence, VK_TRUE, UINT64_MAX);    // wait indefinitely instead of periodically checking
        check_vk_result(err);

        err = vkResetFences(vks->device, 1, &fd->Fence);
        check_vk_result(err);
    }
    {
        err = vkResetCommandPool(vks->device, fd->CommandPool, 0);
        check_vk_result(err);
        VkCommandBufferBeginInfo info = {};
        info.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
        info.flags |= VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
        err = vkBeginCommandBuffer(fd->CommandBuffer, &info);
        check_vk_result(err);
    }

    // Interlocked background drawing
    {
        VkImageMemoryBarrier barrier = {
            .sType = VK_STRUCTURE_TYPE_IMAGE_MEMORY_BARRIER,
            .srcAccessMask = VK_ACCESS_MEMORY_READ_BIT,
            .dstAccessMask = VK_ACCESS_TRANSFER_WRITE_BIT,
            .oldLayout = VK_IMAGE_LAYOUT_UNDEFINED,
            .newLayout = VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL,
            .srcQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED,
            .dstQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED,
            .subresourceRange.aspectMask = VK_IMAGE_ASPECT_COLOR_BIT,
            .subresourceRange.baseMipLevel = 0,
            .subresourceRange.levelCount = 1,
            .subresourceRange.baseArrayLayer = 0,
            .subresourceRange.layerCount = 1,
            .image = wd->BackBuffer[wd->FrameIndex],
        };
        vkCmdPipelineBarrier(fd->CommandBuffer,
            VK_PIPELINE_STAGE_TRANSFER_BIT, VK_PIPELINE_STAGE_TRANSFER_BIT, 0,
            0, NULL, 0, NULL, 1, &barrier);
    }
    if (ui.has_emu_image) {
        {
            VkImageMemoryBarrier barrier = {
                .sType = VK_STRUCTURE_TYPE_IMAGE_MEMORY_BARRIER,
                .srcAccessMask = VK_ACCESS_MEMORY_WRITE_BIT,
                .dstAccessMask = VK_ACCESS_TRANSFER_READ_BIT,
                .oldLayout = VK_IMAGE_LAYOUT_COLOR_ATTACHMENT_OPTIMAL,
                .newLayout = VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL,
                .srcQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED,
                .dstQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED,
                .subresourceRange.aspectMask = VK_IMAGE_ASPECT_COLOR_BIT,
                .subresourceRange.baseMipLevel = 0,
                .subresourceRange.levelCount = 1,
                .subresourceRange.baseArrayLayer = 0,
                .subresourceRange.layerCount = 1,
                .image = ui.emu_image,
            };
            vkCmdPipelineBarrier(fd->CommandBuffer,
                VK_PIPELINE_STAGE_TRANSFER_BIT, VK_PIPELINE_STAGE_TRANSFER_BIT, 0,
                0, NULL, 0, NULL, 1, &barrier);
        }
        const VkImageBlit blit = {
            .srcSubresource.aspectMask = VK_IMAGE_ASPECT_COLOR_BIT,
            .srcSubresource.layerCount = 1,
            .dstSubresource.aspectMask = VK_IMAGE_ASPECT_COLOR_BIT,
            .dstSubresource.layerCount = 1,
            .srcOffsets = {{0, 0, 0}, {1920, 1080, 1}},
            .dstOffsets = {{0, 0, 0}, {wd->Width, wd->Height, 1}}
        };
        vkCmdBlitImage(fd->CommandBuffer, ui.emu_image, VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL,
            wd->BackBuffer[wd->FrameIndex], VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL,
            1, &blit, VK_FILTER_LINEAR);
        {
            VkImageMemoryBarrier barrier = {
                .sType = VK_STRUCTURE_TYPE_IMAGE_MEMORY_BARRIER,
                .srcAccessMask = VK_ACCESS_TRANSFER_READ_BIT,
                .dstAccessMask = VK_ACCESS_MEMORY_WRITE_BIT,
                .oldLayout = VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL,
                .newLayout = VK_IMAGE_LAYOUT_COLOR_ATTACHMENT_OPTIMAL,
                .srcQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED,
                .dstQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED,
                .subresourceRange.aspectMask = VK_IMAGE_ASPECT_COLOR_BIT,
                .subresourceRange.baseMipLevel = 0,
                .subresourceRange.levelCount = 1,
                .subresourceRange.baseArrayLayer = 0,
                .subresourceRange.layerCount = 1,
                .image = ui.emu_image,
            };
            vkCmdPipelineBarrier(fd->CommandBuffer,
                VK_PIPELINE_STAGE_TRANSFER_BIT, VK_PIPELINE_STAGE_TRANSFER_BIT, 0,
                0, NULL, 0, NULL, 1, &barrier);
        }
    } else {
        VkImageSubresourceRange subresourceRange = {
            .aspectMask = VK_IMAGE_ASPECT_COLOR_BIT,
            .baseMipLevel = 0,
            .levelCount = 1,
            .baseArrayLayer = 0,
            .layerCount = 1,
        };
        vkCmdClearColorImage(fd->CommandBuffer, wd->BackBuffer[wd->FrameIndex],
            VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL, &wd->ClearValue.color, 1, &subresourceRange);
    }
    {
        VkImageMemoryBarrier barrier = {
            .sType = VK_STRUCTURE_TYPE_IMAGE_MEMORY_BARRIER,
            .srcAccessMask = VK_ACCESS_TRANSFER_WRITE_BIT,
            .dstAccessMask = VK_ACCESS_MEMORY_READ_BIT,
            .oldLayout = VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL,
            .newLayout = VK_IMAGE_LAYOUT_PRESENT_SRC_KHR,
            .srcQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED,
            .dstQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED,
            .subresourceRange.aspectMask = VK_IMAGE_ASPECT_COLOR_BIT,
            .subresourceRange.baseMipLevel = 0,
            .subresourceRange.levelCount = 1,
            .subresourceRange.baseArrayLayer = 0,
            .subresourceRange.layerCount = 1,
            .image = wd->BackBuffer[wd->FrameIndex],
        };
        vkCmdPipelineBarrier(fd->CommandBuffer,
            VK_PIPELINE_STAGE_TRANSFER_BIT, VK_PIPELINE_STAGE_TRANSFER_BIT, 0,
            0, NULL, 0, NULL, 1, &barrier);
    }

    {
        VkRenderPassBeginInfo info = {};
        info.sType = VK_STRUCTURE_TYPE_RENDER_PASS_BEGIN_INFO;
        info.renderPass = wd->RenderPass;
        info.framebuffer = wd->Framebuffer[wd->FrameIndex];
        info.renderArea.extent.width = wd->Width;
        info.renderArea.extent.height = wd->Height;
        vkCmdBeginRenderPass(fd->CommandBuffer, &info, VK_SUBPASS_CONTENTS_INLINE);
    }

    // Record Imgui Draw Data and draw funcs into command buffer
    ImGui_ImplVulkan_RenderDrawData(igGetDrawData(), fd->CommandBuffer);

    // Submit command buffer
    vkCmdEndRenderPass(fd->CommandBuffer);
    {
        VkPipelineStageFlags wait_stage = VK_PIPELINE_STAGE_COLOR_ATTACHMENT_OUTPUT_BIT;
        VkSubmitInfo info = {};
        info.sType = VK_STRUCTURE_TYPE_SUBMIT_INFO;
        info.waitSemaphoreCount = 1;
        info.pWaitSemaphores = &image_acquired_semaphore;
        info.pWaitDstStageMask = &wait_stage;
        info.commandBufferCount = 1;
        info.pCommandBuffers = &fd->CommandBuffer;
        info.signalSemaphoreCount = 1;
        info.pSignalSemaphores = &fd->RenderCompleteSemaphore;

        err = vkEndCommandBuffer(fd->CommandBuffer);
        check_vk_result(err);
        qemu_mutex_lock(&vks->queue_mutex);
        err = vkQueueSubmit(vks->queue, 1, &info, fd->Fence);
        qemu_mutex_unlock(&vks->queue_mutex);
        check_vk_result(err);
    }
}

static void FramePresent(ImGui_ImplVulkanH_WindowData* wd, VulkanState* vks)
{
    ImGui_ImplVulkanH_FrameData* fd = &wd->Frames[wd->FrameIndex];
    VkPresentInfoKHR info = {};
    info.sType = VK_STRUCTURE_TYPE_PRESENT_INFO_KHR;
    info.waitSemaphoreCount = 1;
    info.pWaitSemaphores = &fd->RenderCompleteSemaphore;
    info.swapchainCount = 1;
    info.pSwapchains = &wd->Swapchain;
    info.pImageIndices = &wd->FrameIndex;
    VkResult err = vkQueuePresentKHR(vks->queue, &info);
    check_vk_result(err);
}

static void CleanupVulkan(ImGui_ImplVulkanH_WindowData* wd, VulkanState* vks)
{
    ImGui_ImplVulkanH_DestroyWindowData(vks->instance, vks->device, wd, NULL);
    vkDestroyDescriptorPool(vks->device, vks->descriptor_pool, NULL);

    vkDestroyDevice(vks->device, NULL);
    vkDestroyInstance(vks->instance, NULL);
}

static void orbital_display_draw(OrbitalUI *ui)
{
    igBeginMainMenuBar();
    if (igBeginMenu("File", true)) {
        if (igMenuItemBool("Open kernel...", NULL, false, false)) { /* TODO */ }
        igSeparator();
        if (igMenuItemBool("Exit", NULL, false, true)) {
            SDL_Event quit;
            quit.type = SDL_QUIT;
            SDL_PushEvent(&quit);
        }
        igEndMenu();
    }
    if (igBeginMenu("Machine", true)) {
        bool running = runstate_is_running();
        if (igMenuItemBool("Resume", NULL, false, !running)) {
            vm_start();
        }
        if (igMenuItemBool("Pause", NULL, false, running)) {
            qemu_system_suspend_request();
            vm_prepare_start();
        }
        if (igMenuItemBool("Reset", NULL, false, false)) { /* TODO */ }
        igSeparator();
        if (igMenuItemBool("Load state", NULL, false, false)) { /* TODO */ }
        if (igMenuItemBool("Save state", NULL, false, false)) { /* TODO */ }
        igSeparator();
        if (igMenuItemBool("Configuration...", NULL, false, false)) { /* TODO */ }
        igEndMenu();
    }
    if (igBeginMenu("Tools", true)) {
        igMenuItemBoolPtr("Statistics", "Alt+1", &ui->show_stats, true);
        igMenuItemBoolPtr("UART Output", "Alt+2", &ui->show_uart, true);
        igMenuItemBoolPtr("GPU Debugger", "Alt+3", &ui->show_gpu_debugger, true);
        igMenuItemBoolPtr("Executing Processes", "Alt+4", &ui->show_executing_processes, true);
        igMenuItemBoolPtr("Process List", "Alt+5", &ui->show_process_list, true);
        igSeparator();
        igMenuItemBoolPtr("CP Commands", "Alt+6", &ui->show_trace_cp, false);
        igMenuItemBoolPtr("ICC Commands", "Alt+7", &ui->show_trace_icc, false);
        igMenuItemBoolPtr("SAMU Commands", "Alt+8", &ui->show_trace_samu, false);
        igSeparator();
        igMenuItemBoolPtr("Memory Editor (GPA)", "Ctrl+1", &ui->show_mem_gpa, false);
        igMenuItemBoolPtr("Memory Editor (GVA)", "Ctrl+2", &ui->show_mem_gva, false);
        igMenuItemBoolPtr("Memory Editor (GART)", "Ctrl+3", &ui->show_mem_gart, false);
        igMenuItemBoolPtr("Memory Editor (IOMMU)", "Ctrl+4", &ui->show_mem_iommu, false);
        igEndMenu();
    }
    if (igBeginMenu("Help", true)) {
        if (igMenuItemBool("About...", NULL, false, false)) {
            /* TODO */
        }
        igEndMenu();
    }
    igEndMainMenuBar();

    if (ui->show_stats) {
        orbital_stats_draw(ui->stats, "Statistics", &ui->show_stats);
    }
    if (ui->show_uart) {
        orbital_logs_draw(ui->logs_uart, "UART Output", &ui->show_uart);
    }
    if (ui->show_gpu_debugger) {
        orbital_debug_gpu_draw(ui->gpu_debugger, "GPU Debugger", &ui->show_gpu_debugger);
    }
    if (ui->show_executing_processes) {
        orbital_procs_draw(ui->procs, "Executing Processes", &ui->show_executing_processes);
    }
    if (ui->show_process_list) {
        orbital_procs_list_draw(ui->procs_list, "Process List", &ui->show_process_list);
    }
}

static void* orbital_display_main(void* arg)
{
    VulkanState* vks = &ui.vk_state;
    int err, flags;
    bool quit;
    uint32_t count;

    err = SDL_InitSubSystem(SDL_INIT_VIDEO);
    if (err) {
        printf("SDL_InitSubSystem failed: %s\n", SDL_GetError());
        return NULL;
    }

    err = SDL_Vulkan_LoadLibrary("libvulkan-1.dll");
    if (err) {
        printf("SDL_Vulkan_LoadLibrary failed: %s\n", SDL_GetError());
        return NULL;
    }

    flags = 0;
    flags |= SDL_WINDOW_MAXIMIZED;
    flags |= SDL_WINDOW_RESIZABLE;
    flags |= SDL_WINDOW_VULKAN;
    ui.sdl_window = SDL_CreateWindow("Orbital",
        SDL_WINDOWPOS_UNDEFINED, SDL_WINDOWPOS_UNDEFINED,
        ORBITAL_WIDTH, ORBITAL_HEIGHT, flags);

    count = 0;
    if (!SDL_Vulkan_GetInstanceExtensions(ui.sdl_window, &count, NULL)) {
        error_report("SDL_Vulkan_GetInstanceExtensions returned false");
        return NULL;
    }
    if (count == 0) {
        error_report("SDL_Vulkan_GetInstanceExtensions failed");
    }

    const char **extensionNames = (const char **)malloc((count + 3) * sizeof(char*));
    extensionNames[count + 0] = VK_KHR_SURFACE_EXTENSION_NAME;
    extensionNames[count + 1] = VK_EXT_DEBUG_UTILS_EXTENSION_NAME;
    extensionNames[count + 2] = VK_EXT_DEBUG_REPORT_EXTENSION_NAME;
    if (!SDL_Vulkan_GetInstanceExtensions(ui.sdl_window, &count, &extensionNames[0])) {
        error_report("SDL_Vulkan_GetInstanceExtensions returned false with extensions");
        return NULL;
    }

    vk_init_instance(vks, count+3, extensionNames);
    if (!SDL_Vulkan_CreateSurface(ui.sdl_window, vks->instance, &vks->surface)) {
        printf("SDL_Vulkan_CreateSurface failed: %s\n", SDL_GetError());
        return NULL;
    }
    vk_init_device(vks);

    // Create framebuffers
    int w, h;
    SDL_GetWindowSize(ui.sdl_window, &w, &h);
    ImGui_ImplVulkanH_WindowData* wd = &ui.imgui_WindowData;
    *wd = ImGui_ImplVulkanH_WindowData_Create();
    wd->ClearEnable = false;
    SetupVulkanWindowData(wd, vks, w, h);

    // Setup Dear ImGui binding
    igCreateContext(NULL);
    ImGuiIO* io = igGetIO(); (void)io;
    //io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;  // Enable Keyboard Controls

    // Setup SDL binding
    ImGui_ImplSDL2_InitForVulkan(ui.sdl_window);

    // Setup Vulkan binding
    ImGui_ImplVulkan_InitInfo init_info = {};
    init_info.Instance = vks->instance;
    init_info.PhysicalDevice = vks->gpu;
    init_info.Device = vks->device;
    init_info.QueueFamily = vks->graphics_queue_node_index;
    init_info.Queue = vks->queue;
    init_info.PipelineCache = NULL;
    init_info.DescriptorPool = vks->descriptor_pool; // todo: check this
    init_info.Allocator = NULL;
    init_info.CheckVkResultFn = check_vk_result;
    ImGui_ImplVulkan_Init(&init_info, wd->RenderPass);

    // Setup style
    orbital_style_initialize();
    igStyleColorsDark(NULL);

     // Upload Fonts
    {
        // Use any command queue
        VkCommandPool command_pool = wd->Frames[wd->FrameIndex].CommandPool;
        VkCommandBuffer command_buffer = wd->Frames[wd->FrameIndex].CommandBuffer;

        err = vkResetCommandPool(vks->device, command_pool, 0);
        check_vk_result(err);
        VkCommandBufferBeginInfo begin_info = {};
        begin_info.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
        begin_info.flags |= VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
        err = vkBeginCommandBuffer(command_buffer, &begin_info);
        check_vk_result(err);

        ImGui_ImplVulkan_CreateFontsTexture(command_buffer);

        VkSubmitInfo end_info = {};
        end_info.sType = VK_STRUCTURE_TYPE_SUBMIT_INFO;
        end_info.commandBufferCount = 1;
        end_info.pCommandBuffers = &command_buffer;
        err = vkEndCommandBuffer(command_buffer);
        check_vk_result(err);
        err = vkQueueSubmit(vks->queue, 1, &end_info, VK_NULL_HANDLE);
        check_vk_result(err);

        err = vkDeviceWaitIdle(vks->device);
        check_vk_result(err);
        ImGui_ImplVulkan_InvalidateFontUploadObjects();
    }

    // Initialization
    float clear_color[4] = {0.45f, 0.55f, 0.60f, 1.00f};
    memcpy(&wd->ClearValue.color.float32[0], &clear_color, 4 * sizeof(float));
    ui.gpu_debugger = orbital_debug_gpu_create();
    ui.logs_uart = orbital_logs_create();
    ui.stats = orbital_stats_create();
    ui.procs = orbital_procs_create();
    ui.procs_list = orbital_procs_list_create();
    ui.show_stats = true;
    ui.show_uart = true;
    ui.show_gpu_debugger = true;
    ui.show_executing_processes = true;
    ui.show_process_list = true;
    ui.show_trace_cp = false;
    ui.show_trace_icc = false;
    ui.show_trace_samu = false;
    ui.show_mem_gpa = false;
    ui.show_mem_gva = false;
    ui.show_mem_gart = false;
    ui.show_mem_iommu = false;
    assert(ui.gpu_debugger);
    assert(ui.logs_uart);
    assert(ui.stats);
    assert(ui.procs);
    assert(ui.procs_list);
    ui.has_emu_image = false;
    ui.active = true;
    ui.procs_updates_per_second = 2.0;

    quit = false;
    while (!quit) {
        SDL_Event event;
        // Events
        while (SDL_PollEvent(&event)) {
            ImGui_ImplSDL2_ProcessEvent(&event);
            if (event.type == SDL_QUIT) {
                quit = true;
            }
            if (event.type == SDL_WINDOWEVENT ||
                event.window.windowID == SDL_GetWindowID(ui.sdl_window)) {
                switch (event.window.event) {
                case SDL_WINDOWEVENT_MINIMIZED:
                    ui.window_state = minimized;
                    break;
                case SDL_WINDOWEVENT_MAXIMIZED:
                    ui.window_state = maximized;
                    break;
                case SDL_WINDOWEVENT_RESIZED:
                case SDL_WINDOWEVENT_EXPOSED:
                    ImGui_ImplVulkanH_CreateWindowDataSwapChainAndFramebuffer(
                        vks->gpu, vks->device, wd, NULL,
                        (int)event.window.data1, (int)event.window.data2);
                    break;
                case SDL_WINDOWEVENT_CLOSE:
                    quit = true;
                    break;
                }
            }
        }

        if (ui.window_state == maximized) {
            // Draw new frame
            ImGui_ImplVulkan_NewFrame();
            ImGui_ImplSDL2_NewFrame(ui.sdl_window);
            igNewFrame();

            // Render orbital windows
            orbital_display_draw(&ui);

            // Push frame to render
            igRender();
            FrameRender(wd, vks);
            FramePresent(wd, vks);
        }
    }

    err = vkDeviceWaitIdle(vks->device);
    check_vk_result(err);
    ImGui_ImplVulkan_Shutdown();
    ImGui_ImplSDL2_Shutdown();
    igDestroyContext(NULL);
    SDL_DestroyWindow(ui.sdl_window);
    CleanupVulkan(wd, vks);
    SDL_Quit();

    return NULL;
}

static void orbital_display_early_init(DisplayOptions *o)
{
    qemu_thread_create(&ui.sdl_thread, "sdl_thread",
        orbital_display_main, NULL, QEMU_THREAD_JOINABLE);

    while (!ui.active)
        usleep(1000);
}

static void orbital_display_init(DisplayState *ds, DisplayOptions *o)
{
}

static QemuDisplay qemu_display_orbital = {
    .type       = DISPLAY_TYPE_ORBITAL,
    .early_init = orbital_display_early_init,
    .init       = orbital_display_init,
};

static void register_orbital(void)
{
    qemu_display_register(&qemu_display_orbital);
}

type_init(register_orbital);
