/*
 * QEMU-Orbital user interface
 *
 * Copyright (c) 2019-2019 Nick Renieris
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


#include <SDL2/SDL.h>
#include <SDL2/SDL_vulkan.h>
#include <vulkan/vulkan.h>

#define CIMGUI_DEFINE_ENUMS_AND_STRUCTS
#define IMGUI_IMPL_API
#include "imgui/imgui.h"
#include "imgui/imgui_impl_sdl.h"
#include "imgui/imgui_impl_vulkan.h"

#include <algorithm>
#include <iostream>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <utility>
#include <vector>
//
#include "undefs.h"
#include "orbital-procs-list.h"
// TODO: Create proper layout for `thread` and remove this
#define THREAD_NAME(td) (char *)(((uint64_t)(td)) + 0x284)

struct orbital_procs_list_t
{
    std::vector<orbital_proc_data> proc_data_list;
    std::multimap<int32_t, freebsd::thread>
        threads_map;  // threads for each pid

    // The following fields are used as temporaries, to allow us to disregard new data when necessary.
    // Every modifications happens in these, and the results are commited (if certains conditions pass)
    // in orbital_procs_list_t::Done().
    std::vector<orbital_proc_data> proc_data_list_temp;
    std::multimap<int32_t, freebsd::thread> threads_map_temp;

    static float calc_width_for_chars(uint32_t chars) {
        auto ig_style = ImGui::GetStyle();

        const auto frame_padding_x = ig_style.FramePadding.x;
        const auto item_spacing_x = ig_style.ItemSpacing.x;

        std::string text(chars, '_');
        return frame_padding_x * 2 + item_spacing_x + ImGui::CalcTextSize(text.c_str()).x;
    }

    struct column_widths_procs_t {
        float name;
        float pid;
        float state;
        float flags;
        float td_count;

        float total;
        bool dirty = true;

        void Calculate() {
            if (!dirty)
                return;

            name = calc_width_for_chars(20);
            pid = calc_width_for_chars(5);
            state = calc_width_for_chars(10);
            flags = calc_width_for_chars(10);
            td_count = calc_width_for_chars(7);

            total = name + pid + state + flags + td_count;

            dirty = false;
        }
    } column_widths_procs;

    struct column_widths_threads_t {
        float name;
        float tid;

        float total;
        bool dirty = true;

        void Calculate() {
            if (!dirty)
                return;

            name = calc_width_for_chars(30);
            tid = calc_width_for_chars(6);

            total = name + tid;

            dirty = false;
        }
    } column_widths_threads;

    orbital_procs_list_t() {
    }

    ~orbital_procs_list_t() {
    }

    void AddProc(struct orbital_proc_data *p) {
        proc_data_list_temp.push_back(*p);
    }

    void AddProcThread(int32_t owner_pid, struct freebsd::thread *td) {
        threads_map_temp.emplace(owner_pid, *td);
    }

    void Clear() {
        proc_data_list_temp.clear();
        threads_map_temp.clear();
    }

    void Done() {
        if (proc_data_list_temp.size() >= proc_data_list.size()) {
            // Commit new data
            proc_data_list = std::move(proc_data_list_temp);
            threads_map = std::move(threads_map_temp);
        } else {
            // Disregard new data
            proc_data_list_temp.clear();
            threads_map_temp.clear();
        }
    }

    void Draw(const char* title, bool* p_open = NULL)
    {
        std::sort(proc_data_list.begin(), proc_data_list.end(), [](const auto &p_lhs, const auto &p_rhs) {
            return p_lhs.proc.p_pid < p_rhs.proc.p_pid;
        });

        column_widths_procs.Calculate();

        ImGui::SetNextWindowSize(ImVec2(column_widths_procs.total, 0));
        if (!ImGui::Begin(title, p_open, ImGuiWindowFlags_AlwaysAutoResize)) {
            ImGui::End();
            return;
        }

        auto p_state_to_str = [](int p_state) {
            switch (p_state) {
#define S(s)               \
    case freebsd::proc::s: \
        return #s;
            S(PRS_NEW)
            S(PRS_NORMAL)
            S(PRS_ZOMBIE)
#undef S
            default:
                return "UNKNOWN";
            }
        };

        auto flags_to_str = [](int flags) {
            std::string flag_str;

#define F(f)                      \
    if ((flags & f) == f)         \
        do                        \
        {                         \
            flag_str += #f " | "; \
        } while (false);

            F(P_ADVLOCK)
            F(P_CONTROLT)
            F(P_KTHREAD)
            F(P_FOLLOWFORK)
            F(P_PPWAIT)
            F(P_PROFIL)
            F(P_STOPPROF)
            F(P_HADTHREADS)
            F(P_SUGID)
            F(P_SYSTEM)
            F(P_SINGLE_EXIT)
            F(P_TRACED)
            F(P_WAITED)
            F(P_WEXIT)
            F(P_EXEC)
            F(P_WKILLED)
            F(P_CONTINUED)
            F(P_STOPPED_SIG)
            F(P_STOPPED_TRACE)
            F(P_STOPPED_SINGLE)
            F(P_PROTECTED)
            F(P_SIGEVENT)
            F(P_SINGLE_BOUNDARY)
            F(P_HWPMC)
            F(P_JAILED)
            F(P_INEXEC)
            F(P_STATCHILD)
            F(P_INMEM)
            F(P_SWAPPINGOUT)
            F(P_SWAPPINGIN)
            F(P_STOPPED)
#undef F

            if (!flag_str.empty())
                flag_str.erase(flag_str.size() - 3);
            return flag_str;
        };

        static const char *headers_proc[] = {
            "Process Name", "PID", "State", "Flags", "Threads"
        };
        static const float header_widths_proc[] = {
            column_widths_procs.name, column_widths_procs.pid, column_widths_procs.state, column_widths_procs.flags, column_widths_procs.td_count
        };
        static const auto header_count_proc = IM_ARRAYSIZE(headers_proc);

        static const auto COLUMN_TITLES_COL = ImColor(255, 255, 255);
        static const auto COLUMN_ROWS_NAME_COL = IM_COL32(200, 200, 200, 255);
        static const auto COLUMN_ROWS_OTHER_COL = IM_COL32(150, 150, 150, 255);

        // Draw headers
        ImGui::Columns(header_count_proc, "process_columns");
        for (auto i = 0; i < header_count_proc; ++i) {
            ImGui::SetColumnWidth(i, header_widths_proc[i]);
        }
        ImGui::Separator();
        for (auto i = 0; i < header_count_proc; ++i) {
            ImGui::TextColored(COLUMN_TITLES_COL, "%s", headers_proc[i]);
            ImGui::NextColumn();
        }
        ImGui::Separator();

        std::set<int32_t> thread_windows;   // set if PIDs
        // Draw rows
        for (const auto data : proc_data_list) {
            bool is_selected;
            char text[50];
            ImGui::PushStyleColor(ImGuiCol_Text, COLUMN_ROWS_NAME_COL);
            snprintf(text, 50, "%-20s", data.proc.p_comm);
            ImGui::Selectable(text, &is_selected, ImGuiSelectableFlags_SpanAllColumns);
            ImGui::NextColumn();
            ImGui::PushStyleColor(ImGuiCol_Text, COLUMN_ROWS_OTHER_COL);
            snprintf(text, 50, "%d", data.proc.p_pid);
            ImGui::Selectable(text, &is_selected, ImGuiSelectableFlags_SpanAllColumns);
            ImGui::NextColumn();
            snprintf(text, 50, "%s", p_state_to_str(data.proc.p_state));
            ImGui::Selectable(text, &is_selected, ImGuiSelectableFlags_SpanAllColumns);
            ImGui::NextColumn();
            ImGui::BeginGroup();
            snprintf(text, 50, "0x%08X", data.proc.p_flag);
            ImGui::Selectable(text, &is_selected, ImGuiSelectableFlags_SpanAllColumns);
            ImGui::EndGroup();
            if (ImGui::IsItemHovered()) {
                std::string flag_str = flags_to_str(data.proc.p_flag);
                ImGui::SetTooltip("%s", flag_str.c_str());
            }
            ImGui::NextColumn();
            snprintf(text, 50, "%lld", threads_map.count(data.proc.p_pid));
            ImGui::Selectable(text, &is_selected, ImGuiSelectableFlags_SpanAllColumns);
            ImGui::NextColumn();
            ImGui::PopStyleColor(2);

            // If there's only 1 thread and its name is the same as the process', don't show its window
            // TODO: Have a way to show those too (via clicking them on the main Process List window)
            if (threads_map.count(data.proc.p_pid) >= 1) {
                auto first_thread = threads_map.equal_range(data.proc.p_pid).first;
                const char *first_thread_name = THREAD_NAME(&first_thread->second);

                if (strcmp(data.proc.p_comm, first_thread_name)) {
                    thread_windows.insert(data.proc.p_pid);
                }
            }
        }

        ImGui::End();

        for (auto p_pid : thread_windows) {
            column_widths_threads.Calculate();

            char thread_window_title[50];
            snprintf(thread_window_title, 50, "Threads List (PID: %d)", p_pid);

            ImGui::SetNextWindowSize(ImVec2(column_widths_threads.total, 0));
            if (!ImGui::Begin(thread_window_title, NULL, ImGuiWindowFlags_AlwaysAutoResize)) {
                ImGui::End();
                continue;
            }

            static const char *headers_thread[] = {
                "Thread Name", "PID"    // TODO: flags (TDP_*)
            };
            static const float header_widths_thread[] = {
                column_widths_threads.name, column_widths_threads.tid
            };
            static const auto header_count_thread = IM_ARRAYSIZE(headers_thread);

            // Draw headers
            ImGui::Columns(header_count_thread, "thread_columns");
            for (auto i = 0; i < header_count_thread; ++i) {
                ImGui::SetColumnWidth(i, header_widths_thread[i]);
            }
            ImGui::Separator();
            for (auto i = 0; i < header_count_thread; ++i) {
                ImGui::TextColored(COLUMN_TITLES_COL, "%s", headers_thread[i]);
                ImGui::NextColumn();
            }
            ImGui::Separator();

            auto threads = threads_map.equal_range(p_pid);

            // Draw rows
            for (auto td_it = threads.first; td_it != threads.second; td_it++) {
                auto td = td_it->second;
                char text[50];

                ImGui::PushStyleColor(ImGuiCol_Text, COLUMN_ROWS_NAME_COL);
                snprintf(text, 50, "%-20s", THREAD_NAME(&td));
                ImGui::Selectable(text, false, ImGuiSelectableFlags_SpanAllColumns);
                ImGui::NextColumn();
                ImGui::PopStyleColor();
                ImGui::PushStyleColor(ImGuiCol_Text, COLUMN_ROWS_OTHER_COL);
                snprintf(text, 50, "%d", td.td_tid);
                ImGui::Selectable(text, false, ImGuiSelectableFlags_SpanAllColumns);
                ImGui::NextColumn();
                ImGui::PopStyleColor();
            }

            ImGui::End();
        }
    }
};

extern "C" {

struct orbital_procs_list_t* orbital_procs_list_create(void)
{
    struct orbital_procs_list_t *procs_list;

    procs_list = new orbital_procs_list_t();
    return procs_list;
}

void orbital_procs_list_destroy(struct orbital_procs_list_t *procs_list)
{
    delete procs_list;
}

void orbital_procs_list_add_proc(struct orbital_procs_list_t *procs_list, struct orbital_proc_data *p)
{
    procs_list->AddProc(p);
}

void orbital_procs_list_add_proc_thread(struct orbital_procs_list_t *procs_list,
                                        int owner_pid,
                                        struct freebsd::thread *td) {
    procs_list->AddProcThread(owner_pid, td);
}

void orbital_procs_list_clear(struct orbital_procs_list_t *procs_list)
{
    procs_list->Clear();
}

void orbital_procs_list_done(struct orbital_procs_list_t *procs_list)
{
    procs_list->Done();
}

void orbital_procs_list_draw(struct orbital_procs_list_t *procs_list, const char *title, bool* p_open)
{
    procs_list->Draw(title, p_open);
}

} // extern "C"
