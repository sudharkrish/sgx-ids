//--------------------------------------------------------------------------
// Copyright (C) 2016-2017 Cisco and/or its affiliates. All rights reserved.
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License Version 2 as published
// by the Free Software Foundation.  You may not use, modify or distribute
// this program under any other version of the GNU General Public License.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
//--------------------------------------------------------------------------

// text_formatter.h author Carter Waxman <cwaxman@cisco.com>

#ifndef TEXT_FORMATTER_H
#define TEXT_FORMATTER_H

#include "perf_formatter.h"

class TextFormatter : public PerfFormatter
{
public:
    TextFormatter(const std::string& tracker_name) : PerfFormatter(tracker_name) {}

    const char* get_extension() override
    { return ".txt"; }

    void write(FILE*, time_t) override;
};

#endif

