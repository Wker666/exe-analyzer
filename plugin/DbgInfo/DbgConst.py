# Define constants for BreakpointType
BREAKPOINT_TYPE_SOFTWARE = 0
BREAKPOINT_TYPE_HARDWARE = 1
BREAKPOINT_TYPE_MEMORY = 2
BREAKPOINT_TYPE_NONE = 3

# Define constants for AccessType
ACCESS_TYPE_EXECUTE = 0
ACCESS_TYPE_WRITE = 1
ACCESS_TYPE_READWRITE = 2
ACCESS_TYPE_NONE = 3

# Define constants for CallBackType
CALLBACK_TYPE_NONE = 0
CALLBACK_TYPE_IGNORE_AFTER = 1
CALLBACK_TYPE_SINGLE_INTO_STEP = 2
CALLBACK_TYPE_SINGLE_STEP_STEP = 3

# Memory allocation constants
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
MEM_RELEASE = 0x8000

# 定义内存保护常量
PAGE_NOACCESS          = 0x01
PAGE_READONLY          = 0x02
PAGE_READWRITE         = 0x04
PAGE_WRITECOPY         = 0x08
PAGE_EXECUTE           = 0x10
PAGE_EXECUTE_READ      = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80
PAGE_GUARD             = 0x100
PAGE_NOCACHE           = 0x200
PAGE_WRITECOMBINE      = 0x400

# 启动信息
START_DBG_PROCESS="START_PRO"
ACTIVE_DBG_PROCESS="ACTIVE_PRO"
VEH_PROCESS="VEH_PRO"
WINDOWS_API_DBG="WIN_API_DBG"
VEH_DBG="VEH_DBG"

# 映射内存保护常量到字符串
protection_flags = {
    PAGE_NOACCESS:          "NOACCESS",
    PAGE_READONLY:          "READONLY",
    PAGE_READWRITE:         "READWRITE",
    PAGE_WRITECOPY:         "WRITECOPY",
    PAGE_EXECUTE:           "EXECUTE",
    PAGE_EXECUTE_READ:      "EXECUTE_READ",
    PAGE_EXECUTE_READWRITE: "EXECUTE_READWRITE",
    PAGE_EXECUTE_WRITECOPY: "EXECUTE_WRITECOPY",
    PAGE_GUARD:             "GUARD",
    PAGE_NOCACHE:           "NOCACHE",
    PAGE_WRITECOMBINE:      "WRITECOMBINE",
}

# Map the integer values to meaningful strings for BreakpointType
breakpoint_type_map = {
    BREAKPOINT_TYPE_SOFTWARE: "Software",
    BREAKPOINT_TYPE_HARDWARE: "Hardware",
    BREAKPOINT_TYPE_MEMORY: "Memory",
    BREAKPOINT_TYPE_NONE: "None",
}

# Map the integer values to meaningful strings for AccessType
access_type_map = {
    ACCESS_TYPE_EXECUTE: "Execute",
    ACCESS_TYPE_WRITE: "Write",
    ACCESS_TYPE_READWRITE: "ReadWrite",
    ACCESS_TYPE_NONE: "None",
}

# Map the integer values to meaningful strings for CallBackType
callback_type_map = {
    CALLBACK_TYPE_NONE: "None",
    CALLBACK_TYPE_IGNORE_AFTER: "Ignore After",
    CALLBACK_TYPE_SINGLE_INTO_STEP: "Single Into Step",
    CALLBACK_TYPE_SINGLE_STEP_STEP: "Single Step Step",
}
