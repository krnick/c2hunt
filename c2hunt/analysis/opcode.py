# Definition of required opcodes

CONST_STRING = "const-string"
APUT_OBJECT = "aput-object"
NEW_ARRAY = "new-array"
IPUT_OBJECT = "iput-object"
IPUT_BOOLEAN = "iput-boolean"
IPUT = "iput"
SPUT_OBJECT = "sput-object"
GOTO = "goto"
SPARSE_SWITCH = "sparse-switch"
NEW_INSTANCE = "new-instance"

start_prefix = {
    APUT_OBJECT,
    NEW_ARRAY,
    IPUT_OBJECT,
    IPUT_BOOLEAN,
    IPUT,
    SPUT_OBJECT,
    GOTO,
    SPARSE_SWITCH,
    NEW_INSTANCE,
}
