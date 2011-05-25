
class v_base_t(object):
    _fmt_ = ""

    def __init__(self, value=0):
        object.__init__(self)
        self.value = value

    def __repr__(self):
        return repr(self.value)

    def __int__(self):
        return int(self.value)

    def __long__(self):
        return long(self.value)

class v_int8(v_base_t):
    _fmt_ = "b"

class v_int16(v_base_t):
    _fmt_ = "h"

class v_int32(v_base_t):
    _fmt_ = "i"

class v_int64(v_base_t):
    _fmt_ = "q"

class v_uint8(v_base_t):
    _fmt_ = "B"

class v_uint16(v_base_t):
    _fmt_ = "H"

class v_uint32(v_base_t):
    _fmt_ = "I"

class v_uint64(v_base_t):
    _fmt_ = "Q"

class v_ptr(v_base_t):
    _fmt_ = "L"
    #FIXME this should be P with & 0xffffffffN
    def __repr__(self):
        return "0x%.8x" % self.value

class v_str(v_ptr):
    pass

class v_wstr(v_ptr):
    pass

