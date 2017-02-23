<?php

namespace bin_prot\type_class;

class type_class {
    public static function read()
    {
        return static::$_read;
    }

    public static function write()
    {
        return static::$_write;
    }

    public static function size()
    {
        return static::$_size;
    }
}

class bin_unit extends type_class {
    protected static $_read  = 'bin_prot\read\bin_read_unit';
    protected static $_write = 'bin_prot\write\bin_write_unit';
    protected static $_size  = 'bin_prot\size\bin_size_unit';
}

class bin_bool extends type_class {
    protected static $_read  = 'bin_prot\read\bin_read_bool';
    protected static $_write = 'bin_prot\write\bin_write_bool';
    protected static $_size  = 'bin_prot\size\bin_size_bool';
}

class bin_char extends type_class {
    protected static $_read  = 'bin_prot\read\bin_read_char';
    protected static $_write = 'bin_prot\write\bin_write_char';
    protected static $_size  = 'bin_prot\size\bin_size_char';
}

class bin_nat0 extends type_class {
    protected static $_read  = 'bin_prot\read\bin_read_nat0';
    protected static $_write = 'bin_prot\write\bin_write_nat0';
    protected static $_size  = 'bin_prot\size\bin_size_nat0';
}

class bin_int extends type_class {
    protected static $_read  = 'bin_prot\read\bin_read_int';
    protected static $_write = 'bin_prot\write\bin_write_int';
    protected static $_size  = 'bin_prot\size\bin_size_int';
}

class bin_int32 extends type_class {
    protected static $_read  = 'bin_prot\read\bin_read_int32';
    protected static $_write = 'bin_prot\write\bin_write_int32';
    protected static $_size  = 'bin_prot\size\bin_size_int32';
}

class bin_int64 extends type_class {
    protected static $_read  = 'bin_prot\read\bin_read_int64';
    protected static $_write = 'bin_prot\write\bin_write_int64';
    protected static $_size  = 'bin_prot\size\bin_size_int64';
}

class bin_int_8bit extends type_class {
    protected static $_read  = 'bin_prot\read\bin_read_int_8bit';
    protected static $_write = 'bin_prot\write\bin_write_int_8bit';
    protected static $_size  = 'bin_prot\size\bin_size_int_8bit';
}

class bin_int_16bit extends type_class {
    protected static $_read  = 'bin_prot\read\bin_read_int_16bit';
    protected static $_write = 'bin_prot\write\bin_write_int_16bit';
    protected static $_size  = 'bin_prot\size\bin_size_int_16bit';
}

class bin_int_32bit extends type_class {
    protected static $_read  = 'bin_prot\read\bin_read_int_32bit';
    protected static $_write = 'bin_prot\write\bin_write_int_32bit';
    protected static $_size  = 'bin_prot\size\bin_size_int_32bit';
}

class bin_int_64bit extends type_class {
    protected static $_read  = 'bin_prot\read\bin_read_int_64bit';
    protected static $_write = 'bin_prot\write\bin_write_int_64bit';
    protected static $_size  = 'bin_prot\size\bin_size_int_64bit';
}

class bin_network16_int extends type_class {
    protected static $_read  = 'bin_prot\read\bin_read_network16_int';
    protected static $_write = 'bin_prot\write\bin_write_network16_int';
    protected static $_size  = 'bin_prot\size\bin_size_network16_int';
}

class bin_network32_int extends type_class {
    protected static $_read  = 'bin_prot\read\bin_read_network32_int';
    protected static $_write = 'bin_prot\write\bin_write_network32_int';
    protected static $_size  = 'bin_prot\size\bin_size_network32_int';
}

class bin_network64_int extends type_class {
    protected static $_read  = 'bin_prot\read\bin_read_network64_int';
    protected static $_write = 'bin_prot\write\bin_write_network64_int';
    protected static $_size  = 'bin_prot\size\bin_size_network64_int';
}

class bin_variant_int extends type_class {
    protected static $_read  = 'bin_prot\read\bin_read_variant_int';
    protected static $_write = 'bin_prot\write\bin_write_variant_int';
    protected static $_size  = 'bin_prot\size\bin_size_variant_int';
}

class bin_float extends type_class {
    protected static $_read  = 'bin_prot\read\bin_read_float';
    protected static $_write = 'bin_prot\write\bin_write_float';
    protected static $_size  = 'bin_prot\size\bin_size_float';
}

class bin_string extends type_class {
    protected static $_read  = 'bin_prot\read\bin_read_string';
    protected static $_write = 'bin_prot\write\bin_write_string';
    protected static $_size  = 'bin_prot\size\bin_size_string';
}

class bin_digest extends type_class {
    protected static $_read  = 'bin_prot\read\bin_read_digest';
    protected static $_write = 'bin_prot\write\bin_write_digest';
    protected static $_size  = 'bin_prot\size\bin_size_digest';
}
