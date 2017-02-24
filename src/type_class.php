<?php

namespace bin_prot\type_class;

class type_class {
    private $_read;
    private $_write;
    private $_size;

    public function __construct($read, $write, $size)
    {
        $this->_read  = $read;
        $this->_write = $write;
        $this->_size  = $size;
    }

    public function read()
    {
        return $this->_read;
    }

    public function write()
    {
        return $this->_write;
    }

    public function size()
    {
        return $this->_size;
    }
}

class bin_unit extends type_class {
    public function __construct()
    {
        parent::__construct('bin_prot\read\bin_read_unit',
                            'bin_prot\write\bin_write_unit',
                            'bin_prot\size\bin_size_unit');
    }
}

class bin_bool extends type_class {
    public function __construct()
    {
        parent::__construct('bin_prot\read\bin_read_bool',
                            'bin_prot\write\bin_write_bool',
                            'bin_prot\size\bin_size_bool');
    }
}

class bin_char extends type_class {
    public function __construct()
    {
        parent::__construct('bin_prot\read\bin_read_char',
                            'bin_prot\write\bin_write_char',
                            'bin_prot\size\bin_size_char');
    }
}

class bin_nat0 extends type_class {
    public function __construct()
    {
        parent::__construct('bin_prot\read\bin_read_nat0',
                            'bin_prot\write\bin_write_nat0',
                            'bin_prot\size\bin_size_nat0');
    }
}

class bin_int extends type_class {
    public function __construct()
    {
        parent::__construct('bin_prot\read\bin_read_int',
                            'bin_prot\write\bin_write_int',
                            'bin_prot\size\bin_size_int');
    }
}

class bin_int32 extends type_class {
    public function __construct()
    {
        parent::__construct('bin_prot\read\bin_read_int32',
                            'bin_prot\write\bin_write_int32',
                            'bin_prot\size\bin_size_int32');
    }
}

class bin_int64 extends type_class {
    public function __construct()
    {
        parent::__construct('bin_prot\read\bin_read_int64',
                            'bin_prot\write\bin_write_int64',
                            'bin_prot\size\bin_size_int64');
    }
}

class bin_int_8bit extends type_class {
    public function __construct()
    {
        parent::__construct('bin_prot\read\bin_read_int_8bit',
                            'bin_prot\write\bin_write_int_8bit',
                            'bin_prot\size\bin_size_int_8bit');
    }
}

class bin_int_16bit extends type_class {
    public function __construct()
    {
        parent::__construct('bin_prot\read\bin_read_int_16bit',
                            'bin_prot\write\bin_write_int_16bit',
                            'bin_prot\size\bin_size_int_16bit');
    }
}

class bin_int_32bit extends type_class {
    public function __construct()
    {
        parent::__construct('bin_prot\read\bin_read_int_32bit',
                            'bin_prot\write\bin_write_int_32bit',
                            'bin_prot\size\bin_size_int_32bit');
    }
}

class bin_int_64bit extends type_class {
    public function __construct()
    {
        parent::__construct('bin_prot\read\bin_read_int_64bit',
                            'bin_prot\write\bin_write_int_64bit',
                            'bin_prot\size\bin_size_int_64bit');
    }
}

class bin_network16_int extends type_class {
    public function __construct()
    {
        parent::__construct('bin_prot\read\bin_read_network16_int',
                            'bin_prot\write\bin_write_network16_int',
                            'bin_prot\size\bin_size_network16_int');
    }
}

class bin_network32_int extends type_class {
    public function __construct()
    {
        parent::__construct('bin_prot\read\bin_read_network32_int',
                            'bin_prot\write\bin_write_network32_int',
                            'bin_prot\size\bin_size_network32_int');
    }
}

class bin_network64_int extends type_class {
    public function __construct()
    {
        parent::__construct('bin_prot\read\bin_read_network64_int',
                            'bin_prot\write\bin_write_network64_int',
                            'bin_prot\size\bin_size_network64_int');
    }
}

class bin_variant_int extends type_class {
    public function __construct()
    {
        parent::__construct('bin_prot\read\bin_read_variant_int',
                            'bin_prot\write\bin_write_variant_int',
                            'bin_prot\size\bin_size_variant_int');
    }
}

class bin_float extends type_class {
    public function __construct()
    {
        parent::__construct('bin_prot\read\bin_read_float',
                            'bin_prot\write\bin_write_float',
                            'bin_prot\size\bin_size_float');
    }
}

class bin_string extends type_class {
    public function __construct()
    {
        parent::__construct('bin_prot\read\bin_read_string',
                            'bin_prot\write\bin_write_string',
                            'bin_prot\size\bin_size_string');
    }
}

class bin_digest extends type_class {
    public function __construct()
    {
        parent::__construct('bin_prot\read\bin_read_digest',
                            'bin_prot\write\bin_write_digest',
                            'bin_prot\size\bin_size_digest');
    }
}

class bin_option extends type_class {
    public function __construct($bin_a)
    {
        $this->_read = function($buf, $pos) use ($bin_a) {
            bin_prot\read\bin_read_option($bin_a->read(), $buf, $pos);
        };
        $this->_write = function($buf, $pos, $v) use ($bin_a) {
            bin_prot\write\bin_write_option($bin_a->write(), $buf, $pos, $v);
        };
        $this->_size = function($v) use ($bin_a) {
            bin_prot\size\bin_size_option($bin_a->size(), $v);
        };
    }
}

class bin_pair extends type_class {
    public function __construct($bin_a, $bin_b)
    {
        $this->_read = function($buf, $pos) use ($bin_a, $bin_b) {
            bin_prot\read\bin_read_pair($bin_a->read(), $bin_b->read(), $buf, $pos);
        };
        $this->_write = function($buf, $pos, $v) use ($bin_a, $bin_b) {
            bin_prot\write\bin_write_pair($bin_a->write(), $bin_b->write(),
                                          $buf, $pos, $v);
        };
        $this->_size = function($v) use ($bin_a, $bin_b) {
            bin_prot\size\bin_size_pair($bin_a->size(), $bin_b->size(), $v);
        };
    }
}

class bin_triple extends type_class {
    public function __construct($bin_a, $bin_b, $bin_c)
    {
        $this->_read = function($buf, $pos) use ($bin_a, $bin_b, $bin_c) {
            bin_prot\read\bin_read_triple($bin_a->read(),
                                          $bin_b->read(),
                                          $bin_c->read(), $buf, $pos);
        };
        $this->_write = function($buf, $pos, $v) use ($bin_a, $bin_b, $bin_c) {
            bin_prot\write\bin_write_triple($bin_a->write(),
                                            $bin_b->write(),
                                            $bin_c->write(), $buf, $pos, $v);
        };
        $this->_size = function($v) use ($bin_a, $bin_b, $bin_c) {
            bin_prot\size\bin_size_triple($bin_a->size(),
                                          $bin_b->size(),
                                          $bin_c->size(), $v);
        };
    }
}

class bin_array extends type_class {
    public function __construct($bin_a)
    {
        $this->_read = function($buf, $pos) use ($bin_a) {
            bin_prot\read\bin_read_array($bin_a->read(), $buf, $pos);
        };
        $this->_write = function($buf, $pos, $v) use ($bin_a) {
            bin_prot\write\bin_write_array($bin_a->write(), $buf, $pos, $v);
        };
        $this->_size = function($v) use ($bin_a) {
            bin_prot\size\bin_size_array($bin_a->size(), $v);
        };
    }
}

class bin_hashtbl extends type_class {
    public function __construct($bin_k, $bin_v)
    {
        $this->_read = function($buf, $pos) use ($bin_a) {
            bin_prot\read\bin_read_hashtbl($bin_k->read(),
                                           $bin_v->read(), $buf, $pos);
        };
        $this->_write = function($buf, $pos, $v) use ($bin_a) {
            bin_prot\write\bin_write_hashtbl($bin_k->write(),
                                             $bin_v->write(), $buf, $pos, $v);
        };
        $this->_size = function($v) use ($bin_a) {
            bin_prot\size\bin_size_hashtbl($bin_k->size(), $bin_v->size(), $v);
        };
    }
}
