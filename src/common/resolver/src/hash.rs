pub fn fnv1a_32_hash(sz_name: *mut i8, insensitive: bool, unicode: bool) -> u32 {
    let mut result: u32 = 2166136261;

    let mut index: isize = 0;

    loop {
        let mut current: i8 = unsafe { *sz_name.offset(index) };

        if current == 0x0 {
            // handle ansi string, 1 byte break
            if !unicode {
                break;
            }

            // unicode has 2 null bytes
            if unsafe { *sz_name.offset(index + 1) } == 0x0 {
                break;
            }
        }

        // toupper
        if insensitive && current >= 0x61 { // 'a'
            current -= 0x20;
        }

        result ^= current as u32;
        result *= 16777619;

        index += 1;
    }

    result
}
