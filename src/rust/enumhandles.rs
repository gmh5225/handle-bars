#[link(name = ".\\out\\rustydump", kind = "static")]
extern "C" {
    fn fetch_handles(pid: u32) -> i32;
}

pub fn find_handles(pid: u32) {
    unsafe {
        fetch_handles(pid);
    }
}