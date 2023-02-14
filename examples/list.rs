fn main() {
    for device in ctap::get_devices().unwrap() {
        println!("{device:?}");
    }
}
