fn main() {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    match steamos_nvidia_image_builder_lib::run_windows_usb_writer_helper(&arguments) {
        Ok(Some(output)) => {
            println!("{output}");
            return;
        }
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(2);
        }
        Ok(None) => {}
    }
    if let Err(error) = steamos_nvidia_image_builder_lib::activate_runtime_bundle() {
        eprintln!("{error}");
        std::process::exit(2);
    }
    if let Err(error) = steamos_nvidia_image_builder_lib::prepare_portable_state() {
        eprintln!("{error}");
        std::process::exit(2);
    }
    match steamos_nvidia_image_builder_lib::run_core_driver_resolver(&arguments) {
        Ok(Some(output)) => {
            println!("{output}");
            return;
        }
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(2);
        }
        Ok(None) => {}
    }
    match steamos_nvidia_image_builder_lib::run_windows_virtual_usb_harness(&arguments) {
        Ok(Some(output)) => {
            println!("{output}");
            return;
        }
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(2);
        }
        Ok(None) => {}
    }
    match steamos_nvidia_image_builder_lib::run_windows_headless_image_builder(&arguments) {
        Ok(Some(output)) => {
            println!("{output}");
            return;
        }
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(2);
        }
        Ok(None) => {}
    }
    steamos_nvidia_image_builder_lib::run();
}
