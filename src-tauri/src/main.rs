fn main() {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
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
    steamos_nvidia_image_builder_lib::run();
}
