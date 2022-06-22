use onetun::{blocking_start, config::Config, start};

fn main() {
    let config = match Config::from_args() {
        Ok(config) => config,
        Err(e) => {
            eprintln!("{}", e);
            std::process::exit(1);
        }
    };

    blocking_start(config).unwrap();
}
