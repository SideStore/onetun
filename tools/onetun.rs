use onetun::{config::Config, start};

#[tokio::main]
async fn main() {
    let config = match Config::from_args() {
        Ok(config) => config,
        Err(e) => {
            eprintln!("{}", e);
            std::process::exit(1);
        }
    };

    start(config).await;
}
