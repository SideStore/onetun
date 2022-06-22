use onetun;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::str::FromStr;

#[no_mangle]
pub extern "C" fn hello_from_rust() {
    println!("Hello from Rust!");
}

#[no_mangle]
pub extern "C" fn start() {
    onetun::blocking_start(
        onetun::config::Config::new(
            vec![],
            vec![],
            "UI+sCDEketXDq6vOAidLe0mYiHogMh1TA2zg3CqlxEA=",
            "ow01dGyrgRSrjln9bGb6fx0FwY5XKSVMTaoKQ2GDSkM=",
            SocketAddr::from_str("192.168.1.22:50670").unwrap(),
            IpAddr::from_str("10.7.0.1").unwrap(),
            None,
            None,
            None,
            None,
        )
        .unwrap(),
    )
    .unwrap();
}
