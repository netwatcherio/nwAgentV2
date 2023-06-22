use fastping_rs::Pinger;
use fastping_rs::PingResult::{Idle, Receive};
use log::{error, info};

pub(crate) fn Ping (ipaddr: &str) -> Result<(), std::io::Error>{
    pretty_env_logger::init();
    let (pinger, results) = match Pinger::new(None, Some(56)) {
        Ok((pinger, results)) => (pinger, results),
        Err(e) => panic!("Error creating pinger: {}", e),
    };

    // this will need to run multiple checks
    // against the configs, and then run the pinger
    // todo take input from api config, add to pinger, run pinger

    pinger.add_ipaddr(&*ipaddr);
    pinger.run_pinger();

    // loop over the results

    loop {
        match results.recv() {
            Ok(result) => match result {
                Idle { addr } => {
                    // log error to console
                    error!("Idle Address {}.", addr);
                }
                Receive { addr, rtt } => {
                    info!("Receive from Address {} in {:?}.", addr, rtt);
                }
            },
            Err(_) => panic!("Worker threads disconnected before the solution was found!"),
        }
    }
}