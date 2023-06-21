pub mod trace;
pub mod geoip;
pub mod caps;
pub mod trippyLib;

use log::{error, info, warn};

pub mod dns;
use fastping_rs::PingResult::{Idle, Receive};
use fastping_rs::Pinger;
use pretty_env_logger;

fn main() /*-> Result<()> */{
    /*let json = trippyLib::Run()?;*/

    // todo
    /*
        fetch the json from the api
        parse the json into a struct
        sort data into check types
        run checks for each type

        non pinger tests will need to be ran in parallel
        pinger tests are already done in batches, after 60
        seconds the pinger will stop, push it's data over grpc
        to the backend.

        the other checks will do the same, and push the data over to the backend periodically.

        obkio stores traceroute data locally, and opens a websocket to pass the data to the
        user from the looks of it.. we can do the same, but we can also push the data to the
        backend, and have the backend do grpc stuff instead

        rperf will also need to be included, and checks handled accordingly
     */

    pretty_env_logger::init();
    let (pinger, results) = match Pinger::new(None, Some(56)) {
        Ok((pinger, results)) => (pinger, results),
        Err(e) => panic!("Error creating pinger: {}", e),
    };

    pinger.add_ipaddr("8.8.8.8");
    pinger.add_ipaddr("1.1.1.1");
    pinger.run_pinger();

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
    /*Ok(())*/
}

