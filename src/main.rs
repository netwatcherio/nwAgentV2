use std::collections::HashMap;

use bson::oid::ObjectId;
use fastping_rs::Pinger;
use fastping_rs::PingResult::{Idle, Receive};
use log::{error, info, warn};
use pretty_env_logger;
use reqwest::Error;
use serde::{Deserialize, Serialize};

pub mod trace;
pub mod geoip;
pub mod caps;
pub mod trippyLib;

pub mod dns;
mod webclient;
mod pingLib;

#[derive(Serialize, Deserialize)]
pub struct ApiRequest {
    pin: Option<String>,
    id: Option<String>,
    data: Option<HashMap<String, String>>,
    error: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum CheckType {
    Rperf,
    Mtr,
    Speedtest,
    Netinfo,
    Ping,
}

#[derive(Serialize, Deserialize)]
pub struct CheckData {
    target: Option<String>,
    check_id: ObjectId,
    agent_id: ObjectId,
    triggered: Option<bool>,
    result: Option<HashMap<String, String>>,
    #[serde(rename = "type")]
    check_type: CheckType,
}

// agent check struct
#[derive(Serialize, Deserialize)]
pub struct AgentCheck {
    #[serde(rename = "type")]
    check_type: CheckType,
    target: Option<String>,
    id: ObjectId,
    agent_id: ObjectId,
    duration: Option<i32>,
    count: Option<i32>,
    triggered: Option<bool>,
    server: Option<bool>,
    pending: Option<bool>,
    interval: i32,
}

fn main() /*-> Result<()> */ {
    /*let json = trippyLib::Run()?;*/

    pingLib::Ping("1.1.1.1").expect("TODO: panic message");
    
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


    /*Ok(())*/
}

