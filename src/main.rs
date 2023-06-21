pub mod trace;
pub mod geoip;
pub mod caps;
pub mod trippyLib;

pub mod dns;

fn main () -> anyhow::Result<()>{
    let json = trippyLib::Run()?;
    Ok(())
}

