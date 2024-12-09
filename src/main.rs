use flexi_logger::*;
use mini_rust_desk_common::ResultType;
use mini_rust_desk_client::start_work;
fn main() -> ResultType<()> {
    let _logger = Logger::try_with_env_or_str("debug")?
        .log_to_stdout()
        .format(opt_format)
        .write_mode(WriteMode::Async)
        .start()?;
    crate::start_work("192.168.3.196:21116","417866831","mM+2AqccYg5imAbJaoKWcLAzcr6M4TG6g93y3xHani8=","");
    Ok(())
}