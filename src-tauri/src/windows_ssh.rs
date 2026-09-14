use ssh2::Session;
use std::{
    io::{self, Read},
    net::{SocketAddr, TcpStream},
    path::Path,
    thread,
    time::{Duration, Instant},
};

#[derive(Debug)]
pub(crate) struct CommandOutput {
    pub(crate) stdout: Vec<u8>,
    pub(crate) stderr: Vec<u8>,
    pub(crate) status: i32,
}

fn read_available(
    reader: &mut impl Read,
    destination: &mut Vec<u8>,
    limit: usize,
) -> Result<bool, String> {
    let mut buffer = [0_u8; 8192];
    match reader.read(&mut buffer) {
        Ok(0) => Ok(false),
        Ok(bytes) => {
            if destination.len().saturating_add(bytes) > limit {
                return Err("In-process SSH command output exceeded its bound.".into());
            }
            destination.extend_from_slice(&buffer[..bytes]);
            Ok(true)
        }
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(false),
        Err(error) => Err(format!(
            "Could not read in-process SSH command output: {error}"
        )),
    }
}

pub(crate) fn run_command(
    port: u16,
    private_key: &Path,
    command: &str,
    timeout: Duration,
    output_limit: usize,
) -> Result<CommandOutput, String> {
    let address = SocketAddr::from(([127, 0, 0, 1], port));
    let stream = TcpStream::connect_timeout(&address, timeout)
        .map_err(|error| format!("Could not connect to the Windows appliance SSH port: {error}"))?;
    stream
        .set_nodelay(true)
        .map_err(|error| format!("Could not configure the appliance SSH socket: {error}"))?;

    let mut session =
        Session::new().map_err(|error| format!("Could not create the SSH session: {error}"))?;
    session.set_timeout(
        timeout
            .as_millis()
            .min(u32::MAX as u128)
            .try_into()
            .unwrap_or(u32::MAX),
    );
    session.set_tcp_stream(stream);
    session
        .handshake()
        .map_err(|error| format!("Could not negotiate the appliance SSH session: {error}"))?;
    session
        .userauth_pubkey_file("builder", None, private_key, None)
        .map_err(|error| format!("Could not authenticate to the appliance: {error}"))?;
    if !session.authenticated() {
        return Err("The appliance rejected the ephemeral SSH identity.".into());
    }

    let mut channel = session
        .channel_session()
        .map_err(|error| format!("Could not open the appliance SSH command channel: {error}"))?;
    channel
        .exec(command)
        .map_err(|error| format!("Could not start the appliance SSH command: {error}"))?;
    session.set_blocking(false);

    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or("In-process SSH command deadline overflowed.")?;
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    loop {
        let mut progressed = read_available(&mut channel, &mut stdout, output_limit)?;
        progressed |= read_available(&mut channel.stderr(), &mut stderr, output_limit)?;
        if channel.eof() {
            break;
        }
        if Instant::now() >= deadline {
            let _ = channel.close();
            return Err("In-process SSH command timed out.".into());
        }
        if !progressed {
            thread::sleep(Duration::from_millis(5));
        }
    }

    session.set_blocking(true);
    channel
        .wait_close()
        .map_err(|error| format!("Could not close the appliance SSH command channel: {error}"))?;
    let status = channel
        .exit_status()
        .map_err(|error| format!("Could not read the appliance SSH exit status: {error}"))?;
    Ok(CommandOutput {
        stdout,
        stderr,
        status,
    })
}
