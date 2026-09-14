use russh::{
    client,
    keys::{load_secret_key, PrivateKeyWithHashAlg, PublicKeyOrCertificate},
    ChannelMsg,
};
use std::{path::Path, sync::Arc, time::Duration};

#[derive(Debug)]
pub(crate) struct CommandOutput {
    pub(crate) stdout: Vec<u8>,
    pub(crate) stderr: Vec<u8>,
    pub(crate) status: i32,
}

struct Client;

impl client::Handler for Client {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

async fn run_command_async(
    port: u16,
    private_key: &Path,
    command: &str,
    timeout: Duration,
    output_limit: usize,
) -> Result<CommandOutput, String> {
    let key = load_secret_key(private_key, None)
        .map_err(|error| format!("Could not read the appliance OpenSSH identity: {error}"))?;
    let config = Arc::new(client::Config {
        inactivity_timeout: Some(timeout),
        ..Default::default()
    });
    let mut session = client::connect(config, ("127.0.0.1", port), Client)
        .await
        .map_err(|error| format!("Could not connect to the Windows appliance SSH port: {error}"))?;
    let authentication = session
        .authenticate_publickey("builder", PrivateKeyWithHashAlg::new(Arc::new(key), None))
        .await
        .map_err(|error| format!("Could not authenticate to the appliance: {error}"))?;
    if !authentication.success() {
        return Err("The appliance rejected the ephemeral SSH identity.".into());
    }

    let mut channel = session
        .channel_open_session()
        .await
        .map_err(|error| format!("Could not open the appliance SSH command channel: {error}"))?;
    channel
        .exec(true, command)
        .await
        .map_err(|error| format!("Could not start the appliance SSH command: {error}"))?;

    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut status = None;
    while let Some(message) = channel.wait().await {
        match message {
            ChannelMsg::Data { data } => {
                if stdout.len().saturating_add(data.len()) > output_limit {
                    return Err("In-process SSH command stdout exceeded its bound.".into());
                }
                stdout.extend_from_slice(&data);
            }
            ChannelMsg::ExtendedData { data, ext: 1 } => {
                if stderr.len().saturating_add(data.len()) > output_limit {
                    return Err("In-process SSH command stderr exceeded its bound.".into());
                }
                stderr.extend_from_slice(&data);
            }
            ChannelMsg::ExitStatus { exit_status } => {
                status = Some(
                    i32::try_from(exit_status)
                        .map_err(|_| "Appliance SSH exit status exceeded the supported range.")?,
                );
            }
            _ => {}
        }
    }
    let status = status.ok_or("The appliance SSH command closed without an exit status.")?;
    let _ = session
        .disconnect(russh::Disconnect::ByApplication, "", "English")
        .await;
    Ok(CommandOutput {
        stdout,
        stderr,
        status,
    })
}

pub(crate) fn run_command(
    port: u16,
    private_key: &Path,
    command: &str,
    timeout: Duration,
    output_limit: usize,
) -> Result<CommandOutput, String> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("Could not start the appliance SSH runtime: {error}"))?;
    runtime.block_on(async {
        tokio::time::timeout(
            timeout,
            run_command_async(port, private_key, command, timeout, output_limit),
        )
        .await
        .map_err(|_| "In-process SSH command timed out.".to_string())?
    })
}
