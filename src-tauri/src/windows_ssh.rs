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

async fn run_gated_command_async<F>(
    port: u16,
    private_key: &Path,
    command: &str,
    ready_marker: &str,
    ready_timeout: Duration,
    timeout: Duration,
    output_limit: usize,
    on_ready: F,
) -> Result<CommandOutput, String>
where
    F: FnOnce() -> Result<(), String>,
{
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
    let ready_deadline = tokio::time::Instant::now() + ready_timeout;
    let mut readiness = Vec::new();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut status = None;
    let mut ready = false;
    let mut on_ready = Some(on_ready);
    loop {
        let message = if ready {
            channel.wait().await
        } else {
            tokio::time::timeout_at(ready_deadline, channel.wait())
                .await
                .map_err(|_| "Mutation guest command readiness marker timed out.".to_string())?
        };
        let Some(message) = message else { break };
        match message {
            ChannelMsg::Data { data } if !ready => {
                if readiness.len().saturating_add(data.len()) > output_limit {
                    return Err("In-process SSH command stdout exceeded its bound.".into());
                }
                readiness.extend_from_slice(&data);
                if let Some(newline) = readiness.iter().position(|byte| *byte == b'\n') {
                    let line = &readiness[..newline];
                    let line = line.strip_suffix(b"\r").unwrap_or(line);
                    if line != ready_marker.as_bytes() {
                        return Err(
                            "Mutation guest command omitted the channel readiness marker.".into(),
                        );
                    }
                    stdout.extend_from_slice(&readiness[newline + 1..]);
                    ready = true;
                    on_ready
                        .take()
                        .ok_or("Mutation readiness callback was already invoked.")?(
                    )?;
                } else if readiness.len() > 64 {
                    return Err("Guest command readiness marker is missing or excessive.".into());
                }
            }
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
    if !ready {
        return Err("Mutation guest command omitted the channel readiness marker.".into());
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

pub(crate) fn run_gated_command<F>(
    port: u16,
    private_key: &Path,
    command: &str,
    ready_marker: &str,
    ready_timeout: Duration,
    timeout: Duration,
    output_limit: usize,
    on_ready: F,
) -> Result<CommandOutput, String>
where
    F: FnOnce() -> Result<(), String>,
{
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("Could not start the appliance SSH runtime: {error}"))?;
    runtime.block_on(async {
        tokio::time::timeout(
            timeout,
            run_gated_command_async(
                port,
                private_key,
                command,
                ready_marker,
                ready_timeout,
                timeout,
                output_limit,
                on_ready,
            ),
        )
        .await
        .map_err(|_| "In-process SSH mutation command timed out.".to_string())?
    })
}
