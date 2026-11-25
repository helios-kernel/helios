use std::fs;

use helios_wit_rpc::inspector::helios::system::programs::ExecResult;

use crate::ShellCommand;
use crate::programs::{self, ProgramError, REMOTE_SHELL_PATH};
use crate::serial::RpcClient;

/// Why the `shell` command had no script to run.
#[derive(Debug, thiserror::Error)]
pub enum ShellScriptError {
    #[error("failed to read local shell script {path}: {source}")]
    ReadScript {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("shell requires either -c <script> or <script-file>")]
    MissingScript,
    #[error("failed to run the remote shell: {source}")]
    RemoteShell {
        #[from]
        source: ProgramError,
    },
}

pub async fn run_shell_command(
    client: &mut RpcClient,
    command: &ShellCommand,
) -> Result<ExecResult, ShellScriptError> {
    let script = match (&command.command, &command.script) {
        (Some(command), None) => command.clone(),
        (None, Some(path)) => {
            fs::read_to_string(path).map_err(|source| ShellScriptError::ReadScript {
                path: path.clone(),
                source,
            })?
        }
        (None, None) => return Err(ShellScriptError::MissingScript),
        (Some(_), Some(_)) => unreachable!("clap must reject conflicting shell inputs"),
    };
    let shell_path = command.shell.as_deref().unwrap_or(REMOTE_SHELL_PATH);
    Ok(run_shell_script(client, shell_path, script).await?)
}

async fn run_shell_script(
    client: &mut RpcClient,
    shell_path: &str,
    script: String,
) -> Result<ExecResult, ProgramError> {
    programs::exec(client, shell_path, &["-c".to_owned(), script]).await
}
