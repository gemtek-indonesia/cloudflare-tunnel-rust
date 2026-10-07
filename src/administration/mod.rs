mod client;
pub mod credentials;
mod filters;
mod login;
mod models;
mod output;
mod yaml;
pub use client::AccountClient;
pub(crate) use client::verified_connector;
pub(crate) use client::verified_tls_connector;

use crate::cli::Invocation;
use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use std::path::PathBuf;
use uuid::Uuid;

pub async fn execute(invocation: Invocation) -> Result<()> {
    if matches!(invocation.command.as_str(), "login" | "tunnel login") {
        return login::execute(&invocation).await;
    }
    let cert_path = credentials::cert_path(invocation.string("origincert"))?;
    let cert = credentials::AccountCredentials::read(&cert_path)?;
    let logger = crate::observability::logging::Logger::new(
        crate::observability::logging::Options {
            level: crate::observability::logging::Level::parse(invocation.string("loglevel"))
                .unwrap_or_default(),
            file: (!invocation.string("logfile").is_empty())
                .then(|| expanded(invocation.string("logfile")))
                .transpose()?,
            directory: (!invocation.string("log-directory").is_empty())
                .then(|| expanded(invocation.string("log-directory")))
                .transpose()?,
            ..Default::default()
        },
        vec![cert.api_token.clone()],
    )?;
    let client = AccountClient::new(cert, invocation.string("api-url"))?;
    match invocation.command.as_str() {
        "tunnel create" => {
            let name = argument(&invocation, 0, "tunnel name")?;
            if invocation.args.len() != 1 {
                bail!("cloudflared tunnel create requires exactly one tunnel name");
            }
            let secret = if invocation.string("secret").is_empty() {
                let mut data = vec![0; 32];
                boring::rand::rand_bytes(&mut data)?;
                data
            } else {
                STANDARD
                    .decode(invocation.string("secret"))
                    .context("invalid base64 tunnel secret")?
            };
            if secret.len() < 32 {
                bail!("Decoded tunnel secret must be at least 32 bytes long");
            }
            let (tunnel, created, path) = create_with_credentials(
                &client,
                name,
                secret,
                invocation.string("credentials-file"),
                &cert_path,
            )
            .await?;
            let id = created.tunnel_id;
            if output_format(&invocation).is_some() {
                render(&invocation, &tunnel)?;
            } else {
                println!(
                    "Tunnel credentials written to {}. Keep this file secret.\n\nCreated tunnel {name} with id {id}",
                    path.display()
                );
            }
        }
        "tunnel list" => {
            let query = filters::tunnels(&invocation)?;
            let values = output::tunnel_rows(client.tunnels(query).await?)?;
            print!("{}", output::tunnels(&invocation, values, &logger)?);
        }
        "tunnel info" => {
            let id = client
                .resolve_tunnel(argument(&invocation, 0, "tunnel ID or name")?)
                .await?;
            let mut clients = output::client_rows(client.connections(id).await?)?;
            if let Some(clients) = &mut clients {
                output::sort_clients(&invocation, clients, &logger);
            }
            let mut tunnels =
                output::tunnel_rows(client.tunnels(vec![("uuid", id.to_string())]).await?)?;
            if tunnels.len() != 1 {
                bail!(
                    "Expected to find a single tunnel with uuid {id} but found {} tunnels.",
                    tunnels.len()
                );
            }
            let tunnel = tunnels.remove(0);
            print!(
                "{}",
                output::info(
                    &invocation,
                    &models::Info {
                        id: tunnel.id,
                        name: tunnel.name,
                        created_at: tunnel.created_at,
                        conns: clients
                    },
                )?
            );
        }
        "tunnel token" => {
            let id = client
                .resolve_tunnel(argument(&invocation, 0, "tunnel ID or name")?)
                .await?;
            let token = client.token(id).await?;
            if invocation.string("credentials-file").is_empty() {
                println!("{token}");
            } else {
                let creds = crate::config::credentials_from_token(&token)?;
                let body = serde_json::to_vec(
                    &json!({"AccountTag":creds.account_tag,"TunnelSecret":STANDARD.encode(&creds.tunnel_secret),"TunnelID":creds.tunnel_id,"Endpoint":creds.endpoint}),
                )?;
                credentials::atomic_create(
                    &expanded(invocation.string("credentials-file"))?,
                    &body,
                    0o400,
                )?;
            }
        }
        "tunnel delete" => {
            if invocation.args.is_empty() {
                bail!("at least one tunnel ID or name required");
            }
            for id in client.resolve_tunnels(&invocation.args).await? {
                let tunnel = client.tunnel(id).await?;
                if tunnel["deleted_at"]
                    .as_str()
                    .is_some_and(|time| !time.is_empty() && !time.starts_with("0001-"))
                {
                    bail!("Tunnel {id} has already been deleted");
                }
                client.delete(id, invocation.bool("force")).await?;
                let path = if invocation.string("credentials-file").is_empty() {
                    cert_path.parent().unwrap().join(format!("{id}.json"))
                } else {
                    expanded(invocation.string("credentials-file"))?
                };
                if path.is_file() && std::fs::remove_file(path).is_err() {
                    eprintln!("Tunnel {id} was deleted but credentials could not be removed");
                }
            }
        }
        "tunnel cleanup" => {
            if invocation.args.is_empty() {
                bail!("at least one tunnel ID or name required");
            }
            let ids = client.resolve_tunnels(&invocation.args).await?;
            let connector = if invocation.string("connector-id").is_empty() {
                None
            } else {
                Some(invocation.string("connector-id").parse()?)
            };
            for id in ids {
                let extra =
                    connector.map_or_else(String::new, |id| format!(" for connector-id {id}"));
                let _ = logger.log(
                    crate::observability::logging::Level::Info,
                    crate::observability::logging::Event::Cloudflared,
                    &format!("Cleanup connection for tunnel {id}{extra}"),
                    Value::Null,
                );
                if let Err(error) = client.cleanup(id, connector).await {
                    let _ = logger.log(
                        crate::observability::logging::Level::Error,
                        crate::observability::logging::Event::Cloudflared,
                        &format!("Error cleaning up connections for tunnel {id}, error :{error}"),
                        Value::Null,
                    );
                }
            }
        }
        "tunnel route dns" | "tunnel route lb" => {
            let id = client
                .resolve_tunnel(argument(&invocation, 0, "tunnel ID or name")?)
                .await?;
            let body = if invocation.command.ends_with("dns") {
                json!({"type":"dns","user_hostname":argument(&invocation,1,"hostname")?,"overwrite_existing":invocation.bool("overwrite-dns")})
            } else {
                json!({"type":"lb","lb_name":argument(&invocation,1,"load balancer name")?,"lb_pool":argument(&invocation,2,"pool name")?})
            };
            render(&invocation, &client.hostname_route(id, body).await?)?;
        }
        command if command.starts_with("tunnel route ip ") => {
            execute_routes(&client, &invocation).await?
        }
        command if command.starts_with("tunnel vnet ") => {
            execute_vnets(&client, &invocation).await?
        }
        _ => bail!("unsupported administration command"),
    }
    Ok(())
}

async fn create_with_credentials(
    client: &AccountClient,
    name: &str,
    secret: Vec<u8>,
    explicit_path: &str,
    cert_path: &std::path::Path,
) -> Result<(Value, crate::config::Credentials, PathBuf)> {
    let tunnel = client.create(name, &secret).await?;
    let id: Uuid = tunnel["id"]
        .as_str()
        .context("API returned no tunnel ID")?
        .parse()?;
    let path = if explicit_path.is_empty() {
        cert_path
            .parent()
            .unwrap_or(std::path::Path::new("."))
            .join(format!("{id}.json"))
    } else {
        expanded(explicit_path)?
    };
    let body = serde_json::to_vec(
        &json!({"AccountTag":client.account(),"TunnelSecret":STANDARD.encode(&secret),"TunnelID":id,"Endpoint":client.endpoint()}),
    )?;
    if let Err(error) = credentials::atomic_create(&path, &body, 0o400) {
        let rollback = client.delete(id, true).await;
        bail!(
            "Tunnel {id} was created but credentials could not be saved: {error}. Cleanup {}.",
            if rollback.is_ok() {
                "deleted the tunnel"
            } else {
                "failed; delete the tunnel manually"
            }
        );
    }
    Ok((
        tunnel,
        crate::config::Credentials {
            account_tag: client.account().to_owned(),
            tunnel_secret: secret,
            tunnel_id: id,
            endpoint: Some(client.endpoint().to_owned()),
        },
        path,
    ))
}

pub async fn prepare_adhoc(invocation: &Invocation) -> Result<crate::config::Credentials> {
    let path = credentials::cert_path(invocation.string("origincert"))?;
    let client = AccountClient::new(
        credentials::AccountCredentials::read(&path)?,
        invocation.string("api-url"),
    )?;
    prepare_adhoc_with_client(invocation, &client, &path).await
}
async fn prepare_adhoc_with_client(
    invocation: &Invocation,
    client: &AccountClient,
    cert_path: &std::path::Path,
) -> Result<crate::config::Credentials> {
    let name = invocation.string("name");
    if name.is_empty() {
        bail!("ad-hoc named tunnel requires --name");
    }
    let logger = crate::observability::logging::Logger::new(
        crate::observability::logging::Options {
            level: crate::observability::logging::Level::parse(invocation.string("loglevel"))
                .unwrap_or_default(),
            ..Default::default()
        },
        vec![],
    )?;
    let active = client
        .tunnels(vec![("name", name.into()), ("is_deleted", "false".into())])
        .await;
    let credentials = if let Ok(tunnels) = active
        && let Some(tunnel) = tunnels.first()
    {
        let id: Uuid = tunnel["id"]
            .as_str()
            .context("API returned no tunnel ID")?
            .parse()?;
        let file = if invocation.string("credentials-file").is_empty() {
            None
        } else {
            Some(expanded(invocation.string("credentials-file"))?)
        };
        let home = std::env::var_os("HOME").map(PathBuf::from);
        crate::config::resolve_credentials(
            None,
            None,
            None,
            file.as_deref(),
            &id.to_string(),
            Some(cert_path),
            &crate::config::search_directories(home.as_deref()),
        )?
        .0
    } else {
        let mut secret = vec![0; 32];
        boring::rand::rand_bytes(&mut secret)?;
        create_with_credentials(
            client,
            name,
            secret,
            invocation.string("credentials-file"),
            cert_path,
        )
        .await?
        .1
    };
    let hostname = invocation.string("hostname");
    if !hostname.is_empty() {
        let body = if invocation.string("lb-pool").is_empty() {
            json!({"type":"dns","user_hostname":hostname,"overwrite_existing":invocation.bool("overwrite-dns")})
        } else {
            json!({"type":"lb","lb_name":hostname,"lb_pool":invocation.string("lb-pool")})
        };
        if let Err(error) = client.hostname_route(credentials.tunnel_id, body).await {
            let _ = logger.log(
                crate::observability::logging::Level::Error,
                crate::observability::logging::Event::Cloudflared,
                "Unable to route named tunnel",
                json!({"error":error.to_string()}),
            );
        }
    }
    Ok(credentials)
}

fn argument<'a>(invocation: &'a Invocation, index: usize, label: &str) -> Result<&'a str> {
    invocation
        .args
        .get(index)
        .map(String::as_str)
        .with_context(|| format!("missing {label}"))
}
fn expanded(path: &str) -> Result<PathBuf> {
    crate::config::expand_home(
        path,
        std::env::var_os("HOME")
            .as_deref()
            .map(std::path::Path::new),
    )
}
fn output_format(invocation: &Invocation) -> Option<&str> {
    match output::format(invocation) {
        "" => None,
        value => Some(value),
    }
}
fn render(invocation: &Invocation, value: &Value) -> Result<()> {
    match invocation.command.as_str() {
        "tunnel vnet list" => {
            print!("{}", output::vnets(invocation, value)?);
            return Ok(());
        }
        "tunnel route ip list" | "tunnel route ip show" => {
            print!("{}", output::routes(invocation, value)?);
            return Ok(());
        }
        _ => {}
    }
    match output_format(invocation) {
        Some("json") => println!("{}", serde_json::to_string_pretty(value)?),
        Some("yaml") => print!("{}", serde_yaml_ng::to_string(value)?),
        Some(_) => bail!("output format must be json or yaml"),
        None => print!("{}", expand_tabs(&text_output(invocation, value))),
    }
    Ok(())
}

fn expand_tabs(input: &str) -> String {
    let mut widths = Vec::new();
    for line in input.lines().filter(|line| line.contains('\t')) {
        for (column, value) in line.split('\t').enumerate() {
            if column >= widths.len() {
                widths.push(0);
            }
            widths[column] = widths[column].max(value.chars().count() + 1);
        }
    }
    let mut output = String::new();
    for line in input.lines() {
        let columns = line.split('\t').collect::<Vec<_>>();
        for (index, column) in columns.iter().enumerate() {
            output.push_str(column);
            if index + 1 < columns.len() {
                output.extend(std::iter::repeat_n(
                    ' ',
                    widths[index].saturating_sub(column.chars().count()),
                ));
            }
        }
        output.push('\n');
    }
    output
}

fn connection_summary(connections: &Value, show_recent: bool) -> String {
    let mut colos = std::collections::BTreeMap::<&str, usize>::new();
    for connection in connections.as_array().into_iter().flatten() {
        if show_recent || connection["is_pending_reconnect"] != true {
            *colos
                .entry(connection["colo_name"].as_str().unwrap_or(""))
                .or_default() += 1;
        }
    }
    colos
        .into_iter()
        .map(|(colo, count)| format!("{count}x{colo}"))
        .collect::<Vec<_>>()
        .join(", ")
}
fn text(value: &Value, field: &str) -> String {
    match &value[field] {
        Value::Null => String::new(),
        Value::String(value) => value.clone(),
        value => value.to_string(),
    }
}
fn text_output(invocation: &Invocation, value: &Value) -> String {
    let rows = value
        .as_array()
        .cloned()
        .unwrap_or_else(|| vec![value.clone()]);
    let show_recent = invocation.bool("show-recently-disconnected");
    let mut output = String::new();
    match invocation.command.as_str() {
        "tunnel list" => {
            if rows.is_empty() {
                return "You have no tunnels, you can use 'cloudflared tunnel create' to create a tunnel\n".into();
            }
            output.push_str("You can obtain more detailed information for each tunnel with `cloudflared tunnel info <name/uuid>`\nID\tNAME\tCREATED\tCONNECTIONS\n");
            for row in rows {
                output.push_str(&format!(
                    "{}\t{}\t{}\t{}\n",
                    text(&row, "id"),
                    text(&row, "name"),
                    text(&row, "created_at"),
                    connection_summary(&row["connections"], show_recent)
                ));
            }
        }
        "tunnel info" => {
            let clients = value["conns"].as_array().cloned().unwrap_or_default();
            if clients.is_empty() {
                return format!(
                    "Your tunnel {} does not have any active connection.\n",
                    text(value, "id")
                );
            }
            output.push_str(&format!(
                "NAME:     {}\nID:       {}\nCREATED:  {}\n\n",
                text(value, "name"),
                text(value, "id"),
                text(value, "createdAt")
            ));
            output.push_str("CONNECTOR ID\tCREATED\tARCHITECTURE\tVERSION\tORIGIN IP\tEDGE\n");
            for row in clients {
                let summary = connection_summary(&row["conns"], show_recent);
                if !summary.is_empty() {
                    output.push_str(&format!(
                        "{}\t{}\t{}\t{}\t{}\t{}\n",
                        text(&row, "id"),
                        text(&row, "run_at"),
                        text(&row, "arch"),
                        text(&row, "version"),
                        row["conns"][0]["origin_ip"].as_str().unwrap_or(""),
                        summary
                    ));
                }
            }
        }
        "tunnel route dns" => {
            let name = value["name"]
                .as_str()
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| invocation.args.get(1).map(String::as_str).unwrap_or(""));
            output = match value["cname"].as_str() {
                Some("new") => format!("Added CNAME {name} which will route to this tunnel\n"),
                Some("updated") => format!("{name} updated to route to your tunnel\n"),
                Some("unchanged") => {
                    format!("{name} is already configured to route to your tunnel\n")
                }
                _ => format!("DNS route result for {name}: {}\n", value["cname"]),
            };
        }
        command if command.starts_with("tunnel route ip") => {
            if command.ends_with("add") {
                return format!(
                    "Successfully added route for {} over tunnel {}\n",
                    text(value, "network"),
                    text(value, "tunnel_id")
                );
            }
            if command.ends_with("delete") {
                return format!("Successfully deleted route with ID {}\n", text(value, "id"));
            }
            if rows.is_empty() {
                return "No routes were found for the given filter flags. You can use 'cloudflared tunnel route ip add' to add a route.\n".into();
            }
            output.push_str(
                "ID\tNETWORK\tVIRTUAL NET ID\tCOMMENT\tTUNNEL ID\tTUNNEL NAME\tCREATED\tDELETED\n",
            );
            for row in rows {
                output.push_str(&format!(
                    "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
                    text(&row, "id"),
                    text(&row, "network"),
                    row["virtual_network_id"].as_str().unwrap_or("default"),
                    text(&row, "comment"),
                    text(&row, "tunnel_id"),
                    text(&row, "tunnel_name"),
                    text(&row, "created_at"),
                    row["deleted_at"]
                        .as_str()
                        .filter(|s| !s.starts_with("0001-"))
                        .unwrap_or("-")
                ));
            }
        }
        command if command.starts_with("tunnel vnet") => {
            if command.ends_with("add") {
                return format!(
                    "Successfully added virtual 'network' {} with ID: {}\nYou can now add IP routes attached to this virtual network. See `cloudflared tunnel route ip add -help`\n",
                    text(value, "name"),
                    text(value, "id")
                );
            }
            if command.ends_with("delete") || command.ends_with("update") {
                return format!(
                    "Successfully {} virtual network '{}'\n",
                    if command.ends_with("delete") {
                        "deleted"
                    } else {
                        "updated"
                    },
                    invocation.args.first().map(String::as_str).unwrap_or("")
                );
            }
            if rows.is_empty() {
                return "No virtual networks were found for the given filter flags. You can use 'cloudflared tunnel vnet add' to add a virtual network.\n".into();
            }
            output.push_str("ID\tNAME\tIS DEFAULT\tCOMMENT\tCREATED\tDELETED\n");
            for row in rows {
                output.push_str(&format!(
                    "{}\t{}\t{}\t{}\t{}\t{}\n",
                    text(&row, "id"),
                    text(&row, "name"),
                    text(&row, "is_default_network"),
                    text(&row, "comment"),
                    text(&row, "created_at"),
                    row["deleted_at"]
                        .as_str()
                        .filter(|s| !s.starts_with("0001-"))
                        .unwrap_or("-")
                ));
            }
        }
        _ => output = format!("{value}\n"),
    }
    output
}
async fn resolve_vnet(client: &AccountClient, name: &str) -> Result<Uuid> {
    if let Ok(id) = name.parse() {
        return Ok(id);
    }
    let result = client
        .vnets(
            http::Method::GET,
            "",
            &[("name", name.into()), ("is_deleted", "false".into())],
            None,
        )
        .await?;
    result
        .as_array()
        .and_then(|rows| rows.first())
        .and_then(|v| v["id"].as_str())
        .context("virtual network name not found")?
        .parse()
        .context("invalid virtual network ID")
}
async fn vnet_query(
    client: &AccountClient,
    invocation: &Invocation,
) -> Result<Vec<(&'static str, String)>> {
    if invocation.string("vnet").is_empty() {
        Ok(vec![])
    } else {
        Ok(vec![(
            "virtual_network_id",
            resolve_vnet(client, invocation.string("vnet"))
                .await?
                .to_string(),
        )])
    }
}

async fn execute_vnets(client: &AccountClient, invocation: &Invocation) -> Result<()> {
    let mut query = Vec::new();
    let (method, suffix, body) = match invocation.command.as_str() {
        "tunnel vnet add" => (
            http::Method::POST,
            String::new(),
            Some(
                json!({"name":argument(invocation,0,"virtual network name")?,"comment":invocation.args.get(1).map(String::as_str).unwrap_or(""),"is_default_network":invocation.bool("default")}),
            ),
        ),
        "tunnel vnet list" => {
            query = filters::vnets(invocation)?;
            (http::Method::GET, String::new(), None)
        }
        "tunnel vnet delete" => {
            if invocation.bool("force") {
                query.push(("force", "true".into()));
            }
            (
                http::Method::DELETE,
                format!(
                    "/{}",
                    resolve_vnet(
                        client,
                        argument(invocation, 0, "virtual network ID or name")?
                    )
                    .await?
                ),
                None,
            )
        }
        "tunnel vnet update" => {
            let mut body = serde_json::Map::new();
            for flag in ["name", "comment"] {
                if invocation.is_set(flag) {
                    body.insert(flag.into(), Value::String(invocation.string(flag).into()));
                }
            }
            if invocation.bool("default") {
                body.insert("is_default_network".into(), Value::Bool(true));
            }
            (
                http::Method::PATCH,
                format!(
                    "/{}",
                    resolve_vnet(
                        client,
                        argument(invocation, 0, "virtual network ID or name")?
                    )
                    .await?
                ),
                Some(Value::Object(body)),
            )
        }
        _ => bail!("unsupported virtual network command"),
    };
    render(
        invocation,
        &client.vnets(method, &suffix, &query, body).await?,
    )
}

async fn execute_routes(client: &AccountClient, invocation: &Invocation) -> Result<()> {
    let listing = matches!(
        invocation.command.as_str(),
        "tunnel route ip show" | "tunnel route ip list"
    );
    if listing && invocation.is_set("vnet") {
        bail!("--vnet does not apply to route listing; use --filter-vnet-id");
    }
    let mut query = if listing {
        Vec::new()
    } else {
        vnet_query(client, invocation).await?
    };
    let (method, suffix, body) = match invocation.command.as_str() {
        "tunnel route ip add" => {
            let network = argument(invocation, 0, "network CIDR")?
                .parse::<ipnet::IpNet>()
                .context("invalid network CIDR")?
                .trunc();
            let id = client
                .resolve_tunnel(argument(invocation, 1, "tunnel ID or name")?)
                .await?;
            let mut body = json!({"network":network.to_string(),"tunnel_id":id,"comment":invocation.args.get(2).map(String::as_str).unwrap_or("")});
            if let Some((_, id)) = query.first() {
                body["virtual_network_id"] = Value::String(id.clone());
            }
            query.clear();
            (http::Method::POST, String::new(), Some(body))
        }
        "tunnel route ip show" | "tunnel route ip list" => {
            query = filters::routes(invocation)?;
            (http::Method::GET, String::new(), None)
        }
        "tunnel route ip get" => {
            let ip = argument(invocation, 0, "IP address")?
                .parse::<std::net::IpAddr>()
                .context("invalid IP address")?;
            (http::Method::GET, format!("/ip/{ip}"), None)
        }
        "tunnel route ip delete" => {
            let input = argument(invocation, 0, "route ID or CIDR")?;
            let id = if let Ok(id) = input.parse::<Uuid>() {
                id
            } else {
                let network = input.parse::<ipnet::IpNet>()?.trunc().to_string();
                let mut filter = query.clone();
                filter.extend([
                    ("tun_types", "cfd_tunnel".into()),
                    ("is_deleted", "false".into()),
                    ("network_subset", network.clone()),
                    ("network_superset", network),
                ]);
                let rows = client.routes(http::Method::GET, "", &filter, None).await?;
                let rows = rows.as_array().context("invalid route list")?;
                if rows.len() != 1 {
                    bail!("CIDR does not identify exactly one active route");
                }
                rows[0]["id"].as_str().context("route has no ID")?.parse()?
            };
            query.clear();
            (http::Method::DELETE, format!("/{id}"), None)
        }
        _ => bail!("unsupported IP route command"),
    };
    render(
        invocation,
        &client.routes(method, &suffix, &query, body).await?,
    )
}

#[cfg(test)]
mod tests;
