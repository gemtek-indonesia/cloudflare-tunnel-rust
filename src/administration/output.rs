use super::{expand_tabs, models::*};
use crate::cli::Invocation;
use crate::observability::logging::{Event, Level, Logger};
use anyhow::{Context, Result};
use serde::Serialize;
use std::collections::BTreeMap;

#[cfg(test)]
mod tests;

pub(super) fn format(invocation: &Invocation) -> &str {
    if invocation.is_set("output") {
        invocation.string("output")
    } else {
        ""
    }
}

pub(super) fn json<T: Serialize>(value: &T) -> Result<String> {
    Ok(escape_json(serde_json::to_string_pretty(value)?) + "\n")
}

pub(super) fn compact_json<T: Serialize>(value: &T) -> Result<String> {
    Ok(escape_json(serde_json::to_string(value)?))
}

fn escape_json(value: String) -> String {
    value
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('&', "\\u0026")
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029")
}

pub(super) fn tunnel_rows(values: Vec<serde_json::Value>) -> Result<Vec<Tunnel>> {
    values
        .into_iter()
        .map(|value| {
            if !value.is_object() {
                anyhow::bail!("invalid tunnel row");
            }
            serde_json::from_value(value).context("invalid tunnel response")
        })
        .collect()
}

fn validate_rows(value: &serde_json::Value) -> Result<()> {
    if let Some(rows) = value.as_array()
        && rows.iter().any(|row| !row.is_object())
    {
        anyhow::bail!("invalid API collection row");
    }
    Ok(())
}

pub(super) fn client_rows(value: serde_json::Value) -> Result<Option<Vec<ActiveClient>>> {
    validate_rows(&value)?;
    serde_json::from_value(value).context("invalid tunnel connections")
}

pub(super) fn summary(connections: &[Connection], recent: bool) -> String {
    let mut counts = BTreeMap::new();
    for connection in connections {
        if !connection.is_pending_reconnect || recent {
            *counts
                .entry(connection.colo_name.as_str())
                .or_insert(0usize) += 1;
        }
    }
    counts
        .into_iter()
        .map(|(colo, count)| format!("{count}x{colo}"))
        .collect::<Vec<_>>()
        .join(", ")
}

pub(super) fn tunnel_table(rows: &[Tunnel], recent: bool) -> String {
    if rows.is_empty() {
        return "No tunnels were found for the given filter flags. You can use 'cloudflared tunnel create' to create a tunnel.\n".into();
    }
    let mut value = String::from(
        "You can obtain more detailed information for each tunnel with `cloudflared tunnel info <name/uuid>`\nID\tNAME\tCREATED\tCONNECTIONS\t\n",
    );
    for row in rows {
        value.push_str(&format!(
            "{}\t{}\t{}\t{}\t\n",
            row.id,
            row.name,
            row.created_at.rfc3339(false),
            summary(row.connections.as_deref().unwrap_or_default(), recent)
        ));
    }
    expand_tabs(&value)
}

pub(super) fn vnet_table(rows: &[VirtualNetwork]) -> String {
    if rows.is_empty() {
        return "No virtual networks were found for the given filter flags. You can use 'cloudflared tunnel vnet add' to add a virtual network.\n".into();
    }
    let mut value = String::from("ID\tNAME\tIS DEFAULT\tCOMMENT\tCREATED\tDELETED\t\n");
    for row in rows {
        value.push_str(&format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t\n",
            row.id,
            row.name,
            row.is_default_network,
            row.comment,
            row.created_at.rfc3339(false),
            deleted(&row.deleted_at)
        ));
    }
    expand_tabs(&value)
}

fn deleted(value: &ApiTime) -> String {
    if value == &ApiTime::default() {
        "-".into()
    } else {
        value.rfc3339(false)
    }
}

pub(super) fn route_table(rows: &[DetailedRoute]) -> String {
    if rows.is_empty() {
        return "No routes were found for the given filter flags. You can use 'cloudflared tunnel route ip add' to add a route.\n".into();
    }
    let mut value = String::from(
        "ID\tNETWORK\tVIRTUAL NET ID\tCOMMENT\tTUNNEL ID\tTUNNEL NAME\tCREATED\tDELETED\t\n",
    );
    for row in rows {
        value.push_str(&format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t\n",
            row.id,
            row.network.display(),
            row.vnet_id
                .map_or_else(|| "default".into(), |id| id.to_string()),
            row.comment,
            row.tunnel_id,
            row.tunnel_name,
            row.created_at.rfc3339(false),
            deleted(&row.deleted_at)
        ));
    }
    expand_tabs(&value)
}

pub(super) fn info_table(info: &Info, recent: bool) -> String {
    let clients = info.conns.as_deref().unwrap_or_default();
    if clients.is_empty() {
        return format!(
            "Your tunnel {} does not have any active connection.\n",
            info.id
        );
    }
    let mut value = format!(
        "NAME:     {}\nID:       {}\nCREATED:  {}\n\n",
        info.name,
        info.id,
        info.created_at.go_string()
    );
    if !clients
        .iter()
        .any(|client| !summary(client.conns.as_deref().unwrap_or_default(), recent).is_empty())
    {
        return "This tunnel has no active connectors.\n".to_owned() + &value;
    }
    value.push_str("CONNECTOR ID\tCREATED\tARCHITECTURE\tVERSION\tORIGIN IP\tEDGE\t\n");
    for client in clients {
        let connections = client.conns.as_deref().unwrap_or_default();
        let summary = summary(connections, recent);
        if !summary.is_empty() {
            value.push_str(&format!(
                "{}\t{}\t{}\t{}\t{}\t{}\t\n",
                client.id,
                client.run_at.rfc3339(false),
                client.arch,
                client.version,
                connections[0].origin_ip.display(),
                summary
            ));
        }
    }
    expand_tabs(&value)
}

fn invalid_sort(logger: &Logger, field: &str, options: &str) {
    let _ = logger.log(
        Level::Error,
        Event::Cloudflared,
        &format!("{field} is not a valid sort field. Valid sort fields are {options}. Defaulting to 'name'."),
        serde_json::Value::Null,
    );
}

pub(super) fn tunnels(
    invocation: &Invocation,
    mut rows: Vec<Tunnel>,
    logger: &Logger,
) -> Result<String> {
    let field = invocation.string("sort-by");
    let mut invalid = false;
    rows.sort_by(|a, b| match field {
        "id" => a.id.to_string().cmp(&b.id.to_string()),
        "createdAt" => a.created_at.unix().cmp(&b.created_at.unix()),
        "deletedAt" => a.deleted_at.unix().cmp(&b.deleted_at.unix()),
        "numConnections" => a
            .connections
            .as_ref()
            .map_or(0, Vec::len)
            .cmp(&b.connections.as_ref().map_or(0, Vec::len)),
        "name" => a.name.cmp(&b.name),
        _ => {
            invalid = true;
            a.name.cmp(&b.name)
        }
    });
    if invocation.bool("invert-sort") {
        rows.reverse();
    }
    if invalid {
        invalid_sort(
            logger,
            field,
            "name, id, createdAt, deletedAt, numConnections",
        );
    }
    match format(invocation) {
        "json" => json(&(!rows.is_empty()).then_some(&rows)),
        "yaml" => super::yaml::tunnels(&rows),
        "" => Ok(tunnel_table(
            &rows,
            invocation.bool("show-recently-disconnected"),
        )),
        _ => anyhow::bail!("output format must be json or yaml"),
    }
}

pub(super) fn vnets(invocation: &Invocation, value: &serde_json::Value) -> Result<String> {
    validate_rows(value)?;
    let rows: Option<Vec<VirtualNetwork>> =
        serde_json::from_value(value.clone()).context("invalid virtual network response")?;
    match format(invocation) {
        "json" => json(&rows),
        "yaml" => super::yaml::vnets(rows.as_deref().unwrap_or_default()),
        "" => Ok(vnet_table(rows.as_deref().unwrap_or_default())),
        _ => anyhow::bail!("output format must be json or yaml"),
    }
}

pub(super) fn routes(invocation: &Invocation, value: &serde_json::Value) -> Result<String> {
    validate_rows(value)?;
    let rows: Vec<DetailedRoute> =
        serde_json::from_value(value.clone()).context("invalid route response")?;
    match format(invocation) {
        "json" => json(&(!rows.is_empty()).then_some(&rows)),
        "yaml" => super::yaml::routes(&rows),
        "" => Ok(route_table(&rows)),
        _ => anyhow::bail!("output format must be json or yaml"),
    }
}

pub(super) fn sort_clients(invocation: &Invocation, rows: &mut [ActiveClient], logger: &Logger) {
    let field = invocation.string("sort-by");
    let mut invalid = false;
    rows.sort_by(|a, b| match field {
        "id" => a.id.to_string().cmp(&b.id.to_string()),
        "version" => a.version.cmp(&b.version),
        "numConnections" => a
            .conns
            .as_ref()
            .map_or(0, Vec::len)
            .cmp(&b.conns.as_ref().map_or(0, Vec::len)),
        "createdAt" => a.run_at.unix().cmp(&b.run_at.unix()),
        _ => {
            invalid = true;
            a.run_at.unix().cmp(&b.run_at.unix())
        }
    });
    if invocation.bool("invert-sort") {
        rows.reverse();
    }
    if invalid {
        invalid_sort(logger, field, "id, startedAt, numConnections, version");
    }
}

pub(super) fn info(invocation: &Invocation, info: &Info) -> Result<String> {
    match format(invocation) {
        "json" => json(info),
        "yaml" => super::yaml::info(info),
        "" => Ok(info_table(
            info,
            invocation.bool("show-recently-disconnected"),
        )),
        _ => anyhow::bail!("output format must be json or yaml"),
    }
}
