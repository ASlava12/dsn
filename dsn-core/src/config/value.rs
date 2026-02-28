use anyhow::{Result, anyhow, bail};
use serde_json::Value;

pub fn set_in_value(root: &mut Value, key_path: &str, value: Value) -> Result<()> {
    let parts: Vec<_> = key_path
        .split('.')
        .filter(|part| !part.is_empty())
        .collect();
    if parts.is_empty() {
        bail!("parameter path cannot be empty");
    }

    let mut current = root;
    for part in &parts[..parts.len() - 1] {
        if !current.is_object() {
            *current = Value::Object(Default::default());
        }
        current = current
            .as_object_mut()
            .expect("object enforced")
            .entry((*part).to_owned())
            .or_insert_with(|| Value::Object(Default::default()));
    }

    current
        .as_object_mut()
        .ok_or_else(|| anyhow!("target parameter path is not an object"))?
        .insert(parts[parts.len() - 1].to_owned(), value);

    Ok(())
}

pub fn remove_in_value(root: &mut Value, key_path: &str) -> Result<()> {
    let parts: Vec<_> = key_path
        .split('.')
        .filter(|part| !part.is_empty())
        .collect();
    if parts.is_empty() {
        bail!("parameter path cannot be empty");
    }

    let mut current = root;
    for part in &parts[..parts.len() - 1] {
        current = current
            .get_mut(*part)
            .ok_or_else(|| anyhow!("parameter '{key_path}' not found"))?;
    }

    current
        .as_object_mut()
        .ok_or_else(|| anyhow!("parameter '{key_path}' parent is not an object"))?
        .remove(parts[parts.len() - 1])
        .ok_or_else(|| anyhow!("parameter '{key_path}' not found"))?;

    Ok(())
}

pub fn get_from_value<'a>(root: &'a Value, key_path: &str) -> Result<&'a Value> {
    let parts: Vec<_> = key_path
        .split('.')
        .filter(|part| !part.is_empty())
        .collect();
    if parts.is_empty() {
        bail!("parameter path cannot be empty");
    }

    let mut current = root;
    for part in parts {
        current = current
            .get(part)
            .ok_or_else(|| anyhow!("parameter '{key_path}' not found"))?;
    }

    Ok(current)
}
