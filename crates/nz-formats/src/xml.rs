//! A minimal, bounded XML reader for archive tables of contents (XAR TOC,
//! DMG property lists). Elements, attributes and text only; no DTDs.

use anyhow::{Result, bail};

#[derive(Debug, Default, Clone)]
pub struct Node {
    pub name: String,
    pub attrs: Vec<(String, String)>,
    pub text: String,
    pub children: Vec<Node>,
}

impl Node {
    pub fn child(&self, name: &str) -> Option<&Node> {
        self.children.iter().find(|c| c.name == name)
    }
    pub fn children<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Node> + 'a {
        self.children.iter().filter(move |c| c.name == name)
    }
    pub fn attr(&self, name: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|a| a.0 == name)
            .map(|a| a.1.as_str())
    }
    pub fn child_text(&self, name: &str) -> Option<&str> {
        self.child(name).map(|c| c.text.trim())
    }
}

fn unescape(s: &str) -> String {
    if !s.contains('&') {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        rest = &rest[i..];
        let Some(end) = rest.find(';').filter(|e| *e < 12) else {
            out.push('&');
            rest = &rest[1..];
            continue;
        };
        let ent = &rest[1..end];
        let c = match ent {
            "lt" => Some('<'),
            "gt" => Some('>'),
            "amp" => Some('&'),
            "quot" => Some('"'),
            "apos" => Some('\u{27}'),
            _ if ent.starts_with("#x") => u32::from_str_radix(&ent[2..], 16)
                .ok()
                .and_then(char::from_u32),
            _ if ent.starts_with('#') => ent[1..].parse().ok().and_then(char::from_u32),
            _ => None,
        };
        match c {
            Some(c) => out.push(c),
            None => out.push_str(&rest[..=end]),
        }
        rest = &rest[end + 1..];
    }
    out.push_str(rest);
    out
}

/// Parse a document and return its root element.
pub fn parse(doc: &str) -> Result<Node> {
    let mut stack: Vec<Node> = vec![Node::default()];
    let mut rest = doc;
    let mut count = 0usize;
    while !rest.is_empty() {
        let Some(lt) = rest.find('<') else {
            break;
        };
        if lt > 0 {
            let top = stack.last_mut().expect("stack never empty");
            top.text.push_str(&unescape(&rest[..lt]));
        }
        rest = &rest[lt..];
        if let Some(r) = rest.strip_prefix("<!--") {
            let Some(e) = r.find("-->") else {
                bail!("unterminated comment")
            };
            rest = &r[e + 3..];
            continue;
        }
        if let Some(r) = rest.strip_prefix("<![CDATA[") {
            let Some(e) = r.find("]]>") else {
                bail!("unterminated CDATA")
            };
            stack
                .last_mut()
                .expect("stack never empty")
                .text
                .push_str(&r[..e]);
            rest = &r[e + 3..];
            continue;
        }
        if rest.starts_with("<?") || rest.starts_with("<!") {
            let Some(e) = rest.find('>') else {
                bail!("unterminated declaration")
            };
            rest = &rest[e + 1..];
            continue;
        }
        let Some(gt) = rest.find('>') else {
            bail!("unterminated tag")
        };
        let tag = &rest[1..gt];
        rest = &rest[gt + 1..];
        if let Some(name) = tag.strip_prefix('/') {
            let name = name.trim();
            if stack.len() < 2 {
                bail!("unbalanced </{name}>");
            }
            let node = stack.pop().expect("checked length");
            if node.name != name {
                bail!("mismatched </{name}>");
            }
            stack
                .last_mut()
                .expect("stack never empty")
                .children
                .push(node);
            continue;
        }
        count += 1;
        if count > 4_000_000 || stack.len() > 512 {
            bail!("XML document too large or deep");
        }
        let self_close = tag.ends_with('/');
        let tag = tag.trim_end_matches('/');
        let (name, mut attrs_s) = match tag.find(char::is_whitespace) {
            Some(i) => (&tag[..i], &tag[i..]),
            None => (tag, ""),
        };
        let mut node = Node {
            name: name.to_string(),
            ..Default::default()
        };
        loop {
            attrs_s = attrs_s.trim_start();
            let Some(eq) = attrs_s.find('=') else { break };
            let key = attrs_s[..eq].trim().to_string();
            let v = attrs_s[eq + 1..].trim_start();
            let Some(q) = v.chars().next().filter(|c| *c == '"' || *c == '\u{27}') else {
                break;
            };
            let Some(end) = v[1..].find(q) else { break };
            node.attrs.push((key, unescape(&v[1..1 + end])));
            attrs_s = &v[end + 2..];
        }
        if self_close {
            stack
                .last_mut()
                .expect("stack never empty")
                .children
                .push(node);
        } else {
            stack.push(node);
        }
    }
    if stack.len() != 1 {
        bail!("unterminated element");
    }
    let mut root = stack.pop().expect("one element");
    let r = root.children.pop();
    match r {
        Some(r) if root.children.is_empty() => Ok(r),
        _ => bail!("no single root element"),
    }
}
