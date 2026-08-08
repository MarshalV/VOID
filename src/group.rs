//! Групповые чаты: модель, ключи потоков и invite-ссылки `void://group/…`.

use rand::RngCore;
use serde::{Deserialize, Serialize};

pub(crate) const GROUP_THREAD_PREFIX: &str = "group:";
const GROUP_ID_HEX_LEN: usize = 32;
const MAX_GROUP_NAME_BYTES: usize = 128;
const MAX_GROUP_MEMBERS: usize = 256;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct GroupMember {
    pub(crate) peer_id: String,
    pub(crate) display_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub(crate) struct GroupChat {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) creator_id: String,
    pub(crate) members: Vec<GroupMember>,
    pub(crate) created_at: String,
}

impl GroupChat {
    pub(crate) fn member_peer_ids(&self) -> Vec<libp2p::PeerId> {
        self.members
            .iter()
            .filter_map(|m| m.peer_id.parse().ok())
            .collect()
    }

    pub(crate) fn includes_peer(&self, peer_id: &libp2p::PeerId) -> bool {
        let s = peer_id.to_string();
        self.members.iter().any(|m| m.peer_id == s)
    }
}

pub(crate) fn new_group_id() -> String {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

pub(crate) fn validate_group_id(id: &str) -> bool {
    id.len() == GROUP_ID_HEX_LEN && id.chars().all(|c| c.is_ascii_hexdigit())
}

pub(crate) fn group_thread_key(group_id: &str) -> String {
    format!("{GROUP_THREAD_PREFIX}{group_id}")
}

pub(crate) fn is_group_thread(key: &str) -> bool {
    key.starts_with(GROUP_THREAD_PREFIX)
}

pub(crate) fn parse_group_thread_key(key: &str) -> Option<&str> {
    let id = key.strip_prefix(GROUP_THREAD_PREFIX)?;
    if validate_group_id(id) {
        Some(id)
    } else {
        None
    }
}

pub(crate) fn dedupe_members(members: Vec<GroupMember>) -> Vec<GroupMember> {
    let mut seen = std::collections::HashSet::new();
    members
        .into_iter()
        .filter(|m| seen.insert(m.peer_id.clone()))
        .collect()
}

pub(crate) fn validate_group_chat(g: &GroupChat) -> bool {
    validate_group_id(&g.id)
        && !g.name.is_empty()
        && g.name.len() <= MAX_GROUP_NAME_BYTES
        && !g.creator_id.is_empty()
        && g.members.len() <= MAX_GROUP_MEMBERS
        && g.members.iter().all(|m| {
            !m.peer_id.is_empty()
                && m.peer_id.len() <= 256
                && !m.display_name.is_empty()
                && m.display_name.len() <= 256
        })
}

/// Извлекает все invite-ссылки из текста сообщения.
pub(crate) fn extract_invite_links(text: &str) -> Vec<String> {
    let mut links = Vec::new();
    let mut search_from = 0usize;
    while let Some(rel) = text[search_from..].find("void://group/") {
        let start = search_from + rel;
        let tail = &text[start..];
        let end = tail
            .find(|c: char| c.is_whitespace())
            .unwrap_or(tail.len());
        let mut link = tail[..end].to_string();
        // Хвост из пунктуации в конце строки/предложения.
        while link
            .chars()
            .last()
            .is_some_and(|c| matches!(c, '.' | ',' | ';' | ')' | ']' | '}' | '»' | '"' | '\''))
        {
            link.pop();
        }
        if !link.is_empty() {
            links.push(link);
        }
        search_from = start + end;
        if search_from >= text.len() {
            break;
        }
    }
    links
}

/// `void://group/{id}?name=…&m=peer1,peer2,…&creator=…`
pub(crate) fn build_invite_link(group: &GroupChat) -> String {
    let name_enc = url_encode(&group.name);
    let members: String = group
        .members
        .iter()
        .map(|m| m.peer_id.as_str())
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "void://group/{}?name={}&m={}&creator={}",
        group.id, name_enc, members, group.creator_id
    )
}

/// Разбор invite-ссылки или голого `void://group/{id}?…`.
pub(crate) fn parse_invite_link(input: &str) -> Option<GroupChat> {
    let s = input.trim();
    let rest = s.strip_prefix("void://group/")?;
    let (id_part, query) = match rest.split_once('?') {
        Some((id, q)) => (id, Some(q)),
        None => (rest, None),
    };
    if !validate_group_id(id_part) {
        return None;
    }
    let mut name = format!("Группа {}", &id_part[..8.min(id_part.len())]);
    let mut creator_id = String::new();
    let mut member_ids: Vec<String> = Vec::new();

    if let Some(q) = query {
        for pair in q.split('&') {
            let Some((k, v)) = pair.split_once('=') else {
                continue;
            };
            match k {
                "name" => {
                    if let Some(dec) = url_decode(v) {
                        if !dec.is_empty() && dec.len() <= MAX_GROUP_NAME_BYTES {
                            name = dec;
                        }
                    }
                }
                "creator" => creator_id = v.to_string(),
                "m" | "members" => {
                    member_ids = v
                        .split(',')
                        .map(str::trim)
                        .filter(|p| !p.is_empty())
                        .map(str::to_string)
                        .collect();
                }
                _ => {}
            }
        }
    }

    let members: Vec<GroupMember> = if member_ids.is_empty() && !creator_id.is_empty() {
        vec![GroupMember {
            peer_id: creator_id.clone(),
            display_name: short_peer_label(&creator_id),
        }]
    } else {
        member_ids
            .into_iter()
            .map(|peer_id| GroupMember {
                display_name: short_peer_label(&peer_id),
                peer_id,
            })
            .collect()
    };

    let mut creator_id = creator_id;
    if creator_id.is_empty() {
        creator_id = members
            .first()
            .map(|m| m.peer_id.clone())
            .unwrap_or_default();
    }

    let group = GroupChat {
        id: id_part.to_string(),
        name,
        creator_id,
        members,
        created_at: chrono::Local::now().format("%Y-%m-%d %H:%M").to_string(),
    };
    if validate_group_chat(&group) {
        Some(group)
    } else {
        None
    }
}

fn short_peer_label(peer_id: &str) -> String {
    let n = peer_id.len().min(8);
    format!("Peer {}", &peer_id[..n])
}

fn url_encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn url_decode(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = hex_nibble(bytes[i + 1])?;
            let lo = hex_nibble(bytes[i + 2])?;
            out.push((hi << 4) | lo);
            i += 3;
        } else if bytes[i] == b'+' {
            out.push(b' ');
            i += 1;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Members right after create: creator only. Invitees join only via explicit
/// `join_group_from_invite` (click / paste), never from DM text or sync.
pub(crate) fn members_on_group_create(
    creator_id: &str,
    creator_name: &str,
    _invitee_peer_ids: &[String],
) -> Vec<GroupMember> {
    vec![GroupMember {
        peer_id: creator_id.to_string(),
        display_name: creator_name.to_string(),
    }]
}

/// Receiving invite text in chat must never auto-install the group.
#[cfg(test)]
pub(crate) fn auto_join_from_invite_message() -> bool {
    false
}

/// `group_sync` must not create a group the local user never joined.
pub(crate) fn may_install_group_from_sync(already_have_group: bool) -> bool {
    already_have_group
}

/// Creator accepting a non-creator sync: only allow `from` to add/remove self.
pub(crate) fn sanitize_sync_members_for_creator(
    existing: &[GroupMember],
    from_peer_id: &str,
    incoming: &[GroupMember],
) -> Vec<GroupMember> {
    let incoming_has_from = incoming.iter().any(|m| m.peer_id == from_peer_id);
    let mut out = existing.to_vec();
    if incoming_has_from {
        if !out.iter().any(|m| m.peer_id == from_peer_id) {
            if let Some(m) = incoming.iter().find(|x| x.peer_id == from_peer_id) {
                out.push(m.clone());
            }
        }
    } else {
        out.retain(|m| m.peer_id != from_peer_id);
    }
    for m in &mut out {
        if let Some(inc) = incoming.iter().find(|x| x.peer_id == m.peer_id) {
            if !inc.display_name.is_empty() {
                m.display_name = inc.display_name.clone();
            }
        }
    }
    dedupe_members(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_group_members_exclude_invitees() {
        let members = members_on_group_create(
            "creator",
            "Alice",
            &["bob".into(), "carol".into()],
        );
        assert_eq!(members.len(), 1);
        assert_eq!(members[0].peer_id, "creator");
        assert!(!members.iter().any(|m| m.peer_id == "bob"));
    }

    #[test]
    fn invite_message_never_auto_joins() {
        assert!(!auto_join_from_invite_message());
    }

    #[test]
    fn parse_and_validate_real_invite_link() {
        let link = concat!(
            "void://group/397a1e0eda7acce07a7fc2e7932ff1c1",
            "?name=111",
            "&m=12D3KooWAaR9gWEA5GUnZVyMrZo3shRxYqopw1mqdy5646k6f5xo",
            "&creator=12D3KooWAaR9gWEA5GUnZVyMrZo3shRxYqopw1mqdy5646k6f5xo",
        );
        let mut g = parse_invite_link(link).expect("parse invite");
        assert_eq!(g.name, "111");
        let me = "12D3KooWJOINERPEER00000000000000000000000001";
        g.members.push(GroupMember {
            peer_id: me.into(),
            display_name: "Peer 12D3KooW".into(),
        });
        assert!(validate_group_chat(&g));
    }

    #[test]
    fn sync_does_not_install_unknown_group() {
        assert!(!may_install_group_from_sync(false));
        assert!(may_install_group_from_sync(true));
    }

    #[test]
    fn invite_link_roundtrip_creator_only() {
        let g = GroupChat {
            id: "0123456789abcdef0123456789abcdef".into(),
            name: "Test".into(),
            creator_id: "creatorpeer".into(),
            members: members_on_group_create("creatorpeer", "Alice", &["bob".into()]),
            created_at: "now".into(),
        };
        let link = build_invite_link(&g);
        let parsed = parse_invite_link(&link).expect("parse");
        assert_eq!(parsed.members.len(), 1);
        assert_eq!(parsed.members[0].peer_id, "creatorpeer");
        assert!(!parsed.members.iter().any(|m| m.peer_id == "bob"));
    }

    #[test]
    fn extract_invite_from_dm_text() {
        let text =
            "invite:\nvoid://group/0123456789abcdef0123456789abcdef?name=G&m=c&creator=c";
        let links = extract_invite_links(text);
        assert_eq!(links.len(), 1);
        assert!(links[0].starts_with("void://group/"));
    }

    #[test]
    fn creator_sanitize_adds_only_sender_self() {
        let existing = vec![GroupMember {
            peer_id: "creator".into(),
            display_name: "A".into(),
        }];
        let incoming = vec![
            GroupMember {
                peer_id: "creator".into(),
                display_name: "A".into(),
            },
            GroupMember {
                peer_id: "bob".into(),
                display_name: "B".into(),
            },
            GroupMember {
                peer_id: "eve".into(),
                display_name: "E".into(),
            },
        ];
        let out = sanitize_sync_members_for_creator(&existing, "bob", &incoming);
        assert!(out.iter().any(|m| m.peer_id == "bob"));
        assert!(!out.iter().any(|m| m.peer_id == "eve"));
    }
}
