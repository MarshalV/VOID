//! Групповые чаты: модель, ключи потоков и invite-ссылки `void://group/…`.

use rand::RngCore;
use serde::{Deserialize, Serialize};

pub const GROUP_THREAD_PREFIX: &str = "group:";
const GROUP_ID_HEX_LEN: usize = 32;
const MAX_GROUP_NAME_BYTES: usize = 128;
const MAX_GROUP_MEMBERS: usize = 256;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupMember {
    pub peer_id: String,
    pub display_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GroupChat {
    pub id: String,
    pub name: String,
    pub creator_id: String,
    pub members: Vec<GroupMember>,
    pub created_at: String,
    /// Монотонная версия подписанного состава. 0 — группа ещё без подписи создателя.
    #[serde(default)]
    pub version: u64,
}

impl GroupChat {
    pub fn member_peer_ids(&self) -> Vec<libp2p::PeerId> {
        self.members
            .iter()
            .filter_map(|m| m.peer_id.parse().ok())
            .collect()
    }

    pub fn includes_peer(&self, peer_id: &libp2p::PeerId) -> bool {
        let s = peer_id.to_string();
        self.members.iter().any(|m| m.peer_id == s)
    }
}

pub fn new_group_id() -> String {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

pub fn validate_group_id(id: &str) -> bool {
    id.len() == GROUP_ID_HEX_LEN && id.chars().all(|c| c.is_ascii_hexdigit())
}

pub fn group_thread_key(group_id: &str) -> String {
    format!("{GROUP_THREAD_PREFIX}{group_id}")
}

pub fn is_group_thread(key: &str) -> bool {
    key.starts_with(GROUP_THREAD_PREFIX)
}

pub fn parse_group_thread_key(key: &str) -> Option<&str> {
    let id = key.strip_prefix(GROUP_THREAD_PREFIX)?;
    if validate_group_id(id) {
        Some(id)
    } else {
        None
    }
}

pub fn dedupe_members(members: Vec<GroupMember>) -> Vec<GroupMember> {
    let mut seen = std::collections::HashSet::new();
    members
        .into_iter()
        .filter(|m| seen.insert(m.peer_id.clone()))
        .collect()
}

pub fn validate_group_chat(g: &GroupChat) -> bool {
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
pub fn extract_invite_links(text: &str) -> Vec<String> {
    let mut links = Vec::new();
    let mut search_from = 0usize;
    while let Some(rel) = text[search_from..].find("void://group/") {
        let start = search_from + rel;
        let tail = &text[start..];
        let end = tail.find(|c: char| c.is_whitespace()).unwrap_or(tail.len());
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
pub fn build_invite_link(group: &GroupChat) -> String {
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
pub fn parse_invite_link(input: &str) -> Option<GroupChat> {
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
        version: 0,
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
pub fn members_on_group_create(
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
pub fn auto_join_from_invite_message() -> bool {
    false
}

/// Следующая версия подписанного состава. Ноль становится единицей.
pub fn next_group_version(current: u64) -> u64 {
    current.saturating_add(1).max(1)
}

/// Живое или офлайн-сообщение группы: мы в составе, и отправитель тоже.
pub fn member_may_post(group: &GroupChat, local_id: &str, sender_id: &str) -> bool {
    let local_in = group.members.iter().any(|m| m.peer_id == local_id);
    let sender_in = sender_id == local_id || group.members.iter().any(|m| m.peer_id == sender_id);
    local_in && sender_in
}

/// Канонические байты подписи создателя: `group_id ‖ version ‖ name ‖ members`.
/// Участники сортируются по `peer_id`, чтобы порядок в JSON не менял подпись.
pub fn group_sync_message(
    group_id: &str,
    version: u64,
    name: &str,
    members: &[GroupMember],
) -> Vec<u8> {
    let mut ordered: Vec<&GroupMember> = members.iter().collect();
    ordered.sort_by(|a, b| {
        a.peer_id
            .cmp(&b.peer_id)
            .then(a.display_name.cmp(&b.display_name))
    });
    let mut v = Vec::with_capacity(64 + name.len());
    v.extend_from_slice(b"VOID_GROUP_SYNC_V1\0");
    push_lp16(&mut v, group_id.as_bytes());
    v.extend_from_slice(&version.to_le_bytes());
    push_lp16(&mut v, name.as_bytes());
    v.extend_from_slice(&(ordered.len() as u32).to_le_bytes());
    for m in ordered {
        push_lp16(&mut v, m.peer_id.as_bytes());
        push_lp16(&mut v, m.display_name.as_bytes());
    }
    v
}

fn push_lp16(out: &mut Vec<u8>, bytes: &[u8]) {
    let n = bytes.len().min(u16::MAX as usize);
    out.extend_from_slice(&(n as u16).to_le_bytes());
    out.extend_from_slice(&bytes[..n]);
}

/// Принятое состояние группы после авторизации `group_sync`.
#[derive(Debug, PartialEq)]
pub struct AuthorizedGroupSync {
    pub name: String,
    pub creator_id: String,
    pub members: Vec<GroupMember>,
    pub version: u64,
}

/// Подписанный снимок создателя: только `version` строго больше локальной
/// и с верной подписью. Без подписи создательский sync отклоняется (откат
/// старым `group_sync`). Чужой unsigned sync по-прежнему может только
/// добавить или убрать отправителя — версию он не двигает.
pub fn admit_group_sync(
    existing: Option<&GroupChat>,
    from: &str,
    group_name: &str,
    creator_id: &str,
    members: Vec<GroupMember>,
    version: u64,
    signed_by_creator: bool,
) -> Option<AuthorizedGroupSync> {
    let local_v = existing.map(|g| g.version).unwrap_or(0);
    if signed_by_creator {
        if version <= local_v {
            return None;
        }
        let mut auth = authorize_group_sync(existing, creator_id, group_name, creator_id, members)?;
        auth.version = version;
        return Some(auth);
    }
    if from == creator_id || existing.is_some_and(|g| from == g.creator_id) {
        return None;
    }
    let mut auth = authorize_group_sync(existing, from, group_name, creator_id, members)?;
    auth.version = local_v;
    Some(auth)
}

/// Авторизация входящего `group_sync` от подтверждённого `from`; `None` — отклонить.
/// - новую группу ставит только её создатель (приглашение из контактов);
/// - создателя существующей группы сменить нельзя;
/// - создатель задаёт имя и состав;
/// - остальные могут только добавить/убрать себя и сменить своё имя.
pub fn authorize_group_sync(
    existing: Option<&GroupChat>,
    from: &str,
    group_name: &str,
    creator_id: &str,
    members: Vec<GroupMember>,
) -> Option<AuthorizedGroupSync> {
    let members = dedupe_members(members);
    let Some(g) = existing else {
        if !creator_id.is_empty() && creator_id != from {
            return None;
        }
        let name = if group_name.trim().is_empty() {
            "Группа".to_string()
        } else {
            group_name.to_string()
        };
        return Some(AuthorizedGroupSync {
            name,
            creator_id: from.to_string(),
            members,
            version: 0,
        });
    };
    if !creator_id.is_empty() && creator_id != g.creator_id {
        return None;
    }
    if from == g.creator_id {
        let name = if group_name.trim().is_empty() {
            g.name.clone()
        } else {
            group_name.to_string()
        };
        return Some(AuthorizedGroupSync {
            name,
            creator_id: g.creator_id.clone(),
            members,
            version: g.version,
        });
    }
    Some(AuthorizedGroupSync {
        name: g.name.clone(),
        creator_id: g.creator_id.clone(),
        members: sanitize_sync_members_for_creator(&g.members, from, &members),
        version: g.version,
    })
}

/// `GroupLeave` для `peer_id`: от самого уходящего или от создателя.
pub fn may_apply_group_leave(group: &GroupChat, from: &str, peer_id: &str) -> bool {
    from == peer_id || from == group.creator_id
}

/// `GroupDelete`: только от создателя известной группы.
pub fn may_apply_group_delete(group: Option<&GroupChat>, from: &str) -> bool {
    group.is_some_and(|g| g.creator_id == from)
}

/// Sync не от создателя: `from` может только добавить/убрать себя и сменить своё имя.
pub fn sanitize_sync_members_for_creator(
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
    if let Some(inc) = incoming.iter().find(|x| x.peer_id == from_peer_id) {
        if let Some(m) = out.iter_mut().find(|m| m.peer_id == from_peer_id) {
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
        let members = members_on_group_create("creator", "Alice", &["bob".into(), "carol".into()]);
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

    fn member(id: &str) -> GroupMember {
        GroupMember {
            peer_id: id.into(),
            display_name: id.to_uppercase(),
        }
    }

    fn existing_group() -> GroupChat {
        GroupChat {
            id: "0123456789abcdef0123456789abcdef".into(),
            name: "G".into(),
            creator_id: "alice".into(),
            members: vec![member("alice"), member("bob"), member("me")],
            created_at: "now".into(),
            version: 1,
        }
    }

    #[test]
    fn sync_new_group_only_from_its_creator() {
        let ok = authorize_group_sync(None, "alice", "G", "alice", vec![member("me")]).unwrap();
        assert_eq!(ok.creator_id, "alice");
        let ok = authorize_group_sync(None, "alice", "", "", vec![member("me")]).unwrap();
        assert_eq!(ok.creator_id, "alice");
        assert!(authorize_group_sync(None, "mallory", "G", "alice", vec![member("me")]).is_none());
    }

    #[test]
    fn sync_cannot_change_creator() {
        let g = existing_group();
        assert!(authorize_group_sync(Some(&g), "mallory", "X", "mallory", vec![]).is_none());
        assert!(authorize_group_sync(Some(&g), "alice", "X", "mallory", vec![]).is_none());
    }

    #[test]
    fn sync_from_creator_is_authoritative() {
        let g = existing_group();
        let out = authorize_group_sync(
            Some(&g),
            "alice",
            "New",
            "alice",
            vec![member("alice"), member("me"), member("carol")],
        )
        .unwrap();
        assert_eq!(out.name, "New");
        assert_eq!(out.members.len(), 3);
        assert!(!out.members.iter().any(|m| m.peer_id == "bob"));
    }

    #[test]
    fn sync_from_member_changes_only_self() {
        let g = existing_group();
        // Bob пытается переименовать группу, выкинуть alice и добавить eve.
        let out = authorize_group_sync(
            Some(&g),
            "bob",
            "Hacked",
            "",
            vec![member("bob"), member("me"), member("eve")],
        )
        .unwrap();
        assert_eq!(out.name, "G");
        assert_eq!(out.creator_id, "alice");
        let ids: Vec<_> = out.members.iter().map(|m| m.peer_id.as_str()).collect();
        assert_eq!(ids, ["alice", "bob", "me"]);
        // Bob выходит сам.
        let out =
            authorize_group_sync(Some(&g), "bob", "", "", vec![member("alice"), member("me")])
                .unwrap();
        assert!(!out.members.iter().any(|m| m.peer_id == "bob"));
        // Новый участник по invite добавляет только себя.
        let out = authorize_group_sync(
            Some(&g),
            "dave",
            "",
            "alice",
            vec![member("alice"), member("dave"), member("eve")],
        )
        .unwrap();
        assert!(out.members.iter().any(|m| m.peer_id == "dave"));
        assert!(!out.members.iter().any(|m| m.peer_id == "eve"));
        assert_eq!(out.members.len(), 4);
    }

    #[test]
    fn member_sync_cannot_rename_others() {
        let g = existing_group();
        let mut fake = member("alice");
        fake.display_name = "Impostor".into();
        let out = authorize_group_sync(
            Some(&g),
            "bob",
            "",
            "",
            vec![fake, member("bob"), member("me")],
        )
        .unwrap();
        assert_eq!(out.members[0].display_name, "ALICE");
    }

    #[test]
    fn leave_and_delete_need_authority() {
        let g = existing_group();
        assert!(may_apply_group_leave(&g, "bob", "bob"));
        assert!(may_apply_group_leave(&g, "alice", "bob"));
        assert!(!may_apply_group_leave(&g, "bob", "me"));
        assert!(may_apply_group_delete(Some(&g), "alice"));
        assert!(!may_apply_group_delete(Some(&g), "bob"));
        assert!(!may_apply_group_delete(None, "alice"));
    }

    #[test]
    fn invite_link_roundtrip_creator_only() {
        let g = GroupChat {
            id: "0123456789abcdef0123456789abcdef".into(),
            name: "Test".into(),
            creator_id: "creatorpeer".into(),
            members: members_on_group_create("creatorpeer", "Alice", &["bob".into()]),
            created_at: "now".into(),
            version: 1,
        };
        let link = build_invite_link(&g);
        let parsed = parse_invite_link(&link).expect("parse");
        assert_eq!(parsed.members.len(), 1);
        assert_eq!(parsed.members[0].peer_id, "creatorpeer");
        assert!(!parsed.members.iter().any(|m| m.peer_id == "bob"));
    }

    #[test]
    fn extract_invite_from_dm_text() {
        let text = "invite:\nvoid://group/0123456789abcdef0123456789abcdef?name=G&m=c&creator=c";
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

    #[test]
    fn creator_replay_does_not_roll_back_version() {
        let mut g = existing_group();
        g.version = 3;
        assert!(admit_group_sync(
            Some(&g),
            "alice",
            "Old",
            "alice",
            vec![member("alice")],
            2,
            true
        )
        .is_none());
        assert!(admit_group_sync(
            Some(&g),
            "alice",
            "Old",
            "alice",
            vec![member("alice")],
            3,
            true
        )
        .is_none());
        assert!(admit_group_sync(
            Some(&g),
            "alice",
            "Same",
            "alice",
            vec![member("alice")],
            0,
            false
        )
        .is_none());
        let ok = admit_group_sync(
            Some(&g),
            "alice",
            "New",
            "alice",
            vec![member("alice"), member("carol")],
            4,
            true,
        )
        .unwrap();
        assert_eq!(ok.version, 4);
        assert_eq!(ok.name, "New");
        let self_edit = admit_group_sync(
            Some(&g),
            "bob",
            "Hacked",
            "alice",
            vec![member("alice"), member("me")],
            0,
            false,
        )
        .unwrap();
        assert_eq!(self_edit.version, 3);
        assert!(!self_edit.members.iter().any(|m| m.peer_id == "bob"));
    }

    #[test]
    fn group_sync_message_ignores_member_order() {
        let a = group_sync_message("id", 2, "N", &[member("b"), member("a")]);
        let b = group_sync_message("id", 2, "N", &[member("a"), member("b")]);
        assert_eq!(a, b);
        let c = group_sync_message("id", 3, "N", &[member("a"), member("b")]);
        assert_ne!(a, c);
    }
}
