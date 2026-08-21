(() => {
  const t = (key, vars) => window.VOID_I18N.t(key, vars);

  const asset = (name) => {
    const encoded = name.split("/").map(encodeURIComponent).join("/");
    return `static/${encoded}?v=11`;
  };

  function resolveInvoke() {
    const t = window.__TAURI__;
    if (t?.core?.invoke) return t.core.invoke.bind(t.core);
    if (t?.tauri?.invoke) return t.tauri.invoke.bind(t.tauri);
    return null;
  }

  function resolveListen() {
    const t = window.__TAURI__;
    if (t?.event?.listen) return t.event.listen.bind(t.event);
    return null;
  }

  function convertFileSrc(path) {
    const c = window.__TAURI__?.core?.convertFileSrc;
    if (c && path) return c(path);
    return path || "";
  }

  function b64ToBytes(b64) {
    const bin = atob(String(b64 || ""));
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function parseWavPcm(u8) {
    if (u8.length < 44) throw new Error("short wav");
    const view = new DataView(u8.buffer, u8.byteOffset, u8.byteLength);
    const tag = (o) => String.fromCharCode(u8[o], u8[o + 1], u8[o + 2], u8[o + 3]);
    if (tag(0) !== "RIFF" || tag(8) !== "WAVE") throw new Error("not wav");
    let off = 12;
    let sampleRate = 48000;
    let channels = 1;
    let bits = 16;
    let dataOff = 0;
    let dataLen = 0;
    while (off + 8 <= u8.length) {
      const id = tag(off);
      const sz = view.getUint32(off + 4, true);
      const body = off + 8;
      if (id === "fmt ") {
        channels = view.getUint16(body + 2, true) || 1;
        sampleRate = view.getUint32(body + 4, true) || 48000;
        bits = view.getUint16(body + 14, true) || 16;
      } else if (id === "data") {
        dataOff = body;
        dataLen = sz;
        break;
      }
      off = body + sz + (sz & 1);
    }
    if (!dataLen) throw new Error("wav has no data");
    const frame = channels * (bits / 8);
    const n = Math.floor(dataLen / frame);
    const pcm = new Float32Array(n);
    if (bits === 16) {
      let i = 0;
      for (let s = 0; s < n; s++) {
        let acc = 0;
        for (let c = 0; c < channels; c++) {
          acc += view.getInt16(dataOff + i, true);
          i += 2;
        }
        pcm[s] = acc / channels / 32768;
      }
    } else if (bits === 8) {
      let i = 0;
      for (let s = 0; s < n; s++) {
        let acc = 0;
        for (let c = 0; c < channels; c++) {
          acc += u8[dataOff + i] - 128;
          i += 1;
        }
        pcm[s] = acc / channels / 128;
      }
    } else {
      throw new Error("unsupported wav");
    }
    return { sampleRate, pcm };
  }

  function createPcmPlayer() {
    let ctx = null;
    let pcm = null;
    let sampleRate = 48000;
    let source = null;
    let startedAt = 0;
    let offset = 0;
    let paused = true;
    let onTime = null;
    let onEnd = null;
    let raf = 0;
    let path = "";

    const ensureCtx = () => {
      if (!ctx) ctx = new (window.AudioContext || window.webkitAudioContext)();
      return ctx;
    };
    const duration = () => (pcm ? pcm.length / sampleRate : 0);
    const now = () => {
      if (paused || !ctx) return offset;
      return Math.min(duration(), offset + (ctx.currentTime - startedAt));
    };
    const stopSource = () => {
      if (source) {
        try {
          source.onended = null;
          source.stop();
        } catch (_) {}
        source = null;
      }
      if (raf) cancelAnimationFrame(raf);
      raf = 0;
    };
    const tick = () => {
      if (onTime) onTime(now(), duration());
      if (!paused) raf = requestAnimationFrame(tick);
    };

    return {
      get paused() {
        return paused;
      },
      get currentTime() {
        return now();
      },
      get duration() {
        return duration();
      },
      async load(filePath) {
        if (path === filePath && pcm) return;
        stopSource();
        paused = true;
        offset = 0;
        pcm = null;
        path = filePath;
        const b64 = await invoke("read_voice_file", { path: filePath });
        const parsed = parseWavPcm(b64ToBytes(b64));
        pcm = parsed.pcm;
        sampleRate = parsed.sampleRate;
      },
      async play() {
        if (!pcm) return;
        const ac = ensureCtx();
        if (ac.resume) await ac.resume();
        stopSource();
        if (offset >= duration() - 0.02) offset = 0;
        const buf = ac.createBuffer(1, pcm.length, sampleRate);
        buf.copyToChannel(pcm, 0);
        source = ac.createBufferSource();
        source.buffer = buf;
        source.connect(ac.destination);
        const startOff = Math.max(0, Math.min(offset, duration() - 0.02));
        source.onended = () => {
          if (paused) return;
          paused = true;
          offset = duration();
          stopSource();
          if (onEnd) onEnd();
        };
        source.start(0, startOff);
        startedAt = ac.currentTime;
        offset = startOff;
        paused = false;
        tick();
      },
      pause() {
        if (paused) return;
        offset = now();
        paused = true;
        stopSource();
      },
      seek(t) {
        offset = Math.max(0, Math.min(duration(), t));
        if (!paused) this.play();
        else if (onTime) onTime(offset, duration());
      },
      set ontimeupdate(fn) {
        onTime = fn;
      },
      set onended(fn) {
        onEnd = fn;
      },
    };
  }

  const els = {
    unlockScreen: document.getElementById("unlock-screen"),
    mainScreen: document.getElementById("main-screen"),
    brandLogo: document.getElementById("brand-logo"),
    unlockSubtitle: document.getElementById("unlock-subtitle"),
    password: document.getElementById("password"),
    passwordConfirm: document.getElementById("password-confirm"),
    confirmWrap: document.getElementById("confirm-wrap"),
    remember: document.getElementById("remember"),
    unlockError: document.getElementById("unlock-error"),
    unlockBtn: document.getElementById("unlock-btn"),
    chatList: document.getElementById("chat-list"),
    chatPeerBtn: document.getElementById("chat-peer-btn"),
    chatHeaderEmpty: document.getElementById("chat-header-empty"),
    chatAvatar: document.getElementById("chat-avatar"),
    chatTitle: document.getElementById("chat-title"),
    chatSub: document.getElementById("chat-sub"),
    messages: document.getElementById("messages"),
    composer: document.getElementById("composer"),
    messageInput: document.getElementById("message-input"),
    sendBtn: document.getElementById("send-btn"),
    attachBtn: document.getElementById("attach-btn"),
    voiceBtn: document.getElementById("voice-btn"),
    connStatus: document.getElementById("conn-status"),
    beaconBanner: document.getElementById("beacon-banner"),
    contactFilter: document.getElementById("contact-filter"),
    overlay: document.getElementById("overlay"),
    modalBody: document.getElementById("modal-body"),
    modalClose: document.getElementById("modal-close"),
    fileOffers: document.getElementById("file-offers"),
    recBar: document.getElementById("rec-bar"),
    recTime: document.getElementById("rec-time"),
    recStop: document.getElementById("rec-stop"),
    voicePreview: document.getElementById("voice-preview"),
    previewPlay: document.getElementById("preview-play"),
    previewSeek: document.getElementById("preview-seek"),
    previewTime: document.getElementById("preview-time"),
    previewCancel: document.getElementById("preview-cancel"),
    previewSend: document.getElementById("preview-send"),
    toast: document.getElementById("toast"),
    sidebar: document.getElementById("sidebar"),
    ctxMenu: document.getElementById("ctx-menu"),
  };

  let invoke = null;
  let snapshot = null;
  let vaultKind = "open_wrapped_key";
  let recording = false;
  let recTimer = null;
  let recStartedAt = 0;
  let previewAudio = null;
  let lastPreviewPath = "";
  let filter = "";
  let lastMsgSig = "";
  let lastContactSig = "";
  let lastSnapRev = 0;
  let snapTimer = null;
  let pendingSnap = null;
  let activeAudio = null;
  let menuSection = "contacts";
  let hopPendingSince = 0;
  let hopUiTimer = null;

  function hopOkFromSnap(s) {
    if (s?.relay_reserved) return true;
    if (!s?.relay_hop_pending) return false;
    if (!hopPendingSince) hopPendingSince = Date.now();
    return Date.now() - hopPendingSince >= 2500;
  }

  function syncHopTimer(s) {
    if (s?.relay_hop_pending && !s?.relay_reserved) {
      if (!hopPendingSince) hopPendingSince = Date.now();
      if (!hopUiTimer && invoke) {
        hopUiTimer = setInterval(async () => {
          try {
            const snap = await invoke("get_snapshot");
            if (snap) applySnapshotNow(snap);
            else if (snapshot) applySnapshotNow(snapshot);
          } catch (_) {
            if (snapshot) applySnapshotNow(snapshot);
          }
        }, 400);
      }
    } else {
      hopPendingSince = 0;
      if (hopUiTimer) {
        clearInterval(hopUiTimer);
        hopUiTimer = null;
      }
    }
  }

  function messagesSig(s) {
    const msgs = s?.messages || [];
    const lang = window.VOID_I18N.lang();
    return `${lang}|${s?.selected_chat || ""}|${msgs
      .map(
        (m) =>
          `${m.id}:${m.delivery}:${m.text?.length || 0}:${m.voice_transfer_id || ""}:${m.voice_path || ""}:${m.file_transfer_id || ""}:${m.file_path || ""}:${m.file_missing ? 1 : 0}`
      )
      .join("|")}`;
  }

  function contactsSig(s) {
    const lang = window.VOID_I18N.lang();
    return `${lang}|${s?.selected_chat || ""}|${filter}|${(s?.contacts || [])
      .map((c) => `${c.peer_id}:${c.online}:${c.display_name}:${c.last_preview || ""}`)
      .join("|")}`;
  }

  function formatChatPreview(c) {
    const raw = c?.last_preview || "";
    if (raw === "__void_voice__" || raw === "Голосовое сообщение") return t("preview.voice");
    if (raw) return raw;
    return c?.is_group ? t("chat.group") : (c?.peer_id || "").slice(0, 20);
  }

  function wireIcons() {
    document.querySelectorAll("[data-icon]").forEach((img) => {
      img.src = asset(img.getAttribute("data-icon"));
    });
    els.brandLogo.src = asset("Image_programm.png");
  }

  function showToast(text) {
    const msg = String(text ?? "").trim();
    if (!msg) return;
    const noise =
      /bootstrap|пробую|недоступен|переключ|дозваниваюсь|seed|dht|подключ|ошибка подключ|мdns|kad|dial/i.test(
        msg
      );
    if (noise) return;
    els.toast.textContent = msg;
    els.toast.hidden = false;
    clearTimeout(showToast._t);
    showToast._t = setTimeout(() => {
      els.toast.hidden = true;
    }, 3200);
  }

  function openModal(html) {
    els.modalBody.innerHTML = html;
    els.overlay.hidden = false;
    els.overlay.setAttribute("aria-hidden", "false");
  }

  function closeModal() {
    els.overlay.hidden = true;
    els.overlay.setAttribute("aria-hidden", "true");
    els.modalBody.innerHTML = "";
  }

  function hideCtx() {
    els.ctxMenu.hidden = true;
    els.ctxMenu.innerHTML = "";
  }

  function deliveryMark(d) {
    if (d === "read") return "✓✓";
    if (d === "delivered") return "✓";
    return "○";
  }

  function avatarColor(seed) {
    let h = 0;
    for (let i = 0; i < seed.length; i++) h = (h * 31 + seed.charCodeAt(i)) >>> 0;
    return `hsl(${h % 360} 32% 38%)`;
  }

  function escapeHtml(s) {
    return String(s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;");
  }
  function escapeAttr(s) {
    return escapeHtml(s).replace(/"/g, "&quot;");
  }

  function shortPeer(id) {
    const s = String(id || "");
    if (s.length <= 14) return s;
    return `${s.slice(0, 12)}…`;
  }

  function peerRouteLabel(id, s) {
    if (!id) return "—";
    const c = (s?.contacts || []).find((x) => x.peer_id === id);
    if (c?.display_name) return escapeHtml(c.display_name);
    const boots = s?.bootstraps || [];
    const isBoot =
      boots.some((b) => b.includes(id)) || (s?.onion_hops || []).includes(id);
    const short = escapeHtml(shortPeer(id));
    return isBoot ? t("onion.node", { id: short }) : short;
  }

  function onionChip(label) {
    return `<span class="onion-hop">${label}</span>`;
  }

  function hopCountLabel(n) {
    if (window.VOID_I18N.lang() === "ru") {
      const mod10 = n % 10;
      const mod100 = n % 100;
      if (mod10 === 1 && mod100 !== 11) return t("onion.hops1", { n });
      if (mod10 >= 2 && mod10 <= 4 && (mod100 < 12 || mod100 > 14)) return t("onion.hops24", { n });
      return t("onion.hopsN", { n });
    }
    return n === 1 ? t("onion.hops1", { n }) : t("onion.hopsN", { n });
  }

  function onionRouteHtml(s) {
    const hops = s?.onion_hops || [];
    let path;
    if (hops.length) {
      const chips = [
        onionChip(t("onion.you")),
        ...hops.map((h) => onionChip(peerRouteLabel(h, s))),
        onionChip(t("onion.peer")),
      ];
      path = `<div class="onion-path">${chips.join('<span class="onion-arrow">→</span>')}</div>
        <p class="muted">${t("onion.now", { n: hopCountLabel(hops.length) })}</p>`;
    } else if ((s?.bootstrap_connected || 0) > 0) {
      path = `<p class="muted">${t("onion.hasNode")}</p>`;
    } else {
      path = `<p class="muted">${t("onion.noNode")}</p>`;
    }
    const traces = (s?.onion_traces || []).slice().reverse();
    const list = traces.length
      ? traces
          .map((tr) => {
            const dir =
              tr.dir === "in" ? t("onion.in") : tr.dir === "direct" ? t("onion.direct") : t("onion.out");
            const dest = peerRouteLabel(tr.dest, s);
            const via = (tr.hops || []).map((h) => peerRouteLabel(h, s)).join(" → ") || "—";
            return `<div class="onion-trace"><strong>${dir}</strong> · ${dest}<div>${via}</div></div>`;
          })
          .join("")
      : `<p class="muted">${t("onion.noPkts")}</p>`;
    return `${path}<div class="onion-traces">${list}</div>`;
  }

  function applySnapshotNow(s) {
    if (!s) return;
    const rev = Number(s.revision || 0);
    if (lastSnapRev && rev && rev < lastSnapRev) return;
    if (rev) lastSnapRev = Math.max(lastSnapRev, rev);
    snapshot = s;
    syncHopTimer(s);
    if (s.unlocked) {
      els.unlockScreen.hidden = true;
      els.mainScreen.hidden = false;
    }
    els.beaconBanner.hidden = !s.beacon_active;
    const pidShort = (s.peer_id || "").slice(0, 12);
    const live = (s.bootstrap_connected || 0) + (s.connected_peers || 0);
    const hopOk = hopOkFromSnap(s);
    const hop = hopOk
      ? " · Hop OK"
      : s.relay_hop_pending
        ? " · Hop…"
        : s.bootstrap_connected > 0
          ? " · " + t("status.noHop")
          : "";
    const via = s.bootstrap_connected > 0 && !hopOk ? " · " + t("status.viaNode") : "";
    const netLabel = s.network_ok
      ? s.bootstrap_connected > 0
        ? t("status.online")
        : t("status.hasLinks")
      : s.bootstraps?.length
        ? t("status.noBootstrap")
        : t("status.noBootstrapSet");
    els.connStatus.textContent = `${netLabel}${via}${hop} · ${pidShort}… · live ${live} · ${t("status.contacts")} ${s.connected_peers} · bootstrap ${s.bootstrap_connected}/${s.bootstraps?.length || 0}`;
    els.connStatus.title = [
      hopOk
        ? t("status.hopOkTitle")
        : s.relay_hop_pending
          ? t("status.hopWaitTitle")
          : s.bootstrap_connected > 0
            ? t("status.viaMailboxTitle")
            : "",
      s.peer_id || "",
      ...(s.bootstraps || []).slice(0, 4),
    ]
      .filter(Boolean)
      .join("\n");
    els.connStatus.style.color = hopOk
      ? "var(--accent)"
      : s.relay_hop_pending
        ? "#c9a227"
        : s.network_ok
          ? "#c9a227"
          : "var(--danger)";

    const cSig = contactsSig(s);
    if (cSig !== lastContactSig) {
      lastContactSig = cSig;
      renderContacts();
    }
    const mSig = messagesSig(s);
    if (mSig !== lastMsgSig) {
      lastMsgSig = mSig;
      const nearBottom =
        els.messages.scrollHeight - els.messages.scrollTop - els.messages.clientHeight < 80;
      renderMessages();
      if (nearBottom) els.messages.scrollTop = els.messages.scrollHeight;
    }
    renderFileOffers();
    recording = !!s.voice_recording;
    const enabled = !!s.selected_chat;
    const previewing = !!s.voice_preview_path;
    els.messageInput.disabled = !enabled;
    els.sendBtn.disabled = !enabled;
    if (els.attachBtn) els.attachBtn.disabled = !enabled || recording || previewing;
    if (els.voiceBtn) els.voiceBtn.disabled = !enabled || previewing;
    updateChatHeader(s);
    els.composer.classList.toggle("recording", recording);
    updateRecBar(s);
    updateVoicePreview(s);
    const onionEl = document.getElementById("onion-live");
    if (onionEl) onionEl.innerHTML = onionRouteHtml(s);
  }

  function updateChatHeader(s) {
    if (!s.selected_chat) {
      els.chatPeerBtn.hidden = true;
      els.chatHeaderEmpty.hidden = false;
      return;
    }
    els.chatHeaderEmpty.hidden = true;
    els.chatPeerBtn.hidden = false;
    const c = (s.contacts || []).find((x) => x.peer_id === s.selected_chat);
    const name = c?.display_name || s.selected_chat.slice(0, 16);
    const letter = (name || "?").trim().charAt(0).toUpperCase();
    els.chatAvatar.textContent = letter;
    els.chatAvatar.style.background = avatarColor(s.selected_chat);
    els.chatAvatar.classList.toggle("online", !!c?.online);
    els.chatTitle.textContent = name;
    if (c?.is_group) {
      els.chatSub.textContent = t("chat.group");
    } else if (c?.online) {
      els.chatSub.textContent = t("chat.onlinePeer", { id: (c.peer_id || "").slice(0, 16) });
    } else {
      els.chatSub.textContent = t("chat.offlinePeer", {
        id: (c?.peer_id || s.selected_chat || "").slice(0, 20),
      });
      els.chatSub.title = c?.peer_id || s.selected_chat || "";
    }
  }

  function applySnapshot(s, immediate) {
    if (!s) return;
    const rev = Number(s.revision || 0);
    if (lastSnapRev && rev && rev < lastSnapRev) return;
    if (immediate) {
      if (snapTimer) {
        clearTimeout(snapTimer);
        snapTimer = null;
      }
      pendingSnap = null;
      applySnapshotNow(s);
      return;
    }
    const pendingRev = Number(pendingSnap?.revision || 0);
    if (pendingSnap && pendingRev && rev && rev < pendingRev) return;
    pendingSnap = s;
    if (snapTimer) return;
    snapTimer = setTimeout(() => {
      snapTimer = null;
      const next = pendingSnap;
      pendingSnap = null;
      applySnapshotNow(next);
    }, 80);
  }

  function sanitizePeerInput(raw) {
    return String(raw || "")
      .replace(/[\u200b-\u200d\ufeff\u00a0]/g, "")
      .trim()
      .replace(/^["'`«»“”‹›]+|["'`«»“”‹›]+$/g, "")
      .trim();
  }

  function renderContacts() {
    const list = (snapshot?.contacts || []).filter((c) => {
      if (!filter) return true;
      const q = filter.toLowerCase();
      return c.display_name.toLowerCase().includes(q) || c.peer_id.toLowerCase().includes(q);
    });
    els.chatList.innerHTML = "";
    list.forEach((c) => {
      const item = document.createElement("div");
      item.className = "chat-item" + (snapshot.selected_chat === c.peer_id ? " active" : "");
      item.dataset.id = c.peer_id;
      const letter = (c.display_name || "?").trim().charAt(0).toUpperCase();
      item.innerHTML = `
        <div class="avatar ${c.online ? "online" : ""}" style="background:${avatarColor(c.peer_id)}">${letter}</div>
        <div>
          <h3></h3>
          <p></p>
        </div>`;
      item.querySelector("h3").textContent = c.display_name;
      item.querySelector("p").textContent = c.online ? t("status.online") : formatChatPreview(c);
      els.chatList.appendChild(item);
    });
  }

  async function selectChat(id) {
    if (!id || !invoke) return;
    hideCtx();
    if (snapshot) snapshot.selected_chat = id;
    lastContactSig = contactsSig(snapshot);
    lastMsgSig = "";
    els.chatList.querySelectorAll(".chat-item").forEach((el) => {
      el.classList.toggle("active", el.dataset.id === id);
    });
    try {
      const next = await invoke("select_chat", { chatId: id, chat_id: id });
      applySnapshot(next, true);
    } catch (err) {
      showToast(String(err));
      return;
    }
    if (window.matchMedia("(max-width: 820px)").matches) {
      els.mainScreen.classList.add("sidebar-collapsed");
    }
    els.sidebar.classList.remove("open");
  }

  function showContactContextMenu(x, y, c) {
    els.ctxMenu.innerHTML = `
      <button type="button" data-act="rename">${t("ctx.renameContact")}</button>
      <button type="button" data-act="clear">${t("ctx.clearChat")}</button>
      <button type="button" data-act="copy">${t("ctx.copyPeer")}</button>
      <button type="button" data-act="delete" class="danger">${t("ctx.deletePeer")}</button>`;
    els.ctxMenu.hidden = false;
    const pad = 8;
    const rect = els.ctxMenu.getBoundingClientRect();
    const w = rect.width || 220;
    const h = rect.height || 160;
    els.ctxMenu.style.left = `${Math.min(x, window.innerWidth - w - pad)}px`;
    els.ctxMenu.style.top = `${Math.min(y, window.innerHeight - h - pad)}px`;
    els.ctxMenu.querySelectorAll("button").forEach((btn) => {
      btn.onclick = async () => {
        hideCtx();
        const act = btn.getAttribute("data-act");
        try {
          if (act === "copy") {
            await navigator.clipboard.writeText(c.peer_id);
            showToast(t("toast.peerCopied"));
          } else if (act === "rename") {
            const name = window.prompt(t("prompt.renameContact"), c.display_name || "");
            if (name == null || !name.trim()) return;
            applySnapshot(await invoke("rename_contact", { peerId: c.peer_id, name: name.trim() }));
          } else if (act === "clear") {
            if (!window.confirm(t("confirm.clearContact"))) return;
            applySnapshot(await invoke("clear_chat", { peerId: c.peer_id }));
          } else if (act === "delete") {
            if (!window.confirm(t("confirm.deleteContact"))) return;
            applySnapshot(await invoke("remove_contact", { peerId: c.peer_id }));
          }
        } catch (err) {
          showToast(String(err));
        }
      };
    });
  }

  function groupIdFromChat(peerId) {
    const s = String(peerId || "");
    return s.startsWith("group:") ? s.slice(6) : s;
  }

  function showGroupContextMenu(x, y, c) {
    const gid = groupIdFromChat(c.peer_id);
    const group = (snapshot?.groups || []).find((g) => g.id === gid);
    const isCreator = !!(group && snapshot?.peer_id && group.creator_id === snapshot.peer_id);
    els.ctxMenu.innerHTML = `
      <button type="button" data-act="rename">${t("ctx.renameGroup")}</button>
      <button type="button" data-act="clear">${t("ctx.clearChat")}</button>
      <button type="button" data-act="copy">${t("ctx.copyInvite")}</button>
      <button type="button" data-act="leave" class="danger">${
        isCreator ? t("ctx.deleteGroup") : t("ctx.leaveGroup")
      }</button>`;
    els.ctxMenu.hidden = false;
    const pad = 8;
    const rect = els.ctxMenu.getBoundingClientRect();
    const w = rect.width || 220;
    const h = rect.height || 160;
    els.ctxMenu.style.left = `${Math.min(x, window.innerWidth - w - pad)}px`;
    els.ctxMenu.style.top = `${Math.min(y, window.innerHeight - h - pad)}px`;
    els.ctxMenu.querySelectorAll("button").forEach((btn) => {
      btn.onclick = async () => {
        hideCtx();
        const act = btn.getAttribute("data-act");
        try {
          if (act === "copy") {
            const link = group?.invite_link || "";
            if (!link) {
              showToast(t("toast.noLink"));
              return;
            }
            await navigator.clipboard.writeText(link);
            showToast(t("toast.inviteCopied"));
          } else if (act === "rename") {
            const name = window.prompt(t("prompt.renameGroup"), c.display_name || "");
            if (name == null || !name.trim()) return;
            applySnapshot(
              await invoke("rename_group", { groupId: gid, group_id: gid, name: name.trim() })
            );
          } else if (act === "clear") {
            if (!window.confirm(t("confirm.clearGroup"))) return;
            applySnapshot(await invoke("clear_chat", { peerId: c.peer_id }));
          } else if (act === "leave") {
            if (!window.confirm(isCreator ? t("confirm.deleteGroup") : t("confirm.leaveGroup"))) {
              return;
            }
            applySnapshot(await invoke("leave_group", { groupId: gid, group_id: gid }));
          }
        } catch (err) {
          showToast(String(err));
        }
      };
    });
  }

  function renderMessages() {
    const msgs = snapshot?.messages || [];
    const prevScroll = els.messages.scrollTop;
    const prevHeight = els.messages.scrollHeight;
    els.messages.innerHTML = "";
    msgs.forEach((m) => {
      const div = document.createElement("div");
      div.className = `message ${m.outgoing ? "sent" : "received"}`;
      if (m.voice_transfer_id) {
        div.classList.add("voice-msg");
        const ready = !!m.voice_path;
        div.innerHTML = `
          <div class="voice-player" data-tid="${escapeAttr(m.voice_transfer_id)}">
            <button type="button" class="voice-play" ${ready ? "" : "disabled"} title="${ready ? "Play/Pause" : t("voice.loading")}">${ready ? "▶" : "…"}</button>
            <input type="range" class="voice-seek" min="0" max="1000" value="0" ${ready ? "" : "disabled"} />
            <span class="voice-time">0:00 / ${fmtTime(m.voice_duration_secs || 0)}</span>
          </div>
          <div class="meta"><span></span><span></span></div>`;
        const meta = div.querySelectorAll(".meta span");
        meta[0].textContent = m.timestamp || "";
        meta[1].textContent = m.outgoing ? deliveryMark(m.delivery) : "";
        if (ready) wireVoiceControls(div, m);
      } else if (m.file_transfer_id) {
        div.classList.add("file-msg");
        const ready = !!m.file_path;
        const missing = !!m.file_missing && !ready;
        const status = ready ? fmtSize(m.file_size) : missing ? t("file.deleted") : t("file.loading");
        div.innerHTML = `
          <div class="file-card ${ready ? "" : missing ? "missing" : "pending"}" data-tid="${escapeAttr(m.file_transfer_id || "")}">
            <div class="file-icon">📄</div>
            <div>
              <div class="file-name"></div>
              <div class="file-size">${status}</div>
            </div>
            <div class="file-actions">
              ${ready ? `<button type="button" class="file-dl" data-act="download" title="${t("file.downloadTitle")}">${t("file.download")}</button>` : ""}
              <button type="button" class="file-del" data-act="delete" title="${t("file.deleteTitle")}">×</button>
            </div>
          </div>
          <div class="meta"><span></span><span></span></div>`;
        div.querySelector(".file-name").textContent = m.file_name || t("file.fallback");
        const meta = div.querySelectorAll(".meta span");
        meta[0].textContent = m.timestamp || "";
        meta[1].textContent = m.outgoing ? deliveryMark(m.delivery) : "";
        const dl = div.querySelector("[data-act=download]");
        if (dl) {
          dl.onclick = async (e) => {
            e.stopPropagation();
            try {
              const dest = await invoke("save_file_to_downloads", { transferId: m.file_transfer_id });
              await invoke("reveal_path", { path: dest });
            } catch (err) {
              showToast(String(err));
            }
          };
        }
        const del = div.querySelector("[data-act=delete]");
        if (del) {
          del.onclick = async (e) => {
            e.stopPropagation();
            if (!window.confirm(t("confirm.deleteFile"))) return;
            try {
              applySnapshot(await invoke("delete_message", { messageId: m.id }), true);
            } catch (err) {
              showToast(String(err));
            }
          };
        }
      } else {
        div.innerHTML = `<div class="body"></div><div class="meta"><span></span><span></span></div>`;
        div.querySelector(".body").textContent = m.text;
        const meta = div.querySelectorAll(".meta span");
        meta[0].textContent = m.timestamp || "";
        meta[1].textContent = m.outgoing ? deliveryMark(m.delivery) : "";
      }
      els.messages.appendChild(div);
    });
    if (els.messages.scrollHeight === prevHeight) {
      els.messages.scrollTop = prevScroll;
    }
  }

  function fmtTime(sec) {
    const s = Math.max(0, Math.floor(sec || 0));
    const m = Math.floor(s / 60);
    const r = s % 60;
    return `${m}:${String(r).padStart(2, "0")}`;
  }

  function fmtSize(n) {
    const b = Number(n) || 0;
    if (b < 1024) return t("size.b", { n: b });
    if (b < 1024 * 1024) return t("size.kb", { n: (b / 1024).toFixed(1) });
    return t("size.mb", { n: (b / (1024 * 1024)).toFixed(1) });
  }

  function stopRecTimer() {
    if (recTimer) {
      clearInterval(recTimer);
      recTimer = null;
    }
  }

  function updateRecBar(s) {
    const on = !!s?.voice_recording;
    els.recBar.hidden = !on;
    if (on) {
      if (!recTimer) {
        recStartedAt = Date.now() - Math.floor((s.voice_recording_secs || 0) * 1000);
        recTimer = setInterval(() => {
          els.recTime.textContent = fmtTime((Date.now() - recStartedAt) / 1000);
        }, 200);
      }
    } else {
      stopRecTimer();
      els.recTime.textContent = "0:00";
    }
  }

  function stopPreviewAudio() {
    if (previewAudio && typeof previewAudio.pause === "function") {
      previewAudio.pause();
    }
    if (els.previewPlay) els.previewPlay.textContent = "▶";
  }

  function updateVoicePreview(s) {
    const path = s?.voice_preview_path;
    const dur = s?.voice_preview_duration || 0;
    if (!path) {
      els.voicePreview.hidden = true;
      lastPreviewPath = "";
      stopPreviewAudio();
      previewAudio = null;
      return;
    }
    els.voicePreview.hidden = false;
    if (path === lastPreviewPath) {
      return;
    }
    lastPreviewPath = path;
    stopPreviewAudio();
    previewAudio = createPcmPlayer();
    els.previewTime.textContent = `0:00 / ${fmtTime(dur)}`;
    els.previewSeek.value = "0";
    previewAudio.ontimeupdate = (cur, total) => {
      const d = total || dur;
      if (!d) return;
      els.previewSeek.value = String(Math.floor((cur / d) * 1000));
      els.previewTime.textContent = `${fmtTime(cur)} / ${fmtTime(d)}`;
    };
    previewAudio.onended = () => {
      els.previewPlay.textContent = "▶";
      els.previewSeek.value = "0";
    };
    els.previewPlay.onclick = async () => {
      try {
        await previewAudio.load(path);
        if (previewAudio.paused) {
          if (activeAudio && activeAudio !== previewAudio) activeAudio.pause();
          activeAudio = previewAudio;
          await previewAudio.play();
          els.previewPlay.textContent = "❚❚";
        } else {
          previewAudio.pause();
          els.previewPlay.textContent = "▶";
        }
      } catch (e) {
        showToast(t("toast.playFail", { err: e }));
      }
    };
    els.previewSeek.oninput = () => {
      const d = previewAudio?.duration || dur;
      if (!d) return;
      previewAudio.seek((Number(els.previewSeek.value) / 1000) * d);
    };
  }

  function wireVoiceControls(div, m) {
    const root = div.querySelector(".voice-player");
    const playBtn = root.querySelector(".voice-play");
    const seek = root.querySelector(".voice-seek");
    const timeEl = root.querySelector(".voice-time");
    const player = createPcmPlayer();
    player.ontimeupdate = (cur, total) => {
      const d = total || m.voice_duration_secs || 0;
      if (!d) return;
      seek.value = String(Math.floor((cur / d) * 1000));
      timeEl.textContent = `${fmtTime(cur)} / ${fmtTime(d)}`;
    };
    player.onended = () => {
      playBtn.textContent = "▶";
      seek.value = "0";
    };

    playBtn.onclick = async () => {
      try {
        await player.load(m.voice_path);
        if (activeAudio && activeAudio !== player) activeAudio.pause();
        activeAudio = player;
        if (player.paused) {
          await player.play();
          playBtn.textContent = "❚❚";
        } else {
          player.pause();
          playBtn.textContent = "▶";
        }
      } catch (e) {
        showToast(t("toast.playFail", { err: e }));
      }
    };

    seek.oninput = () => {
      const d = player.duration || m.voice_duration_secs || 0;
      if (!d) return;
      player.seek((Number(seek.value) / 1000) * d);
    };
  }

  function renderFileOffers() {
    els.fileOffers.innerHTML = "";
    (snapshot?.incoming_files || []).forEach((f) => {
      if (/^void_voice_/i.test(f.filename || "")) return;
      const row = document.createElement("div");
      row.className = "offer";
      row.innerHTML = `<span></span>`;
      row.querySelector("span").textContent = t("file.offer", { name: f.filename, size: f.total_size });
      const acc = document.createElement("button");
      acc.className = "btn primary";
      acc.textContent = t("file.accept");
      acc.onclick = async () => {
        try {
          let saveDir = null;
          const dialog = window.__TAURI__?.dialog;
          if (dialog?.open) {
            const picked = await dialog.open({
              directory: true,
              multiple: false,
              title: t("file.saveWhere"),
            });
            if (picked === null) saveDir = null;
            else saveDir = Array.isArray(picked) ? picked[0] : picked;
          }
          await invoke("accept_file", { transferId: f.transfer_id, saveDir });
          showToast(t("toast.fileAccepted"));
          applySnapshot(await invoke("get_snapshot"));
        } catch (e) {
          showToast(String(e));
        }
      };
      const rej = document.createElement("button");
      rej.className = "btn";
      rej.textContent = t("file.reject");
      rej.onclick = async () => {
        await invoke("reject_file", { transferId: f.transfer_id });
        applySnapshot(await invoke("get_snapshot"));
      };
      row.append(acc, rej);
      els.fileOffers.appendChild(row);
    });
  }

  function menuNav(active) {
    return `
      <div class="menu-nav">
        <button type="button" class="menu-tab ${active === "contacts" ? "active" : ""}" data-sec="contacts" data-i18n="menu.contacts">${t("menu.contacts")}</button>
        <button type="button" class="menu-tab ${active === "groups" ? "active" : ""}" data-sec="groups" data-i18n="menu.groups">${t("menu.groups")}</button>
        <button type="button" class="menu-tab ${active === "network" ? "active" : ""}" data-sec="network" data-i18n="menu.network">${t("menu.network")}</button>
        <button type="button" class="menu-tab ${active === "settings" ? "active" : ""}" data-sec="settings" data-i18n="menu.settings">${t("menu.settings")}</button>
      </div>`;
  }

  function wireMenuTabs() {
    els.modalBody.querySelectorAll(".menu-tab").forEach((btn) => {
      btn.onclick = () => {
        menuSection = btn.getAttribute("data-sec");
        mainMenuModal();
      };
    });
  }

  function mainMenuModal() {
    const sec = menuSection || "contacts";
    let body = "";
    if (sec === "contacts") {
      body = `
        <h4 class="menu-h">${t("menu.contacts")}</h4>
        <label class="field"><span>${t("contacts.peerField")}</span><input id="m-peer" /></label>
        <label class="field"><span>${t("contacts.name")}</span><input id="m-name" placeholder="${t("contacts.namePh")}" /></label>
        <button class="btn primary" id="m-add">${t("contacts.add")}</button>`;
    } else if (sec === "groups") {
      const pick = contactPickerHtml([], snapshot?.peer_id);
      body = `
        <h4 class="menu-h">${t("menu.groups")}</h4>
        <label class="field"><span>${t("groups.name")}</span><input id="m-gname" /></label>
        <p class="muted">${t("groups.membersHint")}</p>
        ${pick}
        <button class="btn primary" id="m-gcreate">${t("groups.create")}</button>
        <hr class="menu-hr" />
        <label class="field"><span>${t("groups.link")}</span><input id="m-glink" /></label>
        <button class="btn" id="m-gjoin">${t("groups.join")}</button>`;
    } else if (sec === "network") {
      const boots =
        (snapshot?.bootstraps || []).map((b) => `<div>${escapeHtml(b)}</div>`).join("") ||
        `<div>${t("network.empty")}</div>`;
      const hopLine = snapshot?.relay_reserved
        ? t("network.hopOk")
        : snapshot?.relay_hop_pending
          ? t("network.hopWait")
          : snapshot?.bootstrap_connected > 0
            ? t("network.hopMailbox")
            : t("network.hopNone");
      const onlineList =
        (snapshot?.contacts || [])
          .filter((c) => c.online)
          .map((c) => escapeHtml(c.display_name || c.peer_id.slice(0, 12)))
          .join(", ") || "—";
      body = `
        <h4 class="menu-h">${t("network.title")}</h4>
        <p class="muted">${t("network.yourPeer")}</p>
        <div class="bootstrap-list" style="user-select:all">${escapeHtml(snapshot?.peer_id || "—")}</div>
        <p class="muted">${
          snapshot?.network_ok
            ? t("network.statusOk", {
                boot: snapshot?.bootstrap_connected || 0,
                peers: snapshot?.connected_peers || 0,
              })
            : t("network.statusOff")
        }</p>
        <p class="muted">${hopLine}</p>
        <p class="muted">${t("network.onlineNow", { list: onlineList })}</p>
        <label class="field"><span>${t("network.joinField")}</span><input id="n-join" placeholder="${t("network.joinPh")}" /></label>
        <button class="btn primary" id="n-go">${t("network.join")}</button>
        <button class="btn" id="n-reload">${t("network.reload")}</button>
        <div><strong>${t("network.bootstrap", { n: snapshot?.bootstraps?.length || 0 })}</strong><div class="bootstrap-list">${boots}</div></div>
        <hr class="menu-hr" />
        <h4 class="menu-h" data-i18n="settings.onion">${t("settings.onion")}</h4>
        <p class="muted" data-i18n="settings.onionHint">${t("settings.onionHint")}</p>
        <div id="onion-live">${onionRouteHtml(snapshot)}</div>`;
    } else {
      const langOpts = window.VOID_I18N.LANGS.map(
        (l) =>
          `<option value="${l.id}"${l.id === window.VOID_I18N.lang() ? " selected" : ""}>${l.native}</option>`
      ).join("");
      body = `
        <h4 class="menu-h" data-i18n="menu.settings">${t("menu.settings")}</h4>
        <label class="field"><span data-i18n="settings.language">${t("settings.language")}</span><select id="s-lang">${langOpts}</select></label>
        <label class="field"><span data-i18n="settings.nick">${t("settings.nick")}</span><input id="s-nick" value="${escapeAttr(snapshot?.nickname || "")}" /></label>
        <label class="field"><span data-i18n="settings.peer">${t("settings.peer")}</span><input id="s-peer" readonly value="${escapeAttr(snapshot?.peer_id || "")}" /></label>
        <p class="muted">${t("settings.publicIp", { ip: snapshot?.public_ip || "—" })}</p>
        <button class="btn primary" id="s-save" data-i18n="settings.saveNick">${t("settings.saveNick")}</button>
        <button class="btn" id="s-copy" data-i18n="settings.copyPeer">${t("settings.copyPeer")}</button>
        <button class="btn" id="s-downloads" data-i18n="settings.downloads">${t("settings.downloads")}</button>
        <button class="btn" id="s-quit" data-i18n="settings.quit">${t("settings.quit")}</button>`;
    }

    openModal(`
      <h3>${t("menu.title")}</h3>
      ${menuNav(sec)}
      <div class="stack menu-section">${body}</div>`);
    wireMenuTabs();

    if (sec === "contacts") {
      document.getElementById("m-add").onclick = async () => {
        try {
          const peer = sanitizePeerInput(document.getElementById("m-peer").value);
          const name = document.getElementById("m-name").value;
          if (!peer) {
            showToast(t("toast.needPeer"));
            return;
          }
          const snap = await invoke("add_contact", {
            peerOrAddr: peer,
            peer_or_addr: peer,
            name,
          });
          applySnapshot(snap, true);
          closeModal();
          showToast(t("toast.contactAdded"));
        } catch (e) {
          showToast(String(e));
        }
      };
    } else if (sec === "groups") {
      document.getElementById("m-gcreate").onclick = async () => {
        try {
          const members = selectedPickerPeers(els.modalBody);
          applySnapshot(
            await invoke("create_group", {
              name: document.getElementById("m-gname").value,
              memberPeerIds: members,
              member_peer_ids: members,
            }),
            true
          );
          closeModal();
        } catch (e) {
          showToast(String(e));
        }
      };
      document.getElementById("m-gjoin").onclick = async () => {
        try {
          applySnapshot(
            await invoke("join_group", { link: document.getElementById("m-glink").value })
          );
          closeModal();
        } catch (e) {
          showToast(String(e));
        }
      };
    } else if (sec === "network") {
      document.getElementById("n-go").onclick = async () => {
        try {
          applySnapshot(
            await invoke("join_via_node", { input: document.getElementById("n-join").value })
          );
          showToast(t("toast.connecting"));
        } catch (e) {
          showToast(String(e));
        }
      };
      document.getElementById("n-reload").onclick = async () => {
        applySnapshot(await invoke("reload_bootstraps"));
        showToast(t("toast.bootReloaded"));
      };
    } else if (sec === "settings") {
      document.getElementById("s-save").onclick = async () => {
        try {
          applySnapshot(
            await invoke("set_nickname", { nickname: document.getElementById("s-nick").value })
          );
          closeModal();
        } catch (e) {
          showToast(String(e));
        }
      };
      document.getElementById("s-copy").onclick = async () => {
        try {
          await navigator.clipboard.writeText(snapshot?.peer_id || "");
          showToast(t("toast.peerCopied"));
        } catch {
          showToast(t("toast.copyFail"));
        }
      };
      document.getElementById("s-downloads").onclick = async () => {
        try {
          const path = await invoke("downloads_path");
          await invoke("open_downloads");
          showToast(path);
        } catch (e) {
          showToast(String(e));
        }
      };
      document.getElementById("s-quit").onclick = () => invoke("quit_application");
      const langSel = document.getElementById("s-lang");
      if (langSel) {
        langSel.onchange = () => {
          window.VOID_I18N.setLang(langSel.value);
          mainMenuModal();
          window.VOID_I18N.applyDom();
        };
      }
    }
  }

  function personContacts() {
    return (snapshot?.contacts || []).filter((c) => !c.is_group);
  }

  function contactPickerHtml(excludePeerIds, alsoExclude) {
    const exclude = new Set(excludePeerIds || []);
    if (alsoExclude) exclude.add(alsoExclude);
    const list = personContacts().filter((c) => !exclude.has(c.peer_id));
    if (!list.length) {
      return `<p class="muted">${t("picker.empty")}</p>`;
    }
    return `<div class="contact-pick">${list
      .map(
        (c) => `
      <label class="check pick-row">
        <input type="checkbox" data-peer="${escapeAttr(c.peer_id)}" />
        <span>${escapeHtml(c.display_name || c.peer_id.slice(0, 12))}${
          c.online ? " · " + t("status.online") : ""
        }</span>
      </label>`
      )
      .join("")}</div>`;
  }

  function selectedPickerPeers(root) {
    return [...(root || document).querySelectorAll(".contact-pick input[type=checkbox]:checked")]
      .map((el) => el.getAttribute("data-peer"))
      .filter(Boolean);
  }

  function peerInfoModal() {
    const chat = snapshot?.selected_chat;
    if (!chat) return;
    const c = (snapshot?.contacts || []).find((x) => x.peer_id === chat);
    if (c?.is_group) {
      const gid = chat.startsWith("group:") ? chat.slice(6) : chat;
      const group = (snapshot?.groups || []).find((x) => x.id === gid);
      const memberIds = (group?.members || []).map((m) => m.peer_id);
      const membersHtml = (group?.members || [])
        .map((m) => `<div>${escapeHtml(m.display_name || m.peer_id.slice(0, 12))}</div>`)
        .join("") || `<div class="muted">${t("group.noMembers")}</div>`;
      openModal(`
        <h3>${t("group.title")}</h3>
        <div class="stack">
          <p><strong>${escapeHtml(group?.name || c.display_name)}</strong></p>
          <p class="muted">${t("group.members", { n: group?.members?.length || 0 })}</p>
          <div class="bootstrap-list">${membersHtml}</div>
          <button class="btn" id="gi-copy">${t("group.copyInvite")}</button>
          <p class="muted">${t("group.inviteHint")}</p>
          ${contactPickerHtml(memberIds, snapshot?.peer_id)}
          <button class="btn primary" id="gi-invite">${t("group.inviteBtn")}</button>
        </div>`);
      document.getElementById("gi-copy").onclick = async () => {
        const link = group?.invite_link || "";
        if (!link) {
          showToast(t("toast.noLink"));
          return;
        }
        try {
          await navigator.clipboard.writeText(link);
          showToast(t("toast.inviteCopied"));
        } catch {
          showToast(t("toast.copyFail"));
        }
      };
      document.getElementById("gi-invite").onclick = async () => {
        try {
          const members = selectedPickerPeers(els.modalBody);
          if (!members.length) {
            showToast(t("toast.pickContacts"));
            return;
          }
          applySnapshot(
            await invoke("invite_to_group", {
              groupId: gid,
              group_id: gid,
              memberPeerIds: members,
              member_peer_ids: members,
            }),
            true
          );
          showToast(t("toast.invited"));
          peerInfoModal();
        } catch (e) {
          showToast(String(e));
        }
      };
      return;
    }
    openModal(`
      <h3>${t("peer.title")}</h3>
      <div class="stack">
        <div class="peer-info-avatar" style="background:${avatarColor(chat)}">${escapeHtml(
          (c?.display_name || "?").trim().charAt(0).toUpperCase()
        )}</div>
        <p><strong>${escapeHtml(c?.display_name || chat.slice(0, 16))}</strong></p>
        <p class="muted">${c?.online ? t("status.online") : t("peer.offline")}</p>
        <p class="muted">Peer ID</p>
        <div class="bootstrap-list" style="user-select:all">${escapeHtml(chat)}</div>
        <button class="btn" id="pi-copy">${t("ctx.copyPeer")}</button>
        <button class="btn" id="pi-rename">${t("peer.rename")}</button>
        <button class="btn" id="pi-clear">${t("peer.clear")}</button>
        <button class="btn danger-outline" id="pi-del">${t("peer.delete")}</button>
      </div>`);
    document.getElementById("pi-copy").onclick = async () => {
      await navigator.clipboard.writeText(chat);
      showToast(t("toast.peerCopied"));
    };
    document.getElementById("pi-rename").onclick = async () => {
      const name = window.prompt(t("prompt.rename"), c?.display_name || "");
      if (name == null || !name.trim()) return;
      applySnapshot(await invoke("rename_contact", { peerId: chat, name: name.trim() }));
      peerInfoModal();
    };
    document.getElementById("pi-clear").onclick = async () => {
      if (!window.confirm(t("confirm.clearChat"))) return;
      applySnapshot(await invoke("clear_chat", { peerId: chat }));
      closeModal();
    };
    document.getElementById("pi-del").onclick = async () => {
      if (!window.confirm(t("confirm.deletePeer"))) return;
      applySnapshot(await invoke("remove_contact", { peerId: chat }));
      closeModal();
    };
  }

  async function boot() {
    window.VOID_I18N.applyDom();
    window.addEventListener("void-lang", () => {
      window.VOID_I18N.applyDom();
      lastContactSig = "";
      lastMsgSig = "";
      if (!invoke) {
        els.unlockSubtitle.textContent = t("unlock.needTauri");
      } else if (!snapshot?.unlocked) {
        els.unlockSubtitle.textContent =
          vaultKind === "create_profile"
            ? t("unlock.createVault")
            : vaultKind === "migrate_plain_master"
              ? t("unlock.migrateKey")
              : t("unlock.enterVault");
      }
      if (snapshot) applySnapshotNow(snapshot);
    });
    wireIcons();
    closeModal();
    hideCtx();
    els.toast.hidden = true;
    els.toast.textContent = "";

    invoke = resolveInvoke();
    if (!invoke) {
      els.unlockSubtitle.textContent = t("unlock.needTauri");
      return;
    }

    const status = await invoke("vault_status");
    vaultKind = status.kind;
    const needConfirm = vaultKind === "create_profile" || vaultKind === "migrate_plain_master";
    els.confirmWrap.hidden = !needConfirm;
    els.unlockSubtitle.textContent =
      vaultKind === "create_profile"
        ? t("unlock.createVault")
        : vaultKind === "migrate_plain_master"
          ? t("unlock.migrateKey")
          : t("unlock.enterVault");

    if (status.unlocked) {
      applySnapshot(await invoke("get_snapshot"));
    } else {
      try {
        const auto = await invoke("try_auto_unlock");
        if (auto) applySnapshot(auto);
      } catch (_) {}
    }

    const listen = resolveListen();
    if (listen) {
      await listen("void://snapshot", (e) => applySnapshot(e.payload));
      await listen("void://status", (e) => {
        const msg = String(e?.payload ?? "");
        if (/файл|голос|доставл|сохран|очеред|ошибка записи|микрофон|контакт|групп/i.test(msg)) {
          showToast(msg);
        }
      });
      await listen("void://message", () => {});
      await listen("void://bootstraps", () => {});
      await listen("void://file", () => {});
      await listen("void://file-complete", (e) => {
        const p = e?.payload || {};
        if (p.filename && !/^void_voice_/i.test(p.filename || "")) {
          showToast(t("toast.fileReceived", { name: p.filename }));
        }
      });
    }

    els.unlockBtn.addEventListener("click", async () => {
      els.unlockError.hidden = true;
      try {
        const snap = await invoke("vault_unlock", {
          password: els.password.value,
          passwordConfirm: needConfirm ? els.passwordConfirm.value : null,
          remember: els.remember.checked,
        });
        applySnapshot(snap);
      } catch (e) {
        els.unlockError.hidden = false;
        els.unlockError.textContent = String(e);
      }
    });

    els.composer.addEventListener("submit", async (e) => {
      e.preventDefault();
      const text = els.messageInput.value.trim();
      if (!text) return;
      els.messageInput.value = "";
      try {
        applySnapshot(await invoke("send_message", { text }));
      } catch (err) {
        showToast(String(err));
      }
    });

    document.getElementById("menu-btn").onclick = () => {
      menuSection = "contacts";
      mainMenuModal();
    };
    els.chatPeerBtn.onclick = () => peerInfoModal();
    els.modalClose.onclick = closeModal;
    els.overlay.addEventListener("click", (e) => {
      if (e.target === els.overlay) closeModal();
    });
    document.addEventListener("click", (e) => {
      if (!els.ctxMenu.hidden && !els.ctxMenu.contains(e.target)) hideCtx();
    });
    document.getElementById("toggle-sidebar").onclick = () => {
      els.mainScreen.classList.toggle("sidebar-collapsed");
      els.sidebar.classList.remove("open");
    };
    els.contactFilter.addEventListener("input", () => {
      filter = els.contactFilter.value.trim();
      renderContacts();
      lastContactSig = contactsSig(snapshot);
    });
    els.chatList.addEventListener("click", (e) => {
      const item = e.target.closest(".chat-item");
      if (!item || !els.chatList.contains(item)) return;
      selectChat(item.dataset.id);
    });
    els.chatList.addEventListener("contextmenu", (e) => {
      const item = e.target.closest(".chat-item");
      if (!item || !els.chatList.contains(item)) return;
      e.preventDefault();
      const c = (snapshot?.contacts || []).find((x) => x.peer_id === item.dataset.id);
      if (!c) return;
      if (c.is_group) showGroupContextMenu(e.clientX, e.clientY, c);
      else showContactContextMenu(e.clientX, e.clientY, c);
    });

    els.attachBtn.onclick = async () => {
      try {
        const dialog = window.__TAURI__?.dialog;
        if (!dialog?.open) {
          showToast(t("toast.noFileDialog"));
          return;
        }
        const selected = await dialog.open({ multiple: false });
        if (!selected) return;
        const path = Array.isArray(selected) ? selected[0] : selected;
        applySnapshot(await invoke("send_file", { path }));
      } catch (e) {
        showToast(String(e));
      }
    };

    els.voiceBtn.onclick = async () => {
      try {
        if (recording) {
          applySnapshot(await invoke("stop_voice_preview"), true);
        } else {
          applySnapshot(await invoke("start_voice"), true);
        }
      } catch (e) {
        showToast(String(e));
      }
    };
    els.recStop.onclick = els.voiceBtn.onclick;
    els.previewCancel.onclick = async () => {
      try {
        stopPreviewAudio();
        applySnapshot(await invoke("cancel_voice_preview"), true);
      } catch (e) {
        showToast(String(e));
      }
    };
    els.previewSend.onclick = async () => {
      try {
        stopPreviewAudio();
        applySnapshot(await invoke("send_voice_preview"), true);
      } catch (e) {
        showToast(String(e));
      }
    };
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }
})();
