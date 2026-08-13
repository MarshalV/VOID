(() => {
  const asset = (name) => {
    const encoded = name.split("/").map(encodeURIComponent).join("/");
    return `static/${encoded}?v=7`;
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
    toast: document.getElementById("toast"),
    sidebar: document.getElementById("sidebar"),
    ctxMenu: document.getElementById("ctx-menu"),
  };

  let invoke = null;
  let snapshot = null;
  let vaultKind = "open_wrapped_key";
  let recording = false;
  let filter = "";
  let lastMsgSig = "";
  let lastContactSig = "";
  let snapTimer = null;
  let pendingSnap = null;
  let activeAudio = null;
  let menuSection = "contacts";

  function messagesSig(s) {
    const msgs = s?.messages || [];
    return msgs
      .map(
        (m) =>
          `${m.id}:${m.delivery}:${m.text?.length || 0}:${m.voice_transfer_id || ""}:${m.voice_path || ""}`
      )
      .join("|");
  }

  function contactsSig(s) {
    return (s?.contacts || [])
      .map((c) => `${c.peer_id}:${c.online}:${c.display_name}:${c.last_preview || ""}`)
      .join("|");
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

  function applySnapshotNow(s) {
    if (!s) return;
    snapshot = s;
    if (s.unlocked) {
      els.unlockScreen.hidden = true;
      els.mainScreen.hidden = false;
    }
    els.beaconBanner.hidden = !s.beacon_active;
    const pidShort = (s.peer_id || "").slice(0, 12);
    const live = (s.bootstrap_connected || 0) + (s.connected_peers || 0);
    const relay = s.relay_reserved ? " · relay Hop OK" : " · нет Hop (NAT закрыт)";
    const netLabel = s.network_ok
      ? s.bootstrap_connected > 0
        ? "в сети"
        : "есть соединения"
      : s.bootstraps?.length
        ? "нет связи с bootstrap"
        : "bootstrap не задан";
    els.connStatus.textContent = `${netLabel}${relay} · ${pidShort}… · live ${live} · контакты ${s.connected_peers} · bootstrap ${s.bootstrap_connected}/${s.bootstraps?.length || 0}`;
    els.connStatus.title = [s.peer_id || "", ...(s.bootstraps || []).slice(0, 4)]
      .filter(Boolean)
      .join("\n");
    els.connStatus.style.color = s.relay_reserved
      ? "var(--accent)"
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
    const enabled = !!s.selected_chat;
    els.messageInput.disabled = !enabled;
    els.sendBtn.disabled = !enabled;
    updateChatHeader(s);
    recording = !!s.voice_recording;
    els.composer.classList.toggle("recording", recording);
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
      els.chatSub.textContent = "Группа";
    } else if (c?.online) {
      els.chatSub.textContent = "в сети · " + (c.peer_id || "").slice(0, 16) + "…";
    } else {
      els.chatSub.textContent =
        "не в сети · PeerId " + (c?.peer_id || s.selected_chat || "").slice(0, 20) + "…";
      els.chatSub.title = c?.peer_id || s.selected_chat || "";
    }
  }

  function applySnapshot(s) {
    if (!s) return;
    pendingSnap = s;
    if (snapTimer) return;
    snapTimer = setTimeout(() => {
      snapTimer = null;
      const next = pendingSnap;
      pendingSnap = null;
      applySnapshotNow(next);
    }, 80);
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
      const letter = (c.display_name || "?").trim().charAt(0).toUpperCase();
      item.innerHTML = `
        <div class="avatar ${c.online ? "online" : ""}" style="background:${avatarColor(c.peer_id)}">${letter}</div>
        <div>
          <h3></h3>
          <p></p>
        </div>`;
      item.querySelector("h3").textContent = c.display_name;
      item.querySelector("p").textContent = c.online
        ? "в сети"
        : c.last_preview || (c.is_group ? "Группа" : c.peer_id.slice(0, 20));
      item.addEventListener("click", async () => {
        hideCtx();
        const next = await invoke("select_chat", { chatId: c.peer_id });
        applySnapshot(next);
        if (window.matchMedia("(max-width: 820px)").matches) {
          els.mainScreen.classList.add("sidebar-collapsed");
        }
        els.sidebar.classList.remove("open");
      });
      item.addEventListener("contextmenu", (e) => {
        e.preventDefault();
        if (c.is_group) return;
        showContactContextMenu(e.clientX, e.clientY, c);
      });
      els.chatList.appendChild(item);
    });
  }

  function showContactContextMenu(x, y, c) {
    els.ctxMenu.innerHTML = `
      <button type="button" data-act="rename">Переименовать контакт</button>
      <button type="button" data-act="clear">Очистить чат</button>
      <button type="button" data-act="copy">Копировать Peer ID</button>
      <button type="button" data-act="delete" class="danger">Удалить пир</button>`;
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
            showToast("Peer ID скопирован");
          } else if (act === "rename") {
            const name = window.prompt("Новое имя контакта", c.display_name || "");
            if (name == null || !name.trim()) return;
            applySnapshot(await invoke("rename_contact", { peerId: c.peer_id, name: name.trim() }));
          } else if (act === "clear") {
            if (!window.confirm("Очистить переписку с этим контактом?")) return;
            applySnapshot(await invoke("clear_chat", { peerId: c.peer_id }));
          } else if (act === "delete") {
            if (!window.confirm("Удалить контакт из книги?")) return;
            applySnapshot(await invoke("remove_contact", { peerId: c.peer_id }));
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
        const dur = (m.voice_duration_secs || 0).toFixed(1);
        const ready = !!m.voice_path;
        div.innerHTML = `
          <div class="voice-player" data-tid="${escapeAttr(m.voice_transfer_id)}">
            <button type="button" class="voice-play" ${ready ? "" : "disabled"} title="${ready ? "Play/Pause" : "Ещё загружается…"}">${ready ? "▶" : "…"}</button>
            <input type="range" class="voice-seek" min="0" max="1000" value="0" ${ready ? "" : "disabled"} />
            <span class="voice-time">0:00 / ${fmtTime(m.voice_duration_secs || 0)}</span>
          </div>
          <div class="meta"><span></span><span></span></div>`;
        const meta = div.querySelectorAll(".meta span");
        meta[0].textContent = m.timestamp || "";
        meta[1].textContent = m.outgoing ? deliveryMark(m.delivery) : "";
        if (ready) wireVoiceControls(div, m);
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

  function wireVoiceControls(div, m) {
    const root = div.querySelector(".voice-player");
    const playBtn = root.querySelector(".voice-play");
    const seek = root.querySelector(".voice-seek");
    const timeEl = root.querySelector(".voice-time");
    const src = convertFileSrc(m.voice_path);
    let audio = null;

    const ensureAudio = () => {
      if (audio) return audio;
      audio = new Audio(src);
      audio.preload = "metadata";
      audio.addEventListener("timeupdate", () => {
        if (!audio.duration) return;
        seek.value = String(Math.floor((audio.currentTime / audio.duration) * 1000));
        timeEl.textContent = `${fmtTime(audio.currentTime)} / ${fmtTime(audio.duration || m.voice_duration_secs || 0)}`;
      });
      audio.addEventListener("ended", () => {
        playBtn.textContent = "▶";
        seek.value = "0";
      });
      audio.addEventListener("play", () => {
        playBtn.textContent = "❚❚";
      });
      audio.addEventListener("pause", () => {
        playBtn.textContent = "▶";
      });
      return audio;
    };

    playBtn.onclick = async () => {
      try {
        const a = ensureAudio();
        if (activeAudio && activeAudio !== a) {
          activeAudio.pause();
        }
        activeAudio = a;
        if (a.paused) await a.play();
        else a.pause();
      } catch (e) {
        showToast("Не удалось воспроизвести: " + e);
      }
    };

    seek.oninput = () => {
      const a = ensureAudio();
      if (!a.duration) return;
      a.currentTime = (Number(seek.value) / 1000) * a.duration;
    };
  }

  function renderFileOffers() {
    els.fileOffers.innerHTML = "";
    (snapshot?.incoming_files || []).forEach((f) => {
      if (/^void_voice_/i.test(f.filename || "")) return;
      const row = document.createElement("div");
      row.className = "offer";
      row.innerHTML = `<span></span>`;
      row.querySelector("span").textContent = `Файл: ${f.filename} (${f.total_size} байт)`;
      const acc = document.createElement("button");
      acc.className = "btn primary";
      acc.textContent = "Принять";
      acc.onclick = async () => {
        try {
          let saveDir = null;
          const dialog = window.__TAURI__?.dialog;
          if (dialog?.open) {
            const picked = await dialog.open({
              directory: true,
              multiple: false,
              title: "Куда сохранить файл",
            });
            if (picked === null) saveDir = null;
            else saveDir = Array.isArray(picked) ? picked[0] : picked;
          }
          await invoke("accept_file", { transferId: f.transfer_id, saveDir });
          showToast("Принято — ждём передачу…");
          applySnapshot(await invoke("get_snapshot"));
        } catch (e) {
          showToast(String(e));
        }
      };
      const rej = document.createElement("button");
      rej.className = "btn";
      rej.textContent = "Отклонить";
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
        <button type="button" class="menu-tab ${active === "contacts" ? "active" : ""}" data-sec="contacts">Контакты</button>
        <button type="button" class="menu-tab ${active === "groups" ? "active" : ""}" data-sec="groups">Группы</button>
        <button type="button" class="menu-tab ${active === "network" ? "active" : ""}" data-sec="network">Сеть</button>
        <button type="button" class="menu-tab ${active === "settings" ? "active" : ""}" data-sec="settings">Настройки</button>
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
        <h4 class="menu-h">Контакты</h4>
        <label class="field"><span>PeerId / multiaddr / IP</span><input id="m-peer" /></label>
        <label class="field"><span>Имя</span><input id="m-name" placeholder="Необязательно" /></label>
        <button class="btn primary" id="m-add">Добавить контакт</button>`;
    } else if (sec === "groups") {
      const pick = contactPickerHtml([], snapshot?.peer_id);
      body = `
        <h4 class="menu-h">Группы</h4>
        <label class="field"><span>Название группы</span><input id="m-gname" /></label>
        <p class="muted">Участники из контактов</p>
        ${pick}
        <button class="btn primary" id="m-gcreate">Создать группу</button>
        <hr class="menu-hr" />
        <label class="field"><span>Ссылка void://group/…</span><input id="m-glink" /></label>
        <button class="btn" id="m-gjoin">Войти в группу</button>`;
    } else if (sec === "network") {
      const boots =
        (snapshot?.bootstraps || []).map((b) => `<div>${escapeHtml(b)}</div>`).join("") ||
        "<div>Пока пусто — войдите через IP ноды</div>";
      body = `
        <h4 class="menu-h">Сеть VOID</h4>
        <p class="muted">Ваш PeerId:</p>
        <div class="bootstrap-list" style="user-select:all">${escapeHtml(snapshot?.peer_id || "—")}</div>
        <p class="muted">Статус: ${
          snapshot?.network_ok
            ? `в сети (bootstrap ${snapshot?.bootstrap_connected || 0}, контакты ${snapshot?.connected_peers || 0})`
            : "нет активного соединения"
        }</p>
        <p class="muted">${
          snapshot?.relay_reserved
            ? "Relay-резервация есть — вас можно набрать из‑за NAT."
            : "Нет relay-резервации — собеседники за NAT до вас не дозвонятся."
        }</p>
        <p class="muted">Сейчас online: ${
          (snapshot?.contacts || [])
            .filter((c) => c.online)
            .map((c) => escapeHtml(c.display_name || c.peer_id.slice(0, 12)))
            .join(", ") || "—"
        }</p>
        <label class="field"><span>IP / IP:PORT / multiaddr</span><input id="n-join" placeholder="например 1.2.3.4:50001" /></label>
        <button class="btn primary" id="n-go">Войти в VOID</button>
        <button class="btn" id="n-reload">Переподключить bootstrap</button>
        <div><strong>Bootstrap (${snapshot?.bootstraps?.length || 0})</strong><div class="bootstrap-list">${boots}</div></div>`;
    } else {
      body = `
        <h4 class="menu-h">Настройки</h4>
        <label class="field"><span>Ник</span><input id="s-nick" value="${escapeAttr(snapshot?.nickname || "")}" /></label>
        <label class="field"><span>Ваш Peer ID</span><input id="s-peer" readonly value="${escapeAttr(snapshot?.peer_id || "")}" /></label>
        <p class="muted">Публичный IP: ${escapeHtml(snapshot?.public_ip || "—")}</p>
        <button class="btn primary" id="s-save">Сохранить ник</button>
        <button class="btn" id="s-copy">Копировать Peer ID</button>
        <button class="btn" id="s-downloads">Открыть папку загрузок</button>
        <button class="btn" id="s-quit">Полный выход</button>`;
    }

    openModal(`
      <h3>Меню</h3>
      ${menuNav(sec)}
      <div class="stack menu-section">${body}</div>`);
    wireMenuTabs();

    if (sec === "contacts") {
      document.getElementById("m-add").onclick = async () => {
        try {
          const snap = await invoke("add_contact", {
            peerOrAddr: document.getElementById("m-peer").value,
            name: document.getElementById("m-name").value,
          });
          applySnapshot(snap);
          closeModal();
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
            })
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
          showToast("Подключение…");
        } catch (e) {
          showToast(String(e));
        }
      };
      document.getElementById("n-reload").onclick = async () => {
        applySnapshot(await invoke("reload_bootstraps"));
        showToast("Bootstrap перезагружены");
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
          showToast("Peer ID скопирован");
        } catch {
          showToast("Не удалось скопировать");
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
      return `<p class="muted">Нет контактов для выбора — сначала добавьте людей в книгу.</p>`;
    }
    return `<div class="contact-pick">${list
      .map(
        (c) => `
      <label class="check pick-row">
        <input type="checkbox" data-peer="${escapeAttr(c.peer_id)}" />
        <span>${escapeHtml(c.display_name || c.peer_id.slice(0, 12))}${
          c.online ? " · в сети" : ""
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
        .join("") || "<div class=\"muted\">Нет участников</div>";
      openModal(`
        <h3>Группа</h3>
        <div class="stack">
          <p><strong>${escapeHtml(group?.name || c.display_name)}</strong></p>
          <p class="muted">Участники (${group?.members?.length || 0})</p>
          <div class="bootstrap-list">${membersHtml}</div>
          <button class="btn" id="gi-copy">Копировать invite-ссылку</button>
          <p class="muted">Пригласить из контактов</p>
          ${contactPickerHtml(memberIds, snapshot?.peer_id)}
          <button class="btn primary" id="gi-invite">Пригласить выбранных</button>
        </div>`);
      document.getElementById("gi-copy").onclick = async () => {
        const link = group?.invite_link || "";
        if (!link) {
          showToast("Нет ссылки");
          return;
        }
        try {
          await navigator.clipboard.writeText(link);
          showToast("Ссылка скопирована");
        } catch {
          showToast("Не удалось скопировать");
        }
      };
      document.getElementById("gi-invite").onclick = async () => {
        try {
          const members = selectedPickerPeers(els.modalBody);
          if (!members.length) {
            showToast("Отметьте контакты");
            return;
          }
          applySnapshot(
            await invoke("invite_to_group", {
              groupId: gid,
              memberPeerIds: members,
            })
          );
          showToast("Приглашения отправлены");
          peerInfoModal();
        } catch (e) {
          showToast(String(e));
        }
      };
      return;
    }
    openModal(`
      <h3>Собеседник</h3>
      <div class="stack">
        <div class="peer-info-avatar" style="background:${avatarColor(chat)}">${escapeHtml(
          (c?.display_name || "?").trim().charAt(0).toUpperCase()
        )}</div>
        <p><strong>${escapeHtml(c?.display_name || chat.slice(0, 16))}</strong></p>
        <p class="muted">${c?.online ? "в сети" : "не в сети"}</p>
        <p class="muted">Peer ID</p>
        <div class="bootstrap-list" style="user-select:all">${escapeHtml(chat)}</div>
        <button class="btn" id="pi-copy">Копировать Peer ID</button>
        <button class="btn" id="pi-rename">Переименовать</button>
        <button class="btn" id="pi-clear">Очистить чат</button>
        <button class="btn danger-outline" id="pi-del">Удалить пир</button>
      </div>`);
    document.getElementById("pi-copy").onclick = async () => {
      await navigator.clipboard.writeText(chat);
      showToast("Peer ID скопирован");
    };
    document.getElementById("pi-rename").onclick = async () => {
      const name = window.prompt("Новое имя", c?.display_name || "");
      if (name == null || !name.trim()) return;
      applySnapshot(await invoke("rename_contact", { peerId: chat, name: name.trim() }));
      peerInfoModal();
    };
    document.getElementById("pi-clear").onclick = async () => {
      if (!window.confirm("Очистить переписку?")) return;
      applySnapshot(await invoke("clear_chat", { peerId: chat }));
      closeModal();
    };
    document.getElementById("pi-del").onclick = async () => {
      if (!window.confirm("Удалить контакт?")) return;
      applySnapshot(await invoke("remove_contact", { peerId: chat }));
      closeModal();
    };
  }

  async function boot() {
    wireIcons();
    closeModal();
    hideCtx();
    els.toast.hidden = true;
    els.toast.textContent = "";

    invoke = resolveInvoke();
    if (!invoke) {
      els.unlockSubtitle.textContent = "Откройте через Tauri (cargo tauri dev)";
      return;
    }

    const status = await invoke("vault_status");
    vaultKind = status.kind;
    const needConfirm = vaultKind === "create_profile" || vaultKind === "migrate_plain_master";
    els.confirmWrap.hidden = !needConfirm;
    els.unlockSubtitle.textContent =
      vaultKind === "create_profile"
        ? "Создайте пароль vault (Argon2id)"
        : vaultKind === "migrate_plain_master"
          ? "Задайте пароль для старого void.key"
          : "Введите пароль vault";

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
        if (/файл|голос|доставл|сохран|очеред|ошибка записи|микрофон|контакт/i.test(msg)) {
          showToast(msg);
        }
      });
      await listen("void://message", async () => {
        applySnapshot(await invoke("get_snapshot"));
      });
      await listen("void://bootstraps", () => {});
      await listen("void://file", async () => {
        applySnapshot(await invoke("get_snapshot"));
      });
      await listen("void://file-complete", async (e) => {
        const p = e?.payload || {};
        if (p.saved_to && !/^void_voice_/i.test(p.filename || "")) {
          showToast(`Сохранено:\n${p.saved_to}`);
          try {
            await invoke("reveal_path", { path: p.saved_to });
          } catch (_) {
            try {
              await invoke("open_downloads");
            } catch (_) {}
          }
        } else if (p.filename && !/^void_voice_/i.test(p.filename || "")) {
          showToast(`Файл доставлен: ${p.filename}`);
        }
        applySnapshot(await invoke("get_snapshot"));
      });
      await listen("void://file-progress", async () => {
        applySnapshot(await invoke("get_snapshot"));
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
    });

    els.attachBtn.onclick = async () => {
      try {
        const dialog = window.__TAURI__?.dialog;
        if (!dialog?.open) {
          showToast("Диалог файлов недоступен");
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
        if (!recording) {
          await invoke("start_voice");
          recording = true;
          els.composer.classList.add("recording");
          showToast("Запись… нажмите ещё раз чтобы отправить");
        } else {
          applySnapshot(await invoke("stop_voice_send"));
          recording = false;
          els.composer.classList.remove("recording");
        }
      } catch (e) {
        showToast(String(e));
      }
    };

    setInterval(async () => {
      if (!snapshot?.unlocked) return;
      try {
        applySnapshot(await invoke("get_snapshot"));
      } catch (_) {}
    }, 4000);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }
})();
