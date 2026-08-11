(() => {
  const asset = (name) => {
    const encoded = name.split("/").map(encodeURIComponent).join("/");
    // cache-bust cropped icons (old padded PNGs were cached by WebView)
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

  function messagesSig(s) {
    const msgs = s?.messages || [];
    return msgs
      .map((m) => `${m.id}:${m.delivery}:${m.text?.length || 0}:${m.voice_transfer_id || ""}`)
      .join("|");
  }

  function contactsSig(s) {
    return (s?.contacts || [])
      .map((c) => `${c.peer_id}:${c.online}:${c.last_preview || ""}`)
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
    // Never toast raw network chatter (bootstrap failover, dial noise, etc.).
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
      ? (s.bootstrap_connected > 0 ? "в сети" : "есть соединения")
      : (s.bootstraps?.length ? "нет связи с bootstrap" : "bootstrap не задан");
    els.connStatus.textContent =
      `${netLabel}${relay} · ${pidShort}… · live ${live} · контакты ${s.connected_peers} · bootstrap ${s.bootstrap_connected}/${s.bootstraps?.length || 0}`;
    els.connStatus.title = [s.peer_id || "", ...(s.bootstraps || []).slice(0, 4)]
      .filter(Boolean)
      .join("\n");
    els.connStatus.style.color = s.relay_reserved
      ? "var(--accent)"
      : (s.network_ok ? "#c9a227" : "var(--danger)");

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
    if (s.selected_chat) {
      const c = (s.contacts || []).find((x) => x.peer_id === s.selected_chat);
      els.chatTitle.textContent = c?.display_name || s.selected_chat.slice(0, 16);
      if (c?.is_group) {
        els.chatSub.textContent = "Группа";
      } else if (c?.online) {
        els.chatSub.textContent = "в сети";
      } else {
        els.chatSub.textContent = "не в сети";
      }
    } else {
      els.chatTitle.textContent = "Выберите чат";
      els.chatSub.textContent = "";
    }
    recording = !!s.voice_recording;
    els.composer.classList.toggle("recording", recording);
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
        const next = await invoke("select_chat", { chatId: c.peer_id });
        applySnapshot(next);
        if (window.matchMedia("(max-width: 820px)").matches) {
          els.mainScreen.classList.add("sidebar-collapsed");
        }
        els.sidebar.classList.remove("open");
      });
      els.chatList.appendChild(item);
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
      const body = m.voice_transfer_id
        ? `🎤 Голосовое (${(m.voice_duration_secs || 0).toFixed(1)} с)`
        : m.text;
      div.innerHTML = `<div class="body"></div><div class="meta"><span></span><span></span></div>`;
      div.querySelector(".body").textContent = body;
      const meta = div.querySelectorAll(".meta span");
      meta[0].textContent = m.timestamp || "";
      meta[1].textContent = m.outgoing ? deliveryMark(m.delivery) : "";
      els.messages.appendChild(div);
    });
    // Keep position unless caller scrolls to bottom.
    if (els.messages.scrollHeight === prevHeight) {
      els.messages.scrollTop = prevScroll;
    }
  }

  function renderFileOffers() {
    els.fileOffers.innerHTML = "";
    (snapshot?.incoming_files || []).forEach((f) => {
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
            if (picked === null) {
              // Отмена диалога → папка по умолчанию VOID/void_downloads
              saveDir = null;
            } else {
              saveDir = Array.isArray(picked) ? picked[0] : picked;
            }
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

  function menuModal() {
    openModal(`
      <h3>Меню</h3>
      <div class="stack">
        <label class="field"><span>PeerId / multiaddr / IP</span><input id="m-peer" /></label>
        <label class="field"><span>Имя</span><input id="m-name" placeholder="Необязательно" /></label>
        <button class="btn primary" id="m-add">Добавить контакт</button>
        <hr style="border-color:var(--line)" />
        <label class="field"><span>Название группы</span><input id="m-gname" /></label>
        <label class="field"><span>Участники (PeerId через запятую)</span><input id="m-gmembers" /></label>
        <button class="btn" id="m-gcreate">Создать группу</button>
        <label class="field"><span>Ссылка void://group/…</span><input id="m-glink" /></label>
        <button class="btn" id="m-gjoin">Войти в группу</button>
      </div>`);
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
    document.getElementById("m-gcreate").onclick = async () => {
      try {
        const members = document
          .getElementById("m-gmembers")
          .value.split(",")
          .map((s) => s.trim())
          .filter(Boolean);
        const snap = await invoke("create_group", {
          name: document.getElementById("m-gname").value,
          memberPeerIds: members,
        });
        applySnapshot(snap);
        closeModal();
      } catch (e) {
        showToast(String(e));
      }
    };
    document.getElementById("m-gjoin").onclick = async () => {
      try {
        const snap = await invoke("join_group", {
          link: document.getElementById("m-glink").value,
        });
        applySnapshot(snap);
        closeModal();
      } catch (e) {
        showToast(String(e));
      }
    };
  }

  function networkModal() {
    const boots = (snapshot?.bootstraps || []).map((b) => `<div>${escapeHtml(b)}</div>`).join("") || "<div>Пока пусто — войдите через IP ноды</div>";
    const dht = (snapshot?.dht_lines || []).slice(0, 40).map((l) => `<div>${escapeHtml(l)}</div>`).join("");
    openModal(`
      <h3>Сеть VOID</h3>
      <div class="stack">
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
            : "Нет relay-резервации — собеседники за NAT до вас не дозвонятся. Подключите bootstrap и дождитесь «СВЯЗЬ ЧЕРЕЗ RELAY»."
        }</p>
        <p class="muted">Сейчас online: ${
          (snapshot?.contacts || [])
            .filter((c) => c.online)
            .map((c) => escapeHtml(c.display_name || c.peer_id.slice(0, 12)))
            .join(", ") || "—"
        }</p>
        <p class="muted">Bootstrap-адреса хранятся в vault.bin и дополняются при подключении новых нод.</p>
        <label class="field"><span>IP / IP:PORT / multiaddr</span><input id="n-join" placeholder="например 1.2.3.4:50001" /></label>
        <button class="btn primary" id="n-go">Войти в VOID</button>
        <button class="btn" id="n-reload">Переподключить bootstrap</button>
        <button class="btn" id="n-dht">Снимок DHT</button>
        <div><strong>Bootstrap (${snapshot?.bootstraps?.length || 0})</strong><div class="bootstrap-list">${boots}</div></div>
        <div><strong>DHT (${snapshot?.dht_total || 0})</strong><div class="bootstrap-list">${dht}</div></div>
      </div>`);
    document.getElementById("n-go").onclick = async () => {
      try {
        applySnapshot(await invoke("join_via_node", { input: document.getElementById("n-join").value }));
        showToast("Подключение…");
      } catch (e) {
        showToast(String(e));
      }
    };
    document.getElementById("n-reload").onclick = async () => {
      applySnapshot(await invoke("reload_bootstraps"));
      showToast("Bootstrap перезагружены");
    };
    document.getElementById("n-dht").onclick = async () => {
      applySnapshot(await invoke("snapshot_dht"));
      networkModal();
    };
  }

  function settingsModal() {
    openModal(`
      <h3>Настройки</h3>
      <div class="stack">
        <label class="field"><span>Ник</span><input id="s-nick" value="${escapeAttr(snapshot?.nickname || "")}" /></label>
        <label class="field"><span>Ваш Peer ID</span><input id="s-peer" readonly value="${escapeAttr(snapshot?.peer_id || "")}" /></label>
        <p class="muted">Публичный IP: ${escapeHtml(snapshot?.public_ip || "—")}</p>
        <button class="btn primary" id="s-save">Сохранить ник</button>
        <button class="btn" id="s-copy">Копировать Peer ID</button>
        <button class="btn" id="s-downloads">Открыть папку загрузок</button>
        <button class="btn" id="s-quit">Полный выход</button>
      </div>`);
    document.getElementById("s-save").onclick = async () => {
      try {
        applySnapshot(await invoke("set_nickname", { nickname: document.getElementById("s-nick").value }));
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

  function escapeHtml(s) {
    return String(s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;");
  }
  function escapeAttr(s) {
    return escapeHtml(s).replace(/"/g, "&quot;");
  }

  async function boot() {
    wireIcons();
    // Ensure blockers are off before any async work.
    closeModal();
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
        if (/файл|голос|доставл|сохран|очеред|ошибка записи|микрофон/i.test(msg)) {
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
        if (p.saved_to) {
          showToast(`Сохранено:\n${p.saved_to}`);
          try {
            await invoke("reveal_path", { path: p.saved_to });
          } catch (_) {
            try {
              await invoke("open_downloads");
            } catch (_) {}
          }
        } else if (p.filename) {
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

    document.getElementById("menu-btn").onclick = menuModal;
    document.getElementById("network-btn").onclick = networkModal;
    document.getElementById("settings-btn").onclick = settingsModal;
    document.getElementById("header-settings-btn").onclick = settingsModal;
    els.modalClose.onclick = closeModal;
    els.overlay.addEventListener("click", (e) => {
      if (e.target === els.overlay) closeModal();
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
