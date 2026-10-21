(function () {
  "use strict";

  var A = window.PwAnalyzer;
  var WORDS = window.PwWords || [];
  var $ = function (id) { return document.getElementById(id); };

  /* ---------- Theme switcher (light / dark / system) ---------- */
  var root = document.documentElement;
  var mq = window.matchMedia ? window.matchMedia("(prefers-color-scheme: dark)") : null;

  function applyTheme(choice) {
    var dark = choice === "dark" || (choice === "system" && mq && mq.matches);
    root.setAttribute("data-theme", dark ? "dark" : "light");
    root.setAttribute("data-theme-choice", choice);
    document.querySelectorAll("[data-theme-choice]").forEach(function (b) {
      if (b.tagName === "BUTTON") b.setAttribute("aria-checked", String(b.getAttribute("data-theme-choice") === choice));
    });
  }
  function currentChoice() { return root.getAttribute("data-theme-choice") || "system"; }

  document.querySelectorAll(".theme-switch button").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var choice = btn.getAttribute("data-theme-choice");
      try { localStorage.setItem("theme", choice); } catch (e) {}
      applyTheme(choice);
    });
  });
  if (mq) {
    var onChange = function () { if (currentChoice() === "system") applyTheme("system"); };
    if (mq.addEventListener) mq.addEventListener("change", onChange); else if (mq.addListener) mq.addListener(onChange);
  }
  applyTheme(currentChoice());

  /* ---------- Toast ---------- */
  var toastTimer;
  function toast(msg) {
    var t = $("toast");
    t.textContent = msg;
    t.classList.add("show");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(function () { t.classList.remove("show"); }, 1800);
  }

  /* ---------- Checker ---------- */
  var input = $("pw");
  var checker = document.querySelector(".checker");
  var results = $("results");
  var breachBtn = $("breach-btn");
  var breachOut = $("breach-result");

  var TYPE_LABEL = { word: "word", common: "top password", sequence: "sequence", keyboard: "keyboard", repeat: "repeat", year: "year", loose: "random" };

  function el(tag, cls, text) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text != null) n.textContent = text;
    return n;
  }

  function renderAnatomy(r) {
    var box = $("anatomy");
    box.textContent = "";
    var segs = [];
    var pos = 0;
    r.patterns.slice().sort(function (a, b) { return a.start - b.start; }).forEach(function (p) {
      if (p.start > pos) segs.push({ type: "loose", token: r.password.slice(pos, p.start) });
      segs.push(p);
      pos = p.end;
    });
    if (pos < r.password.length) segs.push({ type: "loose", token: r.password.slice(pos) });
    segs.forEach(function (s) {
      var seg = el("span", "seg");
      seg.setAttribute("data-type", s.type);
      seg.appendChild(document.createTextNode(s.token));
      seg.appendChild(el("small", null, TYPE_LABEL[s.type] || s.type));
      box.appendChild(seg);
    });
  }

  function renderList(id, items) {
    var ul = $(id);
    ul.textContent = "";
    items.forEach(function (t) { ul.appendChild(el("li", null, t)); });
  }

  function render() {
    var pw = input.value;
    $("clear").hidden = !pw;
    breachBtn.disabled = !pw;
    breachOut.hidden = true;

    if (!pw) {
      checker.removeAttribute("data-score");
      $("label").textContent = "Waiting for a password";
      $("bits").textContent = "";
      results.hidden = true;
      return;
    }

    var r = A.analyze(pw);
    checker.setAttribute("data-score", r.score);
    $("label").textContent = r.label;
    $("bits").textContent = "≈ " + Math.round(r.bits) + " bits of entropy · " + r.length + " chars";

    var list = $("scenarios");
    list.textContent = "";
    A.SCENARIOS.forEach(function (s) {
      var t = A.humanTime(A.crackSeconds(r.guesses, s.rate));
      var li = el("li", "scenario");
      li.setAttribute("data-tier", t.tier);
      li.appendChild(el("span", "s-name", s.name));
      li.appendChild(el("span", "s-detail", s.detail));
      li.appendChild(el("span", "s-time", t.text));
      list.appendChild(li);
    });

    document.querySelectorAll("#checks li").forEach(function (li) {
      var ok = r.checks[li.getAttribute("data-check")];
      li.classList.toggle("ok", !!ok);
      li.classList.toggle("bad", !ok);
    });

    renderAnatomy(r);
    renderList("warnings", r.warnings);
    renderList("suggestions", r.suggestions);
    results.hidden = false;
  }

  var raf;
  input.addEventListener("input", function () { cancelAnimationFrame(raf); raf = requestAnimationFrame(render); });

  $("toggle-vis").addEventListener("click", function () {
    var show = input.type === "password";
    input.type = show ? "text" : "password";
    this.setAttribute("aria-pressed", String(show));
    this.setAttribute("aria-label", show ? "Hide password" : "Show password");
    input.focus();
  });

  $("clear").addEventListener("click", function () {
    input.value = "";
    render();
    input.focus();
  });

  /* ---------- Breach check (HIBP k-anonymity) ---------- */
  function sha1Hex(str) {
    return crypto.subtle.digest("SHA-1", new TextEncoder().encode(str)).then(function (buf) {
      return Array.prototype.map.call(new Uint8Array(buf), function (b) { return ("0" + b.toString(16)).slice(-2); }).join("").toUpperCase();
    });
  }

  var ICON_BAD = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 9v4M12 17h.01M10.3 3.9L1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/></svg>';
  var ICON_OK = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 3l8 3v6c0 4.5-3.4 8.3-8 9-4.6-.7-8-4.5-8-9V6z"/><path d="M8.5 12l2.5 2.5 4.5-5"/></svg>';

  function showBreach(kind, icon, text) {
    breachOut.className = "breach-result " + kind;
    breachOut.innerHTML = icon;
    breachOut.appendChild(el("span", null, text));
    breachOut.hidden = false;
  }

  breachBtn.addEventListener("click", function () {
    var pw = input.value;
    if (!pw) return;
    if (!window.crypto || !crypto.subtle) { showBreach("err", "", "Your browser can't hash securely here. Try the live HTTPS site."); return; }
    breachBtn.disabled = true;
    breachBtn.textContent = "Checking…";
    sha1Hex(pw).then(function (hash) {
      var prefix = hash.slice(0, 5), suffix = hash.slice(5);
      return fetch("https://api.pwnedpasswords.com/range/" + prefix, { headers: { "Add-Padding": "true" } })
        .then(function (res) { if (!res.ok) throw new Error("HTTP " + res.status); return res.text(); })
        .then(function (body) {
          if (input.value !== pw) return; // they kept typing
          var count = 0;
          body.split("\n").some(function (line) {
            var parts = line.trim().split(":");
            if (parts[0] === suffix) { count = parseInt(parts[1], 10) || 0; return true; }
            return false;
          });
          if (count > 0) {
            showBreach("bad", ICON_BAD, "Found in " + count.toLocaleString() + " breach record" + (count === 1 ? "" : "s") + ". Attackers already have this one. Don't use it anywhere.");
          } else {
            showBreach("good", ICON_OK, "Not found in any known breach. That's good, but strength still matters, so check the crack times above.");
          }
        });
    }).catch(function () {
      showBreach("err", "", "Couldn't reach the breach database right now. Check your connection and try again.");
    }).then(function () {
      breachBtn.disabled = !input.value;
      breachBtn.textContent = "Check breaches";
    });
  });

  /* ---------- Generator ---------- */
  function randInt(max) {
    // Unbiased integer in [0, max) using rejection sampling.
    var limit = Math.floor(0x100000000 / max) * max;
    var buf = new Uint32Array(1);
    do { crypto.getRandomValues(buf); } while (buf[0] >= limit);
    return buf[0] % max;
  }

  var mode = "phrase";
  var sizeInput = $("gen-size");
  var lastGenerated = "";

  function log2(n) { return Math.log(n) / Math.LN2; }

  function makePhrase() {
    var n = +sizeInput.value;
    var words = [];
    for (var i = 0; i < n; i++) words.push(WORDS[randInt(WORDS.length)]);
    if ($("opt-cap").checked) words = words.map(function (w) { return w.charAt(0).toUpperCase() + w.slice(1); });
    var bits = n * log2(WORDS.length);
    if ($("opt-num").checked) {
      var at = randInt(n);
      words[at] = words[at] + (10 + randInt(90));
      bits += log2(90) + log2(n);
    }
    return { value: words.join($("opt-sep").value), bits: bits };
  }

  var LOWER = "abcdefghijkmnopqrstuvwxyz", UPPER = "ABCDEFGHJKLMNPQRSTUVWXYZ", DIGITS = "23456789", SYMS = "!@#$%^&*-_=+?";
  function makeRandom() {
    var len = +sizeInput.value;
    var amb = $("opt-amb").checked;
    var sets = [amb ? LOWER : LOWER + "l", amb ? UPPER : UPPER + "IO", amb ? DIGITS : DIGITS + "01"];
    if ($("opt-sym").checked) sets.push(SYMS);
    var all = sets.join("");
    var out;
    do {
      out = "";
      for (var i = 0; i < len; i++) out += all[randInt(all.length)];
    } while (!sets.every(function (s) { for (var j = 0; j < s.length; j++) if (out.indexOf(s[j]) !== -1) return true; return false; }));
    return { value: out, bits: len * log2(all.length) };
  }

  function generate() {
    var g = mode === "phrase" ? makePhrase() : makeRandom();
    lastGenerated = g.value;
    $("gen-output").textContent = g.value;
    $("gen-size-val").textContent = sizeInput.value;
    var t = A.humanTime(A.crackSeconds(Math.pow(2, g.bits), 1e10));
    $("gen-meta").textContent = "≈ " + Math.round(g.bits) + " bits of true randomness. Even if an attacker knew exactly how it was made, a GPU rig would need " + t.text.toLowerCase() + " on average.";
  }

  function setMode(next) {
    mode = next;
    var phrase = next === "phrase";
    $("tab-phrase").setAttribute("aria-selected", String(phrase));
    $("tab-random").setAttribute("aria-selected", String(!phrase));
    $("phrase-opts").hidden = !phrase;
    $("random-opts").hidden = phrase;
    $("gen-size-label").textContent = phrase ? "Words" : "Length";
    sizeInput.min = phrase ? 3 : 12;
    sizeInput.max = phrase ? 8 : 48;
    sizeInput.value = phrase ? 5 : 20;
    generate();
  }

  $("tab-phrase").addEventListener("click", function () { setMode("phrase"); });
  $("tab-random").addEventListener("click", function () { setMode("random"); });
  document.querySelector(".tabs").addEventListener("keydown", function (e) {
    if (e.key === "ArrowRight" || e.key === "ArrowLeft") {
      setMode(mode === "phrase" ? "random" : "phrase");
      $(mode === "phrase" ? "tab-phrase" : "tab-random").focus();
    }
  });
  sizeInput.addEventListener("input", generate);
  ["opt-cap", "opt-num", "opt-sep", "opt-sym", "opt-amb"].forEach(function (id) { $(id).addEventListener("change", generate); });
  $("gen-new").addEventListener("click", generate);

  $("gen-copy").addEventListener("click", function () {
    var done = function () { toast("Copied to clipboard"); };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(lastGenerated).then(done, function () { toast("Couldn't copy. Select it and copy manually."); });
    } else {
      var r = document.createRange(); r.selectNodeContents($("gen-output"));
      var s = getSelection(); s.removeAllRanges(); s.addRange(r);
      try { document.execCommand("copy"); done(); } catch (e) { toast("Select it and copy manually."); }
    }
  });

  $("gen-test").addEventListener("click", function () {
    input.value = lastGenerated;
    render();
    $("checker").scrollIntoView({ block: "start" });
    input.focus({ preventScroll: true });
  });

  setMode("phrase");
  render();
})();
