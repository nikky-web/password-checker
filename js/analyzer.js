/* Password analyzer — runs 100% in the browser. Nothing is sent anywhere. */
(function (root) {
  "use strict";

  // Most-used passwords from public breach compilations (rank order, trimmed).
  var COMMON = [
    "123456","password","123456789","12345678","12345","qwerty","abc123","football","1234567","monkey",
    "111111","letmein","1234","1234567890","dragon","baseball","sunshine","iloveyou","trustno1","princess",
    "adobe123","123123","welcome","login","admin","qwerty123","solo","1q2w3e4r","master","666666",
    "photoshop","1qaz2wsx","qwertyuiop","ashley","mustang","121212","starwars","654321","bailey","access",
    "flower","555555","passw0rd","shadow","lovely","7777777","michael","!@#$%^&*","jesus","password1",
    "superman","hello","charlie","888888","696969","hottie","freedom","aa123456","qazwsx","ninja",
    "azerty","loveme","whatever","donald","batman","zaq1zaq1","000000","123qwe","killer","jordan",
    "jennifer","hunter","buster","soccer","harley","andrew","tigger","joshua","pepper","summer",
    "ginger","hockey","matrix","computer","cookie","maggie","thomas","robert","daniel","banana",
    "chocolate","secret","nicole","london","pokemon","samsung","blink182","family","purple","angel",
    "liverpool","cheese","orange","asdfgh","asdfghjkl","zxcvbnm","zxcvbn","1q2w3e","p@ssw0rd","test",
    "test123","guest","default","root","changeme","administrator","qwe123","google","merlin","biteme",
    "abcdef","abcd1234","hello123","welcome1","monkey123","love","iloveu","lovers","friends","forever",
    "butterfly","beautiful","babygirl","tinkerbell","rockyou","miami","florida","yankees","dolphins","heat"
  ];

  // Common words people build passwords from (dictionary attack material).
  var WORDS = [
    "love","baby","angel","girl","boy","money","house","summer","winter","spring","happy","sweet","honey",
    "blue","red","green","black","pink","purple","star","moon","sun","sky","fire","water","dog","cat",
    "puppy","kitty","tiger","lion","bear","eagle","shark","dragon","monkey","horse","pass","word","password",
    "admin","user","login","welcome","hello","secret","master","super","magic","power","king","queen",
    "prince","princess","god","jesus","faith","hope","life","family","friend","school","college","work",
    "game","player","gamer","music","rock","dance","party","beach","ocean","miami","boca","florida","owls",
    "fau","cyber","hacker","computer","apple","orange","banana","cherry","coffee","pizza","chicken","cookie",
    "chocolate","soccer","football","baseball","hockey","basketball","heat","dolphins","panthers","marlins",
    "michael","jessica","ashley","daniel","david","maria","jose","carlos","nicole","chris","alex","sam",
    "test","guest","qwerty","letmein","trust","freedom","shadow","forever","always","never","killer","ninja",
    "batman","superman","spider","pokemon","mario","zelda","naruto","goku","winner","lucky","crazy","cool"
  ];

  var SEQS = ["abcdefghijklmnopqrstuvwxyz", "0123456789"];
  var KEYROWS = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890", "!@#$%^&*()", "1qaz2wsx3edc4rfv", "qazwsxedcrfv"];
  var LEET = { "4": "a", "@": "a", "3": "e", "1": "i", "!": "i", "0": "o", "5": "s", "$": "s", "7": "t", "8": "b", "9": "g", "+": "t" };

  var commonSet = {};
  COMMON.forEach(function (p, i) { commonSet[p] = i + 1; });

  function log2(n) { return Math.log(n) / Math.LN2; }

  function deLeet(s) {
    var out = "";
    for (var i = 0; i < s.length; i++) { var c = s[i]; out += LEET[c] || c; }
    return out;
  }

  function poolSize(pw) {
    var size = 0;
    if (/[a-z]/.test(pw)) size += 26;
    if (/[A-Z]/.test(pw)) size += 26;
    if (/[0-9]/.test(pw)) size += 10;
    if (/[^a-zA-Z0-9]/.test(pw)) size += 33;
    return size || 1;
  }

  // Find runs of 3+ characters that walk forward/backward along a reference string.
  function findRuns(lower, refs, type) {
    var found = [];
    var i = 0;
    while (i < lower.length - 2) {
      var best = 0;
      for (var r = 0; r < refs.length; r++) {
        var ref = refs[r];
        [ref, ref.split("").reverse().join("")].forEach(function (seq) {
          var start = seq.indexOf(lower[i]);
          while (start !== -1) {
            var len = 1;
            while (i + len < lower.length && start + len < seq.length && seq[start + len] === lower[i + len]) len++;
            if (len > best) best = len;
            start = seq.indexOf(lower[i], start + 1);
          }
        });
      }
      if (best >= 3) { found.push({ type: type, start: i, end: i + best, token: lower.slice(i, i + best) }); i += best; }
      else i++;
    }
    return found;
  }

  function findRepeats(pw) {
    var found = [];
    var re = /(.+?)\1{2,}/g, m;
    while ((m = re.exec(pw)) !== null) {
      found.push({ type: "repeat", start: m.index, end: m.index + m[0].length, token: m[0], unit: m[1] });
    }
    return found;
  }

  function findYears(pw) {
    var found = [];
    var re = /(19[5-9]\d|20[0-3]\d)/g, m;
    while ((m = re.exec(pw)) !== null) found.push({ type: "year", start: m.index, end: m.index + 4, token: m[0] });
    return found;
  }

  var EFF = (typeof module !== "undefined" && module.exports) ? require("./words.js") : (root.PwWords || []);
  var COMMON_WORDS = WORDS.concat(COMMON.filter(function (w) { return /^[a-z]{4,}$/.test(w); }));

  function findWords(pw) {
    var lower = pw.toLowerCase();
    var plain = deLeet(lower);
    var found = [];
    function scan(list, bits, minLen) {
      list.forEach(function (w) {
        if (w.length < minLen) return;
        [lower, plain].forEach(function (hay, idx) {
          var at = hay.indexOf(w);
          while (at !== -1) {
            found.push({ type: "word", start: at, end: at + w.length, token: pw.slice(at, at + w.length), word: w, base: bits, leet: idx === 1 && lower.slice(at, at + w.length) !== w });
            at = hay.indexOf(w, at + 1);
          }
        });
      });
    }
    scan(COMMON_WORDS, 11, 3);   // everyday words: top of any cracking dictionary
    scan(EFF, 13, 5);            // ~7,800-word list: still a dictionary, just bigger
    return found;
  }

  // Greedy cover: prefer longer matches so "password" beats "pass" + "word".
  function pickMatches(all) {
    all.sort(function (a, b) { return (b.end - b.start) - (a.end - a.start) || a.start - b.start; });
    var taken = [], used = {};
    all.forEach(function (m) {
      for (var i = m.start; i < m.end; i++) if (used[i]) return;
      for (var j = m.start; j < m.end; j++) used[j] = true;
      taken.push(m);
    });
    taken.sort(function (a, b) { return a.start - b.start; });
    return { matches: taken, used: used };
  }

  function matchBits(m) {
    var len = m.end - m.start;
    switch (m.type) {
      case "word":
        var bits = m.base;
        if (/[A-Z]/.test(m.token)) bits += /^[A-Z][^A-Z]*$/.test(m.token) ? 1 : 2;
        if (m.leet) bits += 1.5;
        return bits;
      case "sequence": return log2(26 * 2) + log2(len);
      case "keyboard": return log2(KEYROWS.length * 10 * 2) + log2(len);
      case "repeat": return log2(poolSize(m.unit)) * m.unit.length + log2(len / m.unit.length);
      case "year": return log2(80);
      default: return len * 4;
    }
  }

  function analyze(pw) {
    var res = {
      password: pw, length: pw.length, bits: 0, guesses: 1, score: 0, label: "Empty",
      checks: {}, patterns: [], warnings: [], suggestions: []
    };
    if (!pw) return res;

    var lower = pw.toLowerCase();
    var pool = poolSize(pw);

    res.checks = {
      length: pw.length >= 12,
      lower: /[a-z]/.test(pw),
      upper: /[A-Z]/.test(pw),
      number: /[0-9]/.test(pw),
      symbol: /[^a-zA-Z0-9]/.test(pw),
      notCommon: true,
      noPatterns: true
    };

    var rank = commonSet[lower] || commonSet[deLeet(lower)];
    if (rank) {
      res.checks.notCommon = false;
      res.checks.noPatterns = false;
      res.bits = log2(rank) + (pw !== lower ? 1 : 0);
      res.patterns.push({ type: "common", token: pw, start: 0, end: pw.length, note: "Top-" + (rank <= 10 ? "10" : rank <= 50 ? "50" : "150") + " most-used password" });
      res.warnings.push("This is one of the most common passwords on the internet. It's in every attacker's list.");
    } else {
      var candidates = []
        .concat(findWords(pw))
        .concat(findRuns(lower, SEQS, "sequence"))
        .concat(findRuns(lower, KEYROWS, "keyboard"))
        .concat(findRepeats(pw))
        .concat(findYears(pw));
      var picked = pickMatches(candidates);
      var bits = 0;
      picked.matches.forEach(function (m) {
        bits += matchBits(m);
        res.patterns.push({ type: m.type, token: m.token, start: m.start, end: m.end });
      });
      var loose = 0;
      for (var i = 0; i < pw.length; i++) if (!picked.used[i]) loose++;
      bits += loose * log2(pool);
      // A tiny bonus for mixing patterns together, capped by brute force.
      if (picked.matches.length > 1) bits += log2(picked.matches.length);
      res.bits = Math.min(bits, pw.length * log2(pool));

      if (picked.matches.length) res.checks.noPatterns = false;
      var types = {};
      picked.matches.forEach(function (m) { types[m.type] = true; });
      if (types.word) res.warnings.push("Contains dictionary words. Attackers try those first, even with l33t swaps like @ for a.");
      if (types.sequence) res.warnings.push("Contains a sequence like abc or 123. Those are tried early.");
      if (types.keyboard) res.warnings.push("Contains a keyboard pattern like qwerty or asdf.");
      if (types.repeat) res.warnings.push("Contains repeated characters. aaa or abcabc add almost nothing.");
      if (types.year) res.warnings.push("Contains a year. Birth years and grad years are easy to guess.");
    }

    res.bits = Math.max(0, res.bits);
    res.guesses = Math.pow(2, res.bits);

    var b = res.bits;
    res.score = b < 28 ? 0 : b < 40 ? 1 : b < 60 ? 2 : b < 80 ? 3 : 4;
    res.label = ["Very weak", "Weak", "Fair", "Strong", "Very strong"][res.score];

    if (!res.checks.length) res.suggestions.push("Go for 12+ characters. Length beats complexity every time.");
    if (res.checks.length && pw.length < 16 && res.score < 4) res.suggestions.push("Push it to 16+ characters for a real safety margin.");
    if (!res.checks.symbol && res.score < 4) res.suggestions.push("Throw in a symbol somewhere that isn't the very end.");
    if (!res.checks.upper && res.score < 4) res.suggestions.push("Mix in an uppercase letter that isn't the first character.");
    if (!res.checks.noPatterns) res.suggestions.push("Skip words, names, years, and keyboard runs, or use 4+ random words as a passphrase.");
    if (res.score >= 3) res.suggestions.push("Use it on one site only and store it in a password manager.");

    return res;
  }

  // Attack scenarios: guesses per second.
  var SCENARIOS = [
    { id: "online-slow", name: "Online, rate-limited", detail: "Login page that locks you out (~100 guesses/hour)", rate: 100 / 3600 },
    { id: "online-fast", name: "Online, no limit", detail: "Badly built login page (~10 guesses/sec)", rate: 10 },
    { id: "offline-slow", name: "Offline, slow hash", detail: "Stolen database using bcrypt (~10k guesses/sec)", rate: 1e4 },
    { id: "offline-fast", name: "Offline, fast hash", detail: "Stolen MD5/SHA-1 hashes on a GPU rig (~10B guesses/sec)", rate: 1e10 }
  ];

  function crackSeconds(guesses, rate) { return (guesses / 2) / rate; }

  function humanTime(s) {
    if (!isFinite(s) || s > 4.3e17) return { text: "Longer than the universe has existed", tier: 4 };
    if (s < 1) return { text: "Instantly", tier: 0 };
    var units = [["second", 60], ["minute", 60], ["hour", 24], ["day", 30.44], ["month", 12], ["year", 100], ["century", Infinity]];
    var v = s, i = 0;
    while (i < units.length - 1 && v >= units[i][1]) { v /= units[i][1]; i++; }
    var n = Math.round(v);
    var unit = units[i][0];
    var plural = unit === "century" ? "centuries" : unit + "s";
    var text;
    if (unit === "century" && n >= 1000) {
      var big = n * 100;
      text = big >= 1e12 ? "Trillions of years" : big >= 1e9 ? "Billions of years" : big >= 1e6 ? "Millions of years" : "Thousands of years";
    } else {
      text = n + " " + (n === 1 ? unit : plural);
    }
    var tier = s < 3600 ? 0 : s < 86400 * 30 ? 1 : s < 3.15e7 * 10 ? 2 : s < 3.15e7 * 1000 ? 3 : 4;
    return { text: text, tier: tier };
  }

  var api = { analyze: analyze, SCENARIOS: SCENARIOS, crackSeconds: crackSeconds, humanTime: humanTime, poolSize: poolSize };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else root.PwAnalyzer = api;
})(this);
