// AccessLens client script: confirm dialogs, time-series charts, live panel. CSP-safe (no inline JS).
(function () {
  var NS = "http://www.w3.org/2000/svg";
  var $ = function (s) { return document.querySelector(s); };
  var fmt = function (n) { return Number(n).toLocaleString(); };
  var cs = getComputedStyle(document.documentElement);
  var col = function (v) { return cs.getPropertyValue(v).trim(); };

  document.addEventListener("submit", function (e) {
    var m = e.target.getAttribute && e.target.getAttribute("data-confirm");
    if (m && !confirm(m)) e.preventDefault();
  });

  // Keep the scroll position across form submits (the server redirects back to the same page).
  document.addEventListener("submit", function (e) {
    if (e.defaultPrevented || !e.target.method || e.target.method.toLowerCase() !== "post") return;
    try { sessionStorage.setItem("al-scroll", JSON.stringify({ p: location.pathname, y: window.scrollY, t: Date.now() })); } catch (x) {}
  });
  try {
    var saved = JSON.parse(sessionStorage.getItem("al-scroll") || "null");
    sessionStorage.removeItem("al-scroll");
    if (saved && saved.p === location.pathname && Date.now() - saved.t < 15000) {
      document.documentElement.style.scrollBehavior = "auto";
      window.scrollTo(0, saved.y);
      document.documentElement.style.scrollBehavior = "";
    }
  } catch (x) {}

  // Result messages are toasts: dismissable, success ones fade out; the ?msg= parameters are dropped from the URL.
  var toast = $(".flash.toast");
  if (toast) {
    var close = function () { toast.remove(); };
    toast.querySelector(".x").addEventListener("click", close);
    if (toast.classList.contains("ok")) setTimeout(close, 6000);
    var u = new URL(location.href);
    if (u.searchParams.has("msg")) {
      u.searchParams.delete("msg"); u.searchParams.delete("ok");
      history.replaceState(null, "", u.pathname + u.search + u.hash);
    }
  }

  // Sidebar: collapsible section lists + scroll-spy for the current page.
  var navKey = "al-nav-open", openMap = {};
  try { openMap = JSON.parse(localStorage.getItem(navKey) || "{}"); } catch (x) {}
  document.querySelectorAll(".navgroup").forEach(function (g) {
    var k = g.getAttribute("data-nav"), btn = g.querySelector(".navtoggle");
    if (openMap[k] !== undefined && !g.classList.contains("open") === openMap[k]) {
      g.classList.toggle("open", openMap[k]);
      btn.setAttribute("aria-expanded", openMap[k] ? "true" : "false");
    } else if (openMap[k] === false && g.classList.contains("open")) {
      // current page group: honour an explicit collapse
      g.classList.remove("open"); btn.setAttribute("aria-expanded", "false");
    }
    btn.addEventListener("click", function () {
      var o = g.classList.toggle("open");
      btn.setAttribute("aria-expanded", o ? "true" : "false");
      openMap[k] = o;
      try { localStorage.setItem(navKey, JSON.stringify(openMap)); } catch (x) {}
    });
  });
  var spyLinks = {};
  document.querySelectorAll(".navgroup .subnav a").forEach(function (a) {
    if (a.pathname !== location.pathname) return;
    spyLinks[a.getAttribute("data-section")] = a;
    a.addEventListener("click", function () {
      var side = $(".side");
      if (side) { side.classList.remove("open"); var m = $("#menu-btn"); if (m) m.setAttribute("aria-expanded", "false"); }
    });
  });
  if ("IntersectionObserver" in window && Object.keys(spyLinks).length) {
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (en) {
        if (!en.isIntersecting) return;
        Object.keys(spyLinks).forEach(function (id) { spyLinks[id].classList.toggle("on", id === en.target.id); });
      });
    }, { rootMargin: "-10% 0px -75% 0px" });
    Object.keys(spyLinks).forEach(function (id) { var t = document.getElementById(id); if (t) io.observe(t); });
  }

  var mb = $("#menu-btn"), side = $(".side");
  if (mb && side) {
    mb.addEventListener("click", function () {
      var o = side.classList.toggle("open");
      mb.setAttribute("aria-expanded", o ? "true" : "false");
    });
  }

  // Theme switch: system (follow OS) / light / dark, remembered per browser.
  function currentTheme() {
    try { return localStorage.getItem("al-theme") || "system"; } catch (e) { return "system"; }
  }
  function markTheme() {
    var t = currentTheme();
    document.querySelectorAll("[data-theme-set]").forEach(function (b) {
      b.classList.toggle("on", b.getAttribute("data-theme-set") === t);
    });
  }
  document.addEventListener("click", function (e) {
    var b = e.target.closest && e.target.closest("[data-theme-set]");
    if (!b) return;
    var t = b.getAttribute("data-theme-set");
    try { t === "system" ? localStorage.removeItem("al-theme") : localStorage.setItem("al-theme", t); } catch (x) {}
    if (t === "system") document.documentElement.removeAttribute("data-theme");
    else document.documentElement.setAttribute("data-theme", t);
    markTheme();
    cs = getComputedStyle(document.documentElement);
    window.dispatchEvent(new Event("themechange"));
  });
  markTheme();
  if (window.matchMedia) {
    window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", function () {
      cs = getComputedStyle(document.documentElement);
      window.dispatchEvent(new Event("themechange"));
    });
  }

  function el(name, attrs, text) {
    var n = document.createElementNS(NS, name);
    for (var k in attrs) n.setAttribute(k, attrs[k]);
    if (text) n.textContent = text;
    return n;
  }

  function label(t, bucket) {
    var d = new Date(t * 1000);
    if (bucket >= 86400) return d.toLocaleDateString([], { month: "short", day: "numeric" });
    if (bucket >= 3600) return d.toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
    return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  }

  // Stacked local/remote bar chart rendered as SVG.
  function bars(host, series, bucket) {
    host.textContent = "";
    var W = 800, H = host.classList.contains("small") ? 110 : 170, pl = 38, pb = 18, pt = 6;
    var svg = el("svg", { viewBox: "0 0 " + W + " " + H, preserveAspectRatio: "none" });
    var max = Math.max.apply(null, series.map(function (s) { return s.local + s.remote; }).concat([1]));
    var iw = (W - pl) / Math.max(series.length, 1), ih = H - pb - pt;
    [0, 0.5, 1].forEach(function (f) {
      var y = pt + ih * (1 - f);
      svg.appendChild(el("line", { x1: pl, x2: W, y1: y, y2: y, stroke: col("--line"), "stroke-width": 1 }));
      svg.appendChild(el("text", { x: pl - 4, y: y + 3, "text-anchor": "end", "font-size": 10, fill: col("--muted") }, fmt(Math.round(max * f))));
    });
    series.forEach(function (s, i) {
      var x = pl + i * iw, hl = ih * s.local / max, hr = ih * s.remote / max;
      var g = el("g", {});
      g.appendChild(el("title", {}, label(s.t, bucket) + "\nlocal " + fmt(s.local) + " · remote " + fmt(s.remote) + (s.errors ? " · errors " + fmt(s.errors) : "")));
      g.appendChild(el("rect", { x: x, y: 0, width: iw, height: H - pb, fill: "transparent" }));
      g.appendChild(el("rect", { x: x + iw * 0.1, y: pt + ih - hl, width: iw * 0.8, height: hl, fill: col("--local") }));
      g.appendChild(el("rect", { x: x + iw * 0.1, y: pt + ih - hl - hr, width: iw * 0.8, height: hr, fill: col("--remote") }));
      svg.appendChild(g);
    });
    var n = Math.min(6, series.length);
    for (var k = 0; k < n; k++) {
      var i = Math.floor(k * (series.length - 1) / Math.max(n - 1, 1));
      svg.appendChild(el("text", { x: pl + i * iw + iw / 2, y: H - 4, "text-anchor": k === 0 ? "start" : k === n - 1 ? "end" : "middle", "font-size": 10, fill: col("--muted") }, label(series[i].t, bucket)));
    }
    host.appendChild(svg);
  }

  var ts = $("#ts-chart");
  if (ts) {
    var loadTs = function () {
      fetch("/api/timeseries?" + ts.getAttribute("data-qs"), { credentials: "same-origin" })
        .then(function (r) { return r.json(); })
        .then(function (d) { bars(ts, d.series, d.bucket); });
    };
    loadTs();
    setInterval(loadTs, 60000);
    window.addEventListener("themechange", loadTs);
  }

  var live = $("#live");
  if (live) {
    var tb = $("#live-table tbody");
    var srcNames = JSON.parse(live.getAttribute("data-src") || "{}");
    var cell = function (tr, text, cls) {
      var td = document.createElement("td");
      td.textContent = text;
      if (cls) td.className = cls;
      tr.appendChild(td);
      return td;
    };
    var tick = function () {
      fetch("/api/live", { credentials: "same-origin" })
        .then(function (r) { if (r.status === 401 || r.redirected) location.href = "/login"; return r.json(); })
        .then(function (d) {
          bars($("#live-chart"), d.series, 60);
          var s = d.last5;
          $("#live-sum").textContent = "Last 5 min: " + fmt(s.total) + " requests · " + fmt(s.ips) + " clients · " +
            fmt(s.local) + " local / " + fmt(s.remote) + " remote";
          tb.textContent = "";
          d.recent.forEach(function (e) {
            var tr = document.createElement("tr");
            cell(tr, new Date(e.ts * 1000).toLocaleTimeString(), "nowrap");
            var sp = document.createElement("span");
            sp.className = "pill src s-" + e.source;
            sp.textContent = srcNames[e.source] || e.source;
            cell(tr, "").appendChild(sp);
            cell(tr, e.service);
            cell(tr, e.ip + (e.alias ? " (" + e.alias + ")" : ""), "nowrap");
            var w = cell(tr, "");
            var p = document.createElement("span");
            p.className = "pill net-" + (e.network || "").toLowerCase();
            p.textContent = (e.network || "?") + (e.country ? " · " + e.country : "");
            w.appendChild(p);
            cell(tr, e.device + " · " + e.app);
            cell(tr, e.method + " " + e.path, "clip").title = e.ua;
            var st = cell(tr, e.status || "–", "st s" + Math.floor(e.status / 100));
            tb.appendChild(tr);
          });
        })
        .catch(function () {});
    };
    tick();
    setInterval(tick, 3000);
    window.addEventListener("themechange", tick);
  }
})();
