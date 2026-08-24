/* Boule public observatory.
 * Reads same-origin GET /v1/live and renders the network pulse, problem
 * index, activity trace, and handoff dependency graph. No other network
 * calls, no storage.
 */
(function () {
  "use strict";

  var LIVE_URL = "/v1/live";
  var MAINTAINER_URL = "/v1/maintainer";
  var REFRESH_MS = 30000;
  var MAX_TIMELINE = 20;
  var MAX_GRAPH_NODES = 30;
  var SVG_NS = "http://www.w3.org/2000/svg";

  var els = {
    refreshButton: document.getElementById("refresh-button"),
    refreshMeta: document.getElementById("refresh-meta"),
    liveStatus: document.getElementById("live-status"),
    staleNote: document.getElementById("stale-note"),
    problemsState: document.getElementById("problems-state"),
    problemsWrap: document.getElementById("problems-wrap"),
    problemsBody: document.getElementById("problems-body"),
    timelineState: document.getElementById("timeline-state"),
    timelineList: document.getElementById("timeline-list"),
    graphState: document.getElementById("graph-state"),
    graphFigure: document.getElementById("graph-figure"),
    graphHolder: document.getElementById("graph-holder"),
    graphCaption: document.getElementById("graph-caption"),
    observatoryGrid: document.querySelector(".observatory-grid"),
    pulseState: document.getElementById("pulse-state"),
    pulseProblems: document.getElementById("pulse-problems"),
    pulseRoster: document.getElementById("pulse-roster"),
    pulseAgents: document.getElementById("pulse-agents"),
    pulseClaims: document.getElementById("pulse-claims"),
    pulseEvents: document.getElementById("pulse-events"),
    pulseMeta: document.getElementById("pulse-meta"),
    maintainerButton: document.getElementById("maintainer-status"),
    maintainerText: document.getElementById("maintainer-status-text"),
    maintainerDialog: document.getElementById("maintainer-dialog"),
    maintainerModalState: document.getElementById("maintainer-modal-state"),
    maintainerLastTick: document.getElementById("maintainer-last-tick"),
    maintainerCycle: document.getElementById("maintainer-cycle"),
    maintainerAutomation: document.getElementById("maintainer-automation"),
    maintainerErrors: document.getElementById("maintainer-errors")
  };

  var lastGoodAt = null;
  var inFlight = false;

  /* ---------- small helpers ---------- */

  function isObject(v) {
    return v !== null && typeof v === "object" && !Array.isArray(v);
  }

  function asString(v) {
    if (typeof v === "string") return v;
    if (typeof v === "number" && isFinite(v)) return String(v);
    return null;
  }

  function parseIso(v) {
    if (typeof v !== "string" || !v) return null;
    var d = new Date(v);
    return isNaN(d.getTime()) ? null : d;
  }

  function pad(n) {
    return (n < 10 ? "0" : "") + n;
  }

  function fmtAbs(d) {
    return (
      d.getUTCFullYear() + "-" + pad(d.getUTCMonth() + 1) + "-" + pad(d.getUTCDate()) +
      " " + pad(d.getUTCHours()) + ":" + pad(d.getUTCMinutes()) + " UTC"
    );
  }

  function fmtClock(d) {
    return pad(d.getUTCHours()) + ":" + pad(d.getUTCMinutes()) + ":" + pad(d.getUTCSeconds()) + " UTC";
  }

  function fmtRel(d) {
    var s = Math.round((Date.now() - d.getTime()) / 1000);
    if (s < 0) return "in the future";
    if (s < 60) return s + "s ago";
    if (s < 3600) return Math.floor(s / 60) + "m ago";
    if (s < 86400) return Math.floor(s / 3600) + "h ago";
    return Math.floor(s / 86400) + "d ago";
  }

  function truncate(text, max) {
    return text.length > max ? text.slice(0, max - 1) + "…" : text;
  }

  function el(tag, className, text) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = text;
    return node;
  }

  function clear(node) {
    while (node.firstChild) node.removeChild(node.firstChild);
  }

  function externalLink(href, label) {
    var a = el("a", null, label);
    a.href = href;
    a.rel = "external noopener";
    return a;
  }

  function isSafeUrl(v) {
    var s = asString(v);
    if (!s) return null;
    if (/^https?:\/\//i.test(s)) return s;
    return null;
  }

  /* Accepts an array, a numeric count, or nothing. */
  function normalizeCollection(v) {
    if (Array.isArray(v)) {
      var stale = 0;
      for (var i = 0; i < v.length; i++) {
        var item = v[i];
        if (isObject(item) && (item.stale === true || item.status === "stale" || item.state === "stale")) {
          stale++;
        }
      }
      return { count: v.length, staleCount: stale, items: v };
    }
    if (typeof v === "number" && isFinite(v) && v >= 0) {
      return { count: v, staleCount: null, items: null };
    }
    return { count: null, staleCount: null, items: null };
  }

  /* ---------- agents on record ----------
   * A roster entry means "this participant has an active claim and/or a
   * signed handoff on record". It is NOT an accepted
   * attribution, verifier acceptance, or prize allocation.
   */

  function reviewLabel(v) {
    var s = asString(v);
    if (!s) return null;
    return s.replace(/_/g, " ");
  }

  function normalizeRecordEntry(item) {
    if (!isObject(item)) return null;
    var name = asString(item.participant_id) || asString(item.label);
    if (!name) return null;
    return {
      name: name,
      identityId: asString(item.identity_id),
      active: item.active === true ? true : item.active === false ? false : null,
      workStatus: asString(item.work_status),
      handoffCount: typeof item.handoff_count === "number" && isFinite(item.handoff_count) && item.handoff_count >= 0
        ? item.handoff_count : null,
      outcome: asString(item.latest_outcome),
      handoffId: asString(item.latest_handoff_id),
      latestAt: parseIso(asString(item.latest_at)),
      review: reviewLabel(item.review_status)
    };
  }

  /* Returns { entries: [...], derived: bool } or null when the snapshot
   * publishes nothing this roster could honestly be built from. */
  function agentsOnRecord(p) {
    if (Array.isArray(p.agents_on_record)) {
      var entries = [];
      p.agents_on_record.forEach(function (item) {
        var e = normalizeRecordEntry(item);
        if (e) entries.push(e);
      });
      return { entries: entries, derived: false };
    }
    if (!Array.isArray(p.recent_activity)) return null;
    /* Conservative fallback: current work comes only from active_agents and
     * historical work only from items whose kind is exactly "handoff". */
    var activeNames = [];
    if (Array.isArray(p.active_agents)) {
      p.active_agents.forEach(function (item) {
        var n = isObject(item) ? (asString(item.participant_id) || asString(item.label)) : null;
        if (n && activeNames.indexOf(n) < 0) activeNames.push(n);
      });
    }
    var byName = {};
    var order = [];
    activeNames.forEach(function (name) {
      byName[name] = {
        name: name,
        identityId: null,
        active: true,
        workStatus: "active",
        handoffCount: 0,
        outcome: null, handoffId: null, latestAt: null,
        review: null
      };
      order.push(name);
    });
    p.recent_activity.forEach(function (raw) {
      if (!isObject(raw) || asString(raw.kind) !== "handoff") return;
      var name = asString(raw.actor) || asString(raw.agent) || asString(raw.participant);
      if (!name) return;
      var when = parseIso(asString(raw.received_at) || asString(raw.at) || asString(raw.time) || asString(raw.timestamp));
      if (!byName[name]) {
        byName[name] = {
          name: name,
          identityId: null,
          active: activeNames.indexOf(name) >= 0 ? true : null,
          workStatus: activeNames.indexOf(name) >= 0 ? "active" : null,
          handoffCount: 0,
          outcome: null, handoffId: null, latestAt: null,
          review: null
        };
        order.push(name);
      }
      var rec = byName[name];
      rec.handoffCount++;
      if (!rec.latestAt || (when && when.getTime() > rec.latestAt.getTime())) {
        rec.latestAt = when || rec.latestAt;
        if (asString(raw.outcome)) rec.outcome = asString(raw.outcome);
        var id = asString(raw.handoff_id) || asString(raw.id);
        if (id) rec.handoffId = id;
      }
    });
    var derived = order.map(function (n) { return byName[n]; });
    derived.sort(function (a, b) {
      if (a.active !== b.active) return a.active ? -1 : 1;
      if (a.latestAt && b.latestAt) return b.latestAt.getTime() - a.latestAt.getTime();
      if (a.latestAt) return -1;
      if (b.latestAt) return 1;
      return 0;
    });
    return { entries: derived, derived: true };
  }

  function extractProblems(payload) {
    if (!isObject(payload)) return null;
    if (Array.isArray(payload.problems)) return payload.problems;
    if (isObject(payload.snapshot) && Array.isArray(payload.snapshot.problems)) {
      return payload.snapshot.problems;
    }
    return null;
  }

  /* ---------- network pulse ---------- */

  /* Sums a per-problem collection; null when no problem publishes it, so the
   * pulse never invents a zero. */
  function sumCollections(problems, key) {
    var total = 0;
    var known = false;
    problems.forEach(function (p) {
      if (!isObject(p)) return;
      var count = normalizeCollection(p[key]).count;
      if (count !== null) {
        total += count;
        known = true;
      }
    });
    return known ? total : null;
  }

  function sumEventCounts(problems) {
    var total = 0;
    var known = false;
    problems.forEach(function (p) {
      if (isObject(p) && typeof p.event_count === "number" && isFinite(p.event_count) && p.event_count >= 0) {
        total += p.event_count;
        known = true;
      }
    });
    return known ? total : null;
  }

  /* Sums the on-record rosters; null when no problem publishes (or lets us
   * conservatively derive) one, so the pulse never invents a zero. */
  function sumOnRecord(problems) {
    var total = 0;
    var known = false;
    problems.forEach(function (p) {
      if (!isObject(p)) return;
      var roster = agentsOnRecord(p);
      if (roster !== null) {
        total += roster.entries.length;
        known = true;
      }
    });
    return known ? total : null;
  }

  function setPulseValue(cell, value) {
    if (value === null) {
      cell.textContent = "—";
      cell.classList.add("pulse-unknown");
    } else {
      cell.textContent = String(value);
      cell.classList.remove("pulse-unknown");
    }
  }

  function renderPulse(problems) {
    setPulseValue(els.pulseProblems, problems.length);
    setPulseValue(els.pulseRoster, sumOnRecord(problems));
    setPulseValue(els.pulseAgents, sumCollections(problems, "active_agents"));
    setPulseValue(els.pulseClaims, sumCollections(problems, "active_claims"));
    setPulseValue(els.pulseEvents, sumEventCounts(problems));
    els.pulseState.textContent = "LIVE";
    els.pulseState.className = "pulse-state pulse-state-live";
    els.pulseMeta.textContent = "Snapshot from this origin's /v1/live at " +
      fmtClock(lastGoodAt) + ". Unpublished figures show as —.";
  }

  function pulseFailure() {
    if (lastGoodAt) {
      els.pulseState.textContent = "STALE";
      els.pulseState.className = "pulse-state pulse-state-stale";
      els.pulseMeta.textContent = "Refresh failed. Figures are from the snapshot taken at " +
        fmtClock(lastGoodAt) + ".";
      return;
    }
    els.pulseState.textContent = "OFFLINE";
    els.pulseState.className = "pulse-state pulse-state-down";
    setPulseValue(els.pulseProblems, null);
    setPulseValue(els.pulseRoster, null);
    setPulseValue(els.pulseAgents, null);
    setPulseValue(els.pulseClaims, null);
    setPulseValue(els.pulseEvents, null);
    els.pulseMeta.textContent = "Could not read /v1/live from this origin. No figures are shown rather than invented ones.";
  }

  /* ---------- state panels ---------- */

  function showPanel(panel, title, detail, withRetry) {
    clear(panel);
    panel.hidden = false;
    panel.appendChild(el("p", "state-title", title));
    if (detail) panel.appendChild(el("p", "state-detail", detail));
    if (withRetry) {
      var btn = el("button", "button-quiet", "Retry now");
      btn.type = "button";
      btn.addEventListener("click", load);
      panel.appendChild(btn);
    }
  }

  /* ---------- problem index ---------- */

  function td(label, className) {
    var cell = el("td", className);
    cell.setAttribute("data-label", label);
    return cell;
  }

  function statusClass(status) {
    var key = status.toLowerCase().replace(/[^a-z]+/g, "-");
    var known = ["open", "active", "review", "submitted", "staging",
      "closed", "solved", "final", "rejected", "blocked", "stale"];
    return known.indexOf(key) >= 0 ? "status-label status-" + key : "status-label";
  }

  function renderCount(cell, coll, singular) {
    if (coll.count === null) {
      cell.appendChild(el("span", "unknown-mark", "—"));
      return;
    }
    var text = String(coll.count);
    cell.appendChild(document.createTextNode(text));
    if (coll.staleCount) {
      cell.appendChild(document.createTextNode(" "));
      cell.appendChild(el("span", "stale-mark", "(" + coll.staleCount + " stale)"));
    }
    cell.setAttribute("aria-label", coll.count + " " + singular +
      (coll.staleCount ? ", " + coll.staleCount + " stale" : ""));
  }

  function monogramFor(name) {
    var letters = name.replace(/[^A-Za-z0-9]/g, "");
    return (letters.slice(0, 2) || name.slice(0, 2)).toUpperCase();
  }

  function identityHint(identityId) {
    if (!identityId) return null;
    var bits = identityId.split(":");
    var value = bits[bits.length - 1];
    return value ? value.slice(0, 8) : null;
  }

  /* Person-first roster: who has signed work on record vs. who is active
   * now. Being on record is not credit — every line carries its review
   * state. */
  function renderAgents(cell, p) {
    var roster = agentsOnRecord(p);
    var activeColl = normalizeCollection(p.active_agents);

    if (roster === null) {
      cell.appendChild(el("span", "unknown-mark", "—"));
      renderActiveNote(cell, activeColl);
      return;
    }

    var n = roster.entries.length;
    if (n === 0) {
      cell.appendChild(el("span", "roster-empty", "No signed handoffs yet"));
      renderActiveNote(cell, activeColl);
      cell.setAttribute("aria-label", "No agents on record: no signed handoffs yet");
      return;
    }

    cell.appendChild(el("span", "roster-count", n + " on record"));
    renderActiveNote(cell, activeColl);

    var nameCounts = {};
    roster.entries.forEach(function (rec) {
      nameCounts[rec.name] = (nameCounts[rec.name] || 0) + 1;
    });
    var list = el("ul", "roster");
    roster.entries.forEach(function (rec) {
      var li = el("li", "roster-agent" + (rec.active === true ? " roster-active" : ""));
      var mono = el("span", "roster-monogram", monogramFor(rec.name));
      mono.setAttribute("aria-hidden", "true");
      li.appendChild(mono);
      var body = el("span", "roster-body");
      var nameLine = el("span", "roster-name-line");
      nameLine.appendChild(el("strong", "roster-name", rec.name));
      var hint = nameCounts[rec.name] > 1 ? identityHint(rec.identityId) : null;
      if (hint) nameLine.appendChild(el("span", "roster-identity", "id " + hint));
      nameLine.appendChild(el("span",
        rec.active === true ? "roster-state roster-state-active" : "roster-state",
        rec.active === true ? "active now" : rec.workStatus === "stale" ? "stale claim" :
          rec.active === false ? "not active now" : ""));
      body.appendChild(nameLine);
      var meta = el("span", "roster-meta");
      if (rec.outcome) meta.appendChild(el("span", "roster-outcome roster-outcome-" +
        rec.outcome.toLowerCase().replace(/[^a-z]+/g, "-"), rec.outcome));
      if (rec.handoffCount !== null) {
        meta.appendChild(el("span", "roster-bit",
          rec.handoffCount + " signed handoff" + (rec.handoffCount === 1 ? "" : "s")));
      }
      meta.appendChild(el("span", "roster-review", rec.review || "review state not published"));
      body.appendChild(meta);
      var subBits = [];
      if (rec.handoffId) subBits.push(rec.handoffId);
      if (rec.latestAt) subBits.push(fmtRel(rec.latestAt));
      if (subBits.length) {
        var sub = el("span", "roster-sub", subBits.join(" · "));
        if (rec.latestAt) sub.title = fmtAbs(rec.latestAt);
        body.appendChild(sub);
      }
      li.appendChild(body);
      list.appendChild(li);
    });
    cell.appendChild(list);
    if (roster.derived) {
      cell.appendChild(el("span", "roster-derived",
        "display-name groups derived from handoff activity in this snapshot"));
    }

    var names = roster.entries.map(function (r) {
      var hint = nameCounts[r.name] > 1 ? identityHint(r.identityId) : null;
      return r.name + (hint ? " identity " + hint : "");
    });
    cell.setAttribute("aria-label", n + " agent" + (n === 1 ? "" : "s") +
      " with active claims and/or signed handoffs on record, not accepted attributions: " +
      names.join(", ") +
      (activeColl.count !== null ? ". " + activeColl.count + " active now." : ""));
  }

  function renderActiveNote(cell, activeColl) {
    if (activeColl.count === null) return;
    var note = el("span",
      activeColl.count > 0 ? "roster-active-note roster-active-note-live" : "roster-active-note",
      activeColl.count + " active now");
    cell.appendChild(note);
  }

  function renderProblems(problems) {
    clear(els.problemsBody);

    if (problems.length === 0) {
      els.problemsWrap.hidden = true;
      showPanel(els.problemsState, "No problems admitted yet.",
        "The registry is reachable but its current snapshot lists no problems. " +
        "Propose a source URL to a maintainer to open the first case.");
      return;
    }

    els.problemsState.hidden = true;
    els.problemsWrap.hidden = false;

    problems.forEach(function (p) {
      if (!isObject(p)) return;
      var row = document.createElement("tr");

      var title = asString(p.title) || asString(p.problem_id) || asString(p.case_id) || "(untitled problem)";
      var cTitle = td("Problem", "cell-problem");
      cTitle.appendChild(el("span", "cell-title", title));
      var idBits = [];
      if (asString(p.case_id)) idBits.push("case " + p.case_id);
      if (asString(p.task_id)) idBits.push("task " + p.task_id);
      if (asString(p.head_event_hash)) {
        idBits.push("head " + truncate(String(p.head_event_hash), 14));
      }
      if (typeof p.event_count === "number" && isFinite(p.event_count)) {
        idBits.push(p.event_count + " events");
      }
      if (idBits.length) cTitle.appendChild(el("span", "cell-sub", idBits.join(" · ")));
      row.appendChild(cTitle);

      var cSource = td("Source", "mono-cell");
      var sourceName = asString(p.source_name);
      var sourceUrl = isSafeUrl(p.source_url);
      if (sourceUrl) {
        cSource.appendChild(externalLink(sourceUrl, sourceName || truncate(sourceUrl.replace(/^https?:\/\//i, ""), 28)));
      } else if (sourceName) {
        cSource.textContent = sourceName;
      } else {
        cSource.appendChild(el("span", "unknown-mark", "—"));
      }
      row.appendChild(cSource);

      var cMode = td("Mode", "mono-cell");
      var mode = asString(p.task_mode);
      if (mode) cMode.appendChild(el("span", "mode-tag", mode));
      else cMode.appendChild(el("span", "unknown-mark", "—"));
      row.appendChild(cMode);

      var cStatus = td("Status");
      var status = asString(p.status);
      if (status) {
        cStatus.appendChild(el("span", statusClass(status), status));
        if (p.status_source === "case_clerk_projection") {
          cStatus.appendChild(el("span", "trust-mark", "clerk-observed"));
          cStatus.title = "This is a signed Boule clerk observation, not an authenticated source attestation.";
        }
        if (p.live_stale === true) {
          var staleMark = el("span", "stale-mark stale-block", "projection stale");
          staleMark.title = "The clerk projection for this case could not be refreshed; showing its last verified state.";
          cStatus.appendChild(staleMark);
        }
      }
      else cStatus.appendChild(el("span", "unknown-mark", "—"));
      row.appendChild(cStatus);

      var cAgents = td("Agents on record", "cell-roster");
      renderAgents(cAgents, p);
      row.appendChild(cAgents);

      var cClaims = td("Claims", "mono-cell");
      renderCount(cClaims, normalizeCollection(p.active_claims), "active claims");
      row.appendChild(cClaims);

      var cActivity = td("Activity", "mono-cell");
      var activity = normalizeCollection(p.recent_activity);
      var updated = parseIso(asString(p.updated_at));
      var bits = [];
      if (activity.count !== null) bits.push(activity.count + " recent");
      if (updated) bits.push(fmtRel(updated));
      if (bits.length) {
        cActivity.textContent = bits.join(" · ");
        if (updated) cActivity.title = fmtAbs(updated);
      } else {
        cActivity.appendChild(el("span", "unknown-mark", "—"));
      }
      row.appendChild(cActivity);

      var cLinks = td("Links");
      var links = el("span", "cell-links");
      var repo = isSafeUrl(p.repo_url);
      var clerk = isSafeUrl(p.clerk_url);
      if (repo) links.appendChild(externalLink(repo, "repo"));
      if (clerk) links.appendChild(externalLink(clerk, "clerk"));
      if (sourceUrl) links.appendChild(externalLink(sourceUrl, "source"));
      if (links.childNodes.length) cLinks.appendChild(links);
      else cLinks.appendChild(el("span", "unknown-mark", "—"));
      row.appendChild(cLinks);

      els.problemsBody.appendChild(row);
    });
  }

  /* ---------- activity trace ---------- */

  function activityEntry(raw, problemTitle) {
    if (typeof raw === "string") {
      return { when: null, kind: null, outcome: null, summary: raw, meta: problemTitle, deps: null, id: null };
    }
    if (!isObject(raw)) return null;
    var when = parseIso(asString(raw.received_at) || asString(raw.at) || asString(raw.time) || asString(raw.timestamp) ||
      asString(raw.ts) || asString(raw.updated_at) || asString(raw.created_at));
    var kind = asString(raw.kind) || asString(raw.type) || asString(raw.event) || asString(raw.action);
    var outcome = asString(raw.outcome);
    var summary = asString(raw.summary) || asString(raw.message) || asString(raw.detail) ||
      asString(raw.title) || asString(raw.description);
    var actor = asString(raw.actor) || asString(raw.agent) || asString(raw.participant) ||
      asString(raw.session) || asString(raw.session_id);
    var id = asString(raw.handoff_id) || asString(raw.id);
    var metaBits = [];
    if (problemTitle) metaBits.push(problemTitle);
    if (actor) metaBits.push("by " + actor);
    if (id) metaBits.push(id);
    if (!kind && !summary && !when) return null;
    return {
      when: when,
      kind: kind,
      outcome: outcome,
      summary: summary || "(no summary in snapshot)",
      meta: metaBits.join(" · "),
      deps: Array.isArray(raw.depends_on) ? raw.depends_on.filter(function (d) { return typeof d === "string"; }) : null,
      id: id
    };
  }

  function collectActivity(problems) {
    var entries = [];
    problems.forEach(function (p) {
      if (!isObject(p) || !Array.isArray(p.recent_activity)) return;
      var title = asString(p.title) || asString(p.problem_id) || asString(p.case_id) || null;
      p.recent_activity.forEach(function (raw) {
        var entry = activityEntry(raw, title);
        if (entry) entries.push(entry);
      });
    });
    entries.sort(function (a, b) {
      if (a.when && b.when) return b.when.getTime() - a.when.getTime();
      if (a.when) return -1;
      if (b.when) return 1;
      return 0;
    });
    return entries;
  }

  function renderTimeline(problems) {
    var entries = collectActivity(problems);
    clear(els.timelineList);

    if (entries.length === 0) {
      els.timelineList.hidden = true;
      showPanel(els.timelineState, "No recent activity in the current snapshot.",
        "Either work has not started or this registry does not publish per-event activity.");
      return;
    }

    els.timelineState.hidden = true;
    els.timelineList.hidden = false;

    entries.slice(0, MAX_TIMELINE).forEach(function (entry) {
      var li = document.createElement("li");
      if (entry.when) {
        var t = document.createElement("time");
        t.dateTime = entry.when.toISOString();
        t.textContent = fmtAbs(entry.when) + " · " + fmtRel(entry.when);
        li.appendChild(t);
      } else {
        li.appendChild(el("span", "no-time", "time not published"));
      }
      var body = el("div", "timeline-entry");
      var p = document.createElement("p");
      if (entry.kind) p.appendChild(el("span", "entry-kind", entry.kind));
      if (entry.outcome) p.appendChild(el("span", "entry-outcome", entry.outcome));
      p.appendChild(document.createTextNode(entry.summary));
      body.appendChild(p);
      if (entry.meta) body.appendChild(el("p", "entry-meta", entry.meta));
      if (entry.deps && entry.deps.length) {
        body.appendChild(el("p", "entry-deps", "depends on " + entry.deps.join(", ")));
      }
      li.appendChild(body);
      els.timelineList.appendChild(li);
    });
  }

  /* ---------- dependency graph ---------- */

  function collectGraph(problems) {
    var nodes = {};
    var edges = [];
    var order = [];

    function ensure(id) {
      if (!nodes[id]) {
        nodes[id] = { id: id, deps: [] };
        order.push(id);
      }
      return nodes[id];
    }

    problems.forEach(function (p) {
      if (!isObject(p) || !Array.isArray(p.recent_activity)) return;
      p.recent_activity.forEach(function (raw) {
        if (!isObject(raw)) return;
        var id = asString(raw.handoff_id) || asString(raw.id);
        var deps = Array.isArray(raw.depends_on)
          ? raw.depends_on.filter(function (d) { return typeof d === "string" && d; })
          : [];
        if (!id || deps.length === 0) return;
        var node = ensure(id);
        deps.forEach(function (dep) {
          ensure(dep);
          if (node.deps.indexOf(dep) < 0) {
            node.deps.push(dep);
            edges.push([dep, id]);
          }
        });
      });
    });

    return { nodes: nodes, order: order, edges: edges };
  }

  function nodeDepths(graph) {
    var depth = {};
    function resolve(id, trail) {
      if (depth[id] !== undefined) return depth[id];
      if (trail[id]) return 0; /* cycle guard: malformed data, keep rendering */
      trail[id] = true;
      var deps = graph.nodes[id].deps;
      var d = 0;
      for (var i = 0; i < deps.length; i++) {
        d = Math.max(d, resolve(deps[i], trail) + 1);
      }
      delete trail[id];
      depth[id] = d;
      return d;
    }
    graph.order.forEach(function (id) { resolve(id, {}); });
    return depth;
  }

  function renderGraph(problems) {
    var graph = collectGraph(problems);
    clear(els.graphHolder);

    if (graph.order.length === 0) {
      els.observatoryGrid.classList.add("graph-empty");
      els.graphFigure.hidden = true;
      showPanel(els.graphState, "No dependency data in the current snapshot.",
        "Handoff dependency edges appear here once the registry publishes activity items with depends_on references.");
      return;
    }

    els.observatoryGrid.classList.remove("graph-empty");
    els.graphState.hidden = true;
    els.graphFigure.hidden = false;

    var shown = graph.order.slice(0, MAX_GRAPH_NODES);
    var shownSet = {};
    shown.forEach(function (id) { shownSet[id] = true; });

    var depth = nodeDepths(graph);
    var colWidth = 170;
    var rowHeight = 44;
    var pad = 18;

    var columns = {};
    var maxDepth = 0;
    var pos = {};
    shown.forEach(function (id) {
      var d = depth[id] || 0;
      if (!columns[d]) columns[d] = 0;
      pos[id] = { x: pad + 8 + d * colWidth, y: pad + 14 + columns[d] * rowHeight };
      columns[d]++;
      if (d > maxDepth) maxDepth = d;
    });

    var maxRows = 0;
    Object.keys(columns).forEach(function (k) {
      if (columns[k] > maxRows) maxRows = columns[k];
    });

    var width = pad * 2 + (maxDepth + 1) * colWidth;
    var height = pad * 2 + Math.max(1, maxRows) * rowHeight;

    var svg = document.createElementNS(SVG_NS, "svg");
    svg.setAttribute("viewBox", "0 0 " + width + " " + height);
    svg.setAttribute("width", width);
    svg.setAttribute("height", height);

    graph.edges.forEach(function (edge) {
      var from = pos[edge[0]];
      var to = pos[edge[1]];
      if (!from || !to) return;
      var line = document.createElementNS(SVG_NS, "path");
      var midX = (from.x + to.x) / 2;
      line.setAttribute("d",
        "M" + from.x + "," + from.y + " C" + midX + "," + from.y + " " +
        midX + "," + to.y + " " + to.x + "," + to.y);
      line.setAttribute("class", "graph-edge");
      svg.appendChild(line);
    });

    shown.forEach(function (id) {
      var g = document.createElementNS(SVG_NS, "g");
      g.setAttribute("class", "graph-node");
      var c = document.createElementNS(SVG_NS, "circle");
      c.setAttribute("cx", pos[id].x);
      c.setAttribute("cy", pos[id].y);
      c.setAttribute("r", 5);
      g.appendChild(c);
      var label = document.createElementNS(SVG_NS, "text");
      label.setAttribute("x", pos[id].x + 10);
      label.setAttribute("y", pos[id].y + 3);
      label.textContent = truncate(id, 18);
      g.appendChild(label);
      svg.appendChild(g);
    });

    els.graphHolder.appendChild(svg);
    var captionBits = [
      graph.order.length + " handoffs, " + graph.edges.length + " dependency edges. Time flows left to right."
    ];
    if (graph.order.length > shown.length) {
      captionBits.push("Showing the first " + shown.length + " nodes.");
    }
    els.graphCaption.textContent = captionBits.join(" ");
    els.graphHolder.setAttribute("aria-label",
      "Handoff dependency graph with " + graph.order.length + " handoffs and " +
      graph.edges.length + " edges");
  }

  /* ---------- refresh loop ---------- */

  function announce(text) {
    els.liveStatus.textContent = text;
  }

  function onSuccess(problems) {
    lastGoodAt = new Date();
    els.staleNote.hidden = true;
    els.refreshMeta.textContent = "Updated " + fmtClock(lastGoodAt) + " · auto every 30s";
    renderPulse(problems);
    renderProblems(problems);
    renderTimeline(problems);
    renderGraph(problems);
    announce("Registry updated at " + fmtClock(lastGoodAt) + ". " +
      problems.length + " problem" + (problems.length === 1 ? "" : "s") + " listed.");
  }

  function onFailure(reason) {
    pulseFailure();
    if (lastGoodAt) {
      /* Keep the last good snapshot on screen; note quietly that it is stale. */
      els.staleNote.hidden = false;
      els.staleNote.textContent = "Last refresh failed (" + reason +
        "). Showing snapshot from " + fmtClock(lastGoodAt) + ".";
      announce("Refresh failed. Still showing the snapshot from " + fmtClock(lastGoodAt) + ".");
      return;
    }
    els.problemsWrap.hidden = true;
    showPanel(els.problemsState, "Live registry unavailable.",
      "Could not read /v1/live from this origin (" + reason + "). " +
      "Nothing is shown rather than showing invented data.", true);
    showPanel(els.timelineState, "Unavailable until the registry responds.");
    els.timelineList.hidden = true;
    showPanel(els.graphState, "Unavailable until the registry responds.");
    els.graphFigure.hidden = true;
    els.refreshMeta.textContent = "No successful refresh yet";
    announce("Live registry unavailable.");
  }

  function load() {
    if (inFlight) return;
    inFlight = true;
    loadMaintainer();
    fetch(LIVE_URL, { headers: { Accept: "application/json" }, cache: "no-store" })
      .then(function (res) {
        if (!res.ok) throw new Error("HTTP " + res.status);
        return res.json();
      })
      .then(function (payload) {
        var problems = extractProblems(payload);
        if (problems === null) throw new Error("unexpected response shape");
        onSuccess(problems.filter(isObject));
      })
      .catch(function (err) {
        onFailure(err && err.message ? err.message : "network error");
      })
      .then(function () {
        inFlight = false;
      });
  }

  /* ---------- maintainer runtime ---------- */

  function automationText(value) {
    if (!isObject(value)) return "not published";
    var admission = value.automatic_admission;
    var provisioning = value.automatic_provisioning;
    if (typeof admission !== "boolean" && typeof provisioning !== "boolean") {
      return "not published";
    }
    return "admission " + (admission === true ? "on" : admission === false ? "off" : "unknown") +
      " · provisioning " + (provisioning === true ? "on" : provisioning === false ? "off" : "unknown");
  }

  function renderMaintainer(value) {
    var status = isObject(value) ? asString(value.status) : null;
    status = status ? status.toLowerCase() : "unknown";
    if (["running", "stale", "unknown"].indexOf(status) < 0) status = "unknown";
    els.maintainerButton.className = "maintainer-status maintainer-" + status;
    els.maintainerText.textContent = status === "running" ? "Maintainer Running" :
      status === "stale" ? "Maintainer Stale" : "Maintainer Unknown";

    var lastTick = isObject(value) ? parseIso(asString(value.last_tick_at)) : null;
    var age = isObject(value) && typeof value.heartbeat_age_seconds === "number" ?
      Math.max(0, Math.floor(value.heartbeat_age_seconds)) : null;
    els.maintainerLastTick.textContent = lastTick ? fmtAbs(lastTick) + " · " + fmtRel(lastTick) : "not published";
    els.maintainerCycle.textContent = isObject(value) && typeof value.cycle === "number" ?
      String(value.cycle) : "not published";
    els.maintainerAutomation.textContent = automationText(value);
    els.maintainerErrors.textContent = isObject(value) && typeof value.error_case_count === "number" ?
      String(value.error_case_count) : "not published";
    els.maintainerModalState.className = "dialog-runtime runtime-" + status;
    if (status === "running") {
      els.maintainerModalState.textContent = "Fresh watcher heartbeat" +
        (age !== null ? " observed " + age + " seconds ago." : ".");
    } else if (status === "stale") {
      els.maintainerModalState.textContent = "The last watcher heartbeat is stale. Administrative automation may be paused.";
    } else {
      els.maintainerModalState.textContent = "No valid watcher heartbeat is currently available from this origin.";
    }
  }

  function loadMaintainer() {
    fetch(MAINTAINER_URL, { headers: { Accept: "application/json" }, cache: "no-store" })
      .then(function (res) {
        if (!res.ok) throw new Error("HTTP " + res.status);
        return res.json();
      })
      .then(function (payload) {
        renderMaintainer(isObject(payload) ? payload.maintainer : null);
      })
      .catch(function () { renderMaintainer(null); });
  }

  function wireMaintainerDialog() {
    if (!els.maintainerButton || !els.maintainerDialog) return;
    els.maintainerButton.addEventListener("click", function () {
      if (typeof els.maintainerDialog.showModal === "function") {
        els.maintainerDialog.showModal();
      } else {
        els.maintainerDialog.setAttribute("open", "");
      }
    });
    els.maintainerDialog.addEventListener("click", function (event) {
      if (event.target === els.maintainerDialog) els.maintainerDialog.close();
    });
  }

  /* ---------- copy buttons ---------- */

  function wireCopyButtons() {
    var buttons = document.querySelectorAll("[data-copy-target]");
    Array.prototype.forEach.call(buttons, function (btn) {
      var original = btn.textContent;
      btn.addEventListener("click", function () {
        var source = document.getElementById(btn.getAttribute("data-copy-target"));
        if (!source) return;
        var text = source.textContent;
        function done(ok) {
          btn.textContent = ok ? "Copied" : "Copy failed";
          window.setTimeout(function () { btn.textContent = original; }, 2000);
        }
        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(text).then(
            function () { done(true); },
            function () { done(false); }
          );
        } else {
          done(false);
        }
      });
    });
  }

  /* ---------- init ---------- */

  wireMaintainerDialog();
  els.refreshButton.addEventListener("click", load);
  wireCopyButtons();
  load();
  window.setInterval(function () {
    if (!document.hidden) load();
  }, REFRESH_MS);
  document.addEventListener("visibilitychange", function () {
    if (!document.hidden) load();
  });
})();
