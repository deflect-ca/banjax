// Copyright (c) 2026, eQualit.ie inc.
// All rights reserved.
//
// This source code is licensed under the BSD-style license found in the
// LICENSE file in the root directory of this source tree.

// Throws a set of bot-like clients at two hosts that challenge the same
// headless Chromium User-Agent, one with the sha-inverse challenge and one
// with AltCha (see per_site_user_agent_decision_lists in banjax-config.yaml),
// and prints side by side which clients each challenge actually stopped.
//
// Usage, from the repo root with the stack up (docker compose up --build -d):
//   docker compose run --rm altcha-bot-tester            # every scenario
//   docker compose run --rm altcha-bot-tester headless   # scenarios matching a substring

import http from "node:http";
import https from "node:https";
import { lookup } from "node:dns/promises";
import { setTimeout as sleep } from "node:timers/promises";
import { chromium } from "playwright";

const EDGE_ADDR = process.env.EDGE_ADDR || "localhost";
// https by default: the ALTCHA widget needs a secure context (crypto.subtle) and refuses to
// solve over plain http. nginx's certificate is self-signed, so it is not verified.
const EDGE_SCHEME = process.env.EDGE_SCHEME || "https";
const DEFAULT_PORT = EDGE_SCHEME === "https" ? 443 : 80;
const EDGE_PORT = Number(process.env.EDGE_PORT || DEFAULT_PORT);
const SHA_HOST = process.env.SHA_HOST || "sha-test.banjax";
const ALTCHA_HOST = process.env.ALTCHA_HOST || "altcha-test.banjax";
const TEST_PATH = process.env.TEST_PATH || "/hello";
// how long a browser gets to solve a challenge and land on the origin page
const SOLVE_TIMEOUT_MS = Number(process.env.SOLVE_TIMEOUT_MS || 30000);
// failed challenges per ip are rate limited (3 in 10s by default, then an iptables
// ban), so scenarios that fail a challenge are spaced out by this much
const PAUSE_SECONDS = Number(process.env.PAUSE_SECONDS || 6);
// headless-browser solves per host, to see the spread of solve times (both challenges
// are randomized, so one sample says little about the typical cost)
const SAMPLES = Number(process.env.SAMPLES || 1);
// Chromium CPU slowdown factor for browser scenarios, e.g. 4 for a mid-range phone
const CPU_THROTTLE = Number(process.env.CPU_THROTTLE || 1);
const FILTER = process.argv[2] || "";

// a desktop Chrome UA that does not contain "HeadlessChrome"
const SPOOFED_UA =
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";
const ORIGIN_MARKER = "hello!";

const MODES = [
    { key: "sha", label: "sha-inverse", host: SHA_HOST, cookie: "deflect_challenge3" },
    { key: "altcha", label: "altcha", host: ALTCHA_HOST, cookie: "deflect_altcha" },
];

// what a response turned out to be, from the client's point of view
function classify(status, body) {
    if (status === 200 && body.includes(ORIGIN_MARKER)) return "origin";
    if (body.includes("<altcha-widget")) return "altcha-page";
    if (body.includes("deflect_challenge3")) return "sha-page";
    if (status === 403) return "denied";
    return `http-${status}`;
}

// plainGet sends one request with no JavaScript engine behind it, like curl or a
// python script would.
function plainGet(edgeIp, host, { ua, cookie } = {}) {
    return new Promise((resolve) => {
        const headers = { Host: host, "User-Agent": ua };
        if (cookie) headers.Cookie = cookie;
        const client = EDGE_SCHEME === "https" ? https : http;
        const req = client.request(
            {
                host: edgeIp,
                port: EDGE_PORT,
                path: TEST_PATH,
                method: "GET",
                headers,
                timeout: 10000,
                servername: host,
                rejectUnauthorized: false,
            },
            (res) => {
                let body = "";
                res.setEncoding("utf8");
                res.on("data", (chunk) => (body += chunk));
                res.on("end", () =>
                    resolve({
                        kind: classify(res.statusCode, body),
                        decision: res.headers["x-banjax-decision"] || "",
                    }),
                );
            },
        );
        // an iptables ban shows up as a connection that never answers
        req.on("timeout", () => req.destroy(new Error("timeout")));
        req.on("error", (err) => resolve({ kind: err.message === "timeout" ? "timeout (banned?)" : `error: ${err.message}` }));
        req.end();
    });
}

// browserVisit opens the page in a fresh browser context and waits for the
// challenge page to solve itself and reload into the origin page.
// click ticks the ALTCHA checkbox, as a bot driving a real browser would: the AltCha challenge
// only starts its proof of work on that click. The sha-inverse page has no checkbox.
async function browserVisit(browser, host, { javaScriptEnabled = true, userAgent, click = false } = {}) {
    const context = await browser.newContext({ javaScriptEnabled, userAgent, ignoreHTTPSErrors: true });
    const page = await context.newPage();
    if (CPU_THROTTLE > 1) {
        const cdp = await context.newCDPSession(page);
        await cdp.send("Emulation.setCPUThrottlingRate", { rate: CPU_THROTTLE });
    }
    let challengePages = 0;
    let decision = "";
    page.on("response", (res) => {
        if (res.request().resourceType() !== "document") return;
        if (res.status() === 429) challengePages += 1;
        decision = res.headers()["x-banjax-decision"] || decision;
    });

    const url = `${EDGE_SCHEME}://${host}${EDGE_PORT === DEFAULT_PORT ? "" : `:${EDGE_PORT}`}${TEST_PATH}`;
    const started = performance.now();
    let solvedMs = null;
    try {
        await page.goto(url, { waitUntil: "load", timeout: 15000 });
        if (click && (await page.locator("altcha-widget").count()) > 0) {
            // click the label: the widget draws its checkmark svg over the checkbox, which a real
            // mouse click goes through but Playwright's click refuses as "intercepts pointer events"
            await page.locator("altcha-widget label").click({ timeout: 10000 });
        }
        const deadline = Date.now() + (javaScriptEnabled ? SOLVE_TIMEOUT_MS : 3000);
        while (Date.now() < deadline) {
            // evaluate throws while the challenge page is reloading, so just retry
            const text = await page.evaluate(() => document.body?.innerText || "").catch(() => "");
            if (text.includes(ORIGIN_MARKER)) {
                solvedMs = performance.now() - started;
                break;
            }
            await sleep(100);
        }
    } catch (err) {
        await context.close();
        return { kind: `error: ${err.message.split("\n")[0]}` };
    }

    const content = await page.content().catch(() => "");
    const cookies = await context.cookies();
    await context.close();
    return {
        kind: solvedMs !== null ? "origin" : classify(429, content),
        solvedMs,
        challengePages,
        decision,
        cookies,
    };
}

function forgedCookie(mode) {
    if (mode.key === "sha") return `${mode.cookie}=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==`;
    // ALTCHA v2 payload shape with a made-up challenge, signature and key
    const payload = {
        challenge: {
            parameters: {
                algorithm: "PBKDF2/SHA-256",
                nonce: "0".repeat(32),
                salt: "0".repeat(32),
                cost: 1,
                keyLength: 32,
                keyPrefix: "00",
                keySignature: "0".repeat(64),
                expiresAt: 9999999999,
                data: { binding: "1.2.3.4" },
            },
            signature: "0".repeat(64),
        },
        solution: { counter: 1, derivedKey: "0".repeat(64) },
    };
    return `${mode.cookie}=${Buffer.from(JSON.stringify(payload)).toString("base64")}`;
}

// shouldStop is a boolean, or per mode as { sha, altcha } when the challenges differ.
function shouldStop(scenario, mode) {
    return typeof scenario.shouldStop === "object" ? scenario.shouldStop[mode.key] : scenario.shouldStop;
}

// Each scenario runs once per mode. shouldStop marks clients a working challenge
// must keep out; the others are reported but are expected to get through.
// failsChallenge marks scenarios that count towards the failed-challenge ban.
const SCENARIOS = [
    {
        name: "no-js-client",
        about: "plain HTTP client (curl-like) sending the headless UA",
        shouldStop: true,
        failsChallenge: true,
        run: (ctx, mode) => plainGet(ctx.edgeIp, mode.host, { ua: ctx.headlessUA }),
    },
    {
        name: "forged-cookie",
        about: "plain HTTP client with a made-up solution cookie",
        shouldStop: true,
        failsChallenge: true,
        run: (ctx, mode) => plainGet(ctx.edgeIp, mode.host, { ua: ctx.headlessUA, cookie: forgedCookie(mode) }),
    },
    {
        name: "js-disabled-browser",
        about: "headless Chromium with JavaScript turned off",
        shouldStop: true,
        failsChallenge: true,
        run: (ctx, mode) => browserVisit(ctx.browser, mode.host, { javaScriptEnabled: false }),
    },
    {
        name: "headless-no-click",
        about: "stock headless Chromium that runs the page's JS but never interacts with it",
        // the sha-inverse page solves itself on load; the AltCha one waits for a click
        shouldStop: { sha: false, altcha: true },
        failsChallenge: true,
        run: (ctx, mode) => browserVisit(ctx.browser, mode.host),
    },
    {
        name: "headless-browser",
        about: "stock headless Chromium (navigator.webdriver=true) that also clicks the checkbox",
        shouldStop: false,
        failsChallenge: true,
        run: async (ctx, mode) => {
            const results = [];
            for (let i = 0; i < SAMPLES; i++) {
                // every sample fails one challenge before solving it, so space them out
                if (i > 0) await sleep(PAUSE_SECONDS * 1000);
                results.push(await browserVisit(ctx.browser, mode.host, { click: true }));
            }
            const solved = results.filter((r) => r.kind === "origin");
            const result = solved.at(-1) || results.at(-1);
            ctx.solvedCookies[mode.key] = result.cookies?.find((c) => c.name === mode.cookie);
            if (SAMPLES > 1) {
                result.times = solved.map((r) => r.solvedMs).sort((a, b) => a - b);
                result.unsolved = results.length - solved.length;
            }
            return result;
        },
    },
    {
        name: "cookie-replay",
        about: "plain HTTP client reusing the cookie the headless browser just earned",
        shouldStop: false,
        failsChallenge: false,
        run: (ctx, mode) => {
            const cookie = ctx.solvedCookies[mode.key];
            if (!cookie) return { kind: "skipped (no solved cookie)" };
            return plainGet(ctx.edgeIp, mode.host, { ua: ctx.headlessUA, cookie: `${cookie.name}=${cookie.value}` });
        },
    },
    {
        name: "spoofed-ua",
        about: "plain HTTP client sending a normal desktop Chrome UA",
        shouldStop: false,
        failsChallenge: false,
        run: (ctx, mode) => plainGet(ctx.edgeIp, mode.host, { ua: SPOOFED_UA }),
    },
];

function describe(result) {
    if (result.kind !== "origin") return `STOPPED  ${result.kind}`;
    const parts = [];
    const secs = (ms) => `${(ms / 1000).toFixed(2)}s`;
    if (result.times?.length) {
        const t = result.times;
        parts.push(`median ${secs(t[Math.floor(t.length / 2)])}, min ${secs(t[0])}, max ${secs(t.at(-1))} over ${t.length}`);
        if (result.unsolved) parts.push(`${result.unsolved} unsolved`);
    } else if (result.solvedMs != null) parts.push(secs(result.solvedMs));
    if (result.challengePages) parts.push(`${result.challengePages} challenge page(s)`);
    if (result.decision) parts.push(result.decision);
    return `THROUGH  ${parts.join(", ")}`;
}

async function main() {
    const edgeIp = (await lookup(EDGE_ADDR, { family: 4 })).address;
    // send both test hosts to nginx without touching /etc/hosts; nginx has a single
    // server block on :80, so any Host reaches banjax
    const browser = await chromium.launch({
        headless: true,
        args: [`--host-resolver-rules=MAP ${SHA_HOST} ${edgeIp}, MAP ${ALTCHA_HOST} ${edgeIp}`, "--disable-dev-shm-usage"],
    });
    const probe = await browser.newPage();
    const headlessUA = await probe.evaluate(() => navigator.userAgent);
    const webdriver = await probe.evaluate(() => navigator.webdriver);
    await probe.close();

    console.log(`edge:       ${EDGE_SCHEME}://${EDGE_ADDR} (${edgeIp}:${EDGE_PORT})${TEST_PATH}`);
    console.log(`hosts:      sha-inverse=${SHA_HOST}  altcha=${ALTCHA_HOST}`);
    console.log(`browser:    ${headlessUA}`);
    console.log(`webdriver:  ${webdriver}`);
    console.log(`cpu:        ${CPU_THROTTLE > 1 ? `${CPU_THROTTLE}x throttled` : "unthrottled"}, ${SAMPLES} headless sample(s)\n`);

    const ctx = { edgeIp, browser, headlessUA, solvedCookies: {} };
    const scenarios = SCENARIOS.filter((s) => s.name.includes(FILTER));
    const rows = [];
    let regressions = 0;

    for (const [i, scenario] of scenarios.entries()) {
        const row = { scenario, results: {} };
        for (const mode of MODES) {
            row.results[mode.key] = await scenario.run(ctx, mode);
            if (shouldStop(scenario, mode) && row.results[mode.key].kind === "origin") regressions += 1;
        }
        rows.push(row);
        console.log(`${scenario.name}: ${scenario.about}`);
        for (const mode of MODES) console.log(`  ${mode.label.padEnd(12)} ${describe(row.results[mode.key])}`);
        if (scenario.failsChallenge && i < scenarios.length - 1) await sleep(PAUSE_SECONDS * 1000);
    }
    await browser.close();

    // the first scenario doubles as the preflight: if the headless UA reaches the
    // origin with no cookie at all, banjax is not challenging it and nothing above means much
    const preflight = rows.find((r) => r.scenario.name === "no-js-client");
    if (preflight && MODES.every((m) => preflight.results[m.key].kind === "origin")) {
        console.log(
            `\nneither host challenged the headless UA. Check that banjax-config.yaml has the\n` +
                `per_site_user_agent_decision_lists entries for ${SHA_HOST} and ${ALTCHA_HOST},\n` +
                `then reload banjax (docker compose restart banjax).`,
        );
        process.exit(2);
    }

    console.log("\nsummary (stopped = never reached the origin page):");
    console.log(`  ${"scenario".padEnd(22)}${"should stop".padEnd(13)}${MODES.map((m) => m.label.padEnd(14)).join("")}`);
    for (const { scenario, results } of rows) {
        const cells = MODES.map((m) => (results[m.key].kind === "origin" ? "through" : "stopped").padEnd(14));
        const stop = MODES.map((m) => (shouldStop(scenario, m) ? "yes" : "no"));
        const stopLabel = stop.every((v) => v === stop[0]) ? stop[0] : MODES.filter((m, i) => stop[i] === "yes").map((m) => m.key).join(",");
        console.log(`  ${scenario.name.padEnd(22)}${stopLabel.padEnd(13)}${cells.join("")}`);
    }
    if (regressions > 0) {
        console.log(`\n${regressions} client(s) that should have been stopped reached the origin`);
        process.exit(1);
    }
}

main().catch((err) => {
    console.error(err);
    process.exit(3);
});
