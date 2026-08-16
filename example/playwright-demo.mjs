import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { chromium } from "playwright";
import {
  FileReceiptLedger,
  createTargetObservation,
  executePreparedAction,
  makeApprovalDecision,
  prepareAction,
  sha256Hex,
} from "../dist/index.js";
import { startFixtureServer } from "./fixture-server.mjs";

function rawFingerprint(target) {
  return [
    target.tag,
    target.type,
    target.label,
    target.href,
    target.formAction,
  ].join("|");
}

async function observe(page) {
  const raw = await page.evaluate(() => {
    const element = document.querySelector('[data-ref="b1"]');
    const anchor = element.closest("a[href]");
    const form = element.closest("form");
    return {
      url: location.href,
      generation: document.documentElement.dataset.generation,
      target: {
        tag: element.tagName.toLowerCase(),
        type: (element.getAttribute("type") || "").toLowerCase(),
        label: (element.getAttribute("aria-label") || element.textContent || "").trim(),
        href: anchor ? new URL(anchor.href, location.href).href : "",
        formAction: form ? new URL(form.action || location.href, location.href).href : "",
      },
    };
  });
  return {
    rawObservation: {
      origin: new URL(raw.url).origin,
      pathname: new URL(raw.url).pathname,
      fingerprint: rawFingerprint(raw.target),
      generation: raw.generation,
    },
    observation: createTargetObservation({
      url: raw.url,
      targetFingerprint: rawFingerprint(raw.target),
      pageGeneration: raw.generation,
    }),
  };
}

function playwrightAdapter(page, expectedRawObservation) {
  return {
    capability: "atomic-compare-and-act/v1",
    async compareAndAct(input) {
      const result = await page.evaluate(
        ({ expectedRaw, action, payload }) => {
          const element = [...document.querySelectorAll("[data-ref]")].find(
            (candidate) => candidate.getAttribute("data-ref") === payload.ref,
          );
          const currentRaw = element
            ? (() => {
                const anchor = element.closest("a[href]");
                const form = element.closest("form");
                return [
                  element.tagName.toLowerCase(),
                  (element.getAttribute("type") || "").toLowerCase(),
                  (element.getAttribute("aria-label") || element.textContent || "").trim(),
                  anchor ? new URL(anchor.href, location.href).href : "",
                  form ? new URL(form.action || location.href, location.href).href : "",
                ].join("|");
              })()
            : "target-missing";
          const snapshot = {
            url: location.href,
            generation: document.documentElement.dataset.generation,
            currentRaw,
          };
          if (
            location.origin !== expectedRaw.origin ||
            location.pathname !== expectedRaw.pathname ||
            currentRaw !== expectedRaw.fingerprint ||
            snapshot.generation !== expectedRaw.generation
          ) {
            return { status: "target_changed", ...snapshot };
          }
          if (action !== "click") throw new Error("demo_action_unsupported");
          element.click();
          return { status: "committed", ...snapshot };
        },
        { expectedRaw: expectedRawObservation, action: input.action, payload: input.payload },
      );
      return {
        status: result.status,
        observation: createTargetObservation({
          url: result.url,
          targetFingerprint: result.currentRaw,
          pageGeneration: result.generation,
        }),
      };
    },
  };
}

async function launchBrowser() {
  try {
    return await chromium.launch({ headless: true });
  } catch (error) {
    if (process.platform !== "darwin") throw error;
    return chromium.launch({ channel: "chrome", headless: true });
  }
}

async function runScenario(page, ledgerRoot, url, mutation, operationId) {
  await page.goto(url);
  const first = await observe(page);
  const prepared = prepareAction({
    action: "click",
    riskClass: "R2",
    observation: first.observation,
    payload: { ref: "b1" },
    approvalDisplay: {
      title: "Publish draft",
      detail: "Click the selected fixture button",
    },
    operationId,
  });
  const decision = makeApprovalDecision(prepared.approvalRequest, "approved");
  if (mutation === "target") await page.evaluate(() => window.__swapTarget());
  if (mutation === "generation") await page.evaluate(() => window.__bumpGeneration());
  const ledger = new FileReceiptLedger(ledgerRoot);
  const outcome = await executePreparedAction({
    prepared,
    decision,
    adapter: playwrightAdapter(page, first.rawObservation),
    ledger,
    capture: async () => ({
      artifactRef: `fixture.capture.${mutation ?? "stable"}`,
      contentHash: sha256Hex(await page.locator("body").innerText()),
    }),
  });
  assert.equal(outcome.kind, "recorded");
  return {
    receipt: outcome.receipt,
    actionCount: await page.evaluate(() => window.__actionCount),
  };
}

const fixture = await startFixtureServer();
const browser = await launchBrowser();
const ledgerRoot = await mkdtemp(join(tmpdir(), "browser-action-demo-"));
try {
  const page = await browser.newPage();
  const stable = await runScenario(
    page,
    ledgerRoot,
    fixture.url,
    null,
    "00000000-0000-4000-8000-000000000101",
  );
  const changed = await runScenario(
    page,
    ledgerRoot,
    fixture.url,
    "target",
    "00000000-0000-4000-8000-000000000102",
  );
  const generationChanged = await runScenario(
    page,
    ledgerRoot,
    fixture.url,
    "generation",
    "00000000-0000-4000-8000-000000000103",
  );
  assert.equal(stable.receipt.result.status, "committed");
  assert.equal(stable.actionCount, 1);
  assert.equal(changed.receipt.result.status, "aborted_target_changed");
  assert.equal(changed.actionCount, 0);
  assert.equal(generationChanged.receipt.result.status, "aborted_target_changed");
  assert.equal(generationChanged.actionCount, 0);
  process.stdout.write(
    `${JSON.stringify({
      stable: { status: stable.receipt.result.status, actionCount: stable.actionCount },
      changed: { status: changed.receipt.result.status, actionCount: changed.actionCount },
      generationChanged: {
        status: generationChanged.receipt.result.status,
        actionCount: generationChanged.actionCount,
      },
    })}\n`,
  );
} finally {
  await browser.close();
  await fixture.close();
  await rm(ledgerRoot, { recursive: true, force: true });
}
