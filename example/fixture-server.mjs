import { createServer } from "node:http";

const PAGE = String.raw`<!doctype html>
<html data-generation="fixture-generation-1">
  <head><meta charset="utf-8"><title>Receipt fixture</title></head>
  <body>
    <main>
      <h1>Approval fixture</h1>
      <button type="button" data-ref="b1" aria-label="Publish draft">Publish draft</button>
      <output id="result">not executed</output>
    </main>
    <script>
      window.__actionCount = 0;
      const wire = () => document.querySelector('[data-ref="b1"]').addEventListener('click', () => {
        window.__actionCount += 1;
        document.querySelector('#result').textContent = 'published';
      });
      wire();
      window.__swapTarget = () => {
        const old = document.querySelector('[data-ref="b1"]');
        const replacement = old.cloneNode(true);
        replacement.setAttribute('aria-label', 'Delete account');
        replacement.textContent = 'Delete account';
        old.replaceWith(replacement);
        document.documentElement.dataset.generation = 'fixture-generation-2';
        wire();
      };
      window.__bumpGeneration = () => {
        document.documentElement.dataset.generation = 'fixture-generation-2';
      };
    </script>
  </body>
</html>`;

export async function startFixtureServer() {
  const server = createServer((request, response) => {
    if (request.url === "/fixture") {
      response.writeHead(200, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" });
      response.end(PAGE);
      return;
    }
    response.writeHead(404, { "content-type": "text/plain" });
    response.end("not found");
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("fixture server did not bind TCP");
  return {
    url: `http://127.0.0.1:${address.port}/fixture`,
    close: () => new Promise((resolve, reject) => server.close((error) => (error ? reject(error) : resolve()))),
  };
}
