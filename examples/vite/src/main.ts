import './style.css'
import * as prem_rs from "@premai/reticle"
import { get as getEmoji } from "node-emoji";

const boolMoji = (b: boolean) => b ? getEmoji(':ok:') : getEmoji(':x:');

document.querySelector<HTMLDivElement>('#app')!.innerHTML = `
<section id="center">
  <div class="hero"></div>
  <div>
    <label for="server-url">Attestation server URL</label>
    <input id="server-url" type="url" value="http://localhost:8000" placeholder="http://localhost:8000" />
    <button id="attest-btn" class="ticks">Attest</button>
  </div>
  <pre id="output"></pre>
</section>
`

document.getElementById('attest-btn')!.addEventListener('click', async () => {
  const url = (document.getElementById('server-url') as HTMLInputElement).value.trim();
  const output = document.getElementById('output')!;

  output.textContent = 'Running…';
  (document.getElementById('attest-btn') as HTMLButtonElement).disabled = true;

  let client: prem_rs.Client | undefined;
  try {
    client = new prem_rs.ClientBuilder(url).build();
    const modules = await client.request_modules();
    await client.attest();
    output.textContent = [
      `${boolMoji(true)} Attestation passed`,
      `GPU capable: ${boolMoji(modules.has_gpu())}`,
    ].join('\n');
    modules.free();
  } catch (err) {
    output.textContent = `${boolMoji(false)} Attestation failed\n${err}`;
  } finally {
    client?.free();
    (document.getElementById('attest-btn') as HTMLButtonElement).disabled = false;
  }
});
