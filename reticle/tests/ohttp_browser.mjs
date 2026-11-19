import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const source = await readFile(new URL('../src/ohttp/browser.js', import.meta.url), 'utf8');
const { ohttpFetch } = await import(`data:text/javascript;base64,${Buffer.from(source).toString('base64')}`);
const endpoint = 'https://relay.example/ohttp';
const requestType = 'message/ohttp-chunked-req';
const responseType = 'message/ohttp-chunked-res';

function send(body, signal = new AbortController().signal, streaming = false) {
    return ohttpFetch(endpoint, body, { signal }, requestType, responseType, streaming);
}

function chunks(...values) {
    return new ReadableStream({
        start(controller) {
            for (const value of values) controller.enqueue(new Uint8Array(value));
            controller.close();
        },
    });
}

test('buffered default works without streaming Request support and preserves response streaming', async (t) => {
    // Node lazily initializes its Fetch globals on first access.
    assert.equal(typeof globalThis.Request, 'function');
    t.mock.method(globalThis, 'Request', function () {
        throw new TypeError('Streaming uploads unsupported');
    });
    let responseController;
    const response = new Response(new ReadableStream({
        start(controller) { responseController = controller; },
    }));
    const fetch = t.mock.method(globalThis, 'fetch', async (url, init) => {
        assert.equal(url, endpoint);
        assert.deepEqual(init.body, new Uint8Array([1, 2, 3]));
        assert.equal('duplex' in init, false);
        assert.equal(init.headers['Content-Type'], requestType);
        assert.equal(init.headers.Accept, responseType);
        assert.equal(init.redirect, 'error');
        assert.equal(init.credentials, 'omit');
        return response;
    });
    const handle = send(chunks([1, 2], [3]));
    assert.equal(await handle.response, response);
    const reader = response.body.getReader();
    responseController.enqueue(new Uint8Array([4]));
    assert.deepEqual(await reader.read(), { done: false, value: new Uint8Array([4]) });
    responseController.close();
    assert.equal(fetch.mock.callCount(), 1);
    handle.dispose();
});

test('streaming uploads remain available explicitly', async (t) => {
    const body = chunks([1]);
    t.mock.method(globalThis, 'fetch', async (_url, init) => {
        assert.equal(init.body, body);
        assert.equal(init.duplex, 'half');
        return new Response();
    });
    const handle = send(body, undefined, true);
    await handle.response;
    handle.dispose();
});

test('network failures do not replay a POST', async (t) => {
    const fetch = t.mock.method(globalThis, 'fetch', async () => {
        throw new TypeError('Network failure');
    });
    const handle = send(chunks([1]));
    await assert.rejects(handle.response, /Network failure/);
    assert.equal(fetch.mock.callCount(), 1);
    handle.dispose();
});

test('body errors prevent any network request', async (t) => {
    const fetch = t.mock.method(globalThis, 'fetch', async () => new Response());
    const handle = send(new ReadableStream({
        start(controller) { controller.error(new Error('Upload failed')); },
    }));
    await assert.rejects(handle.response, /Upload failed/);
    assert.equal(fetch.mock.callCount(), 0);
    handle.dispose();
});

for (const mode of ['request abort', 'dispose', 'already aborted']) {
    test(`${mode} cancels buffering without sending`, async (t) => {
        let cancelled = false;
        const fetch = t.mock.method(globalThis, 'fetch', async () => new Response());
        const controller = new AbortController();
        if (mode === 'already aborted') controller.abort();
        const body = new ReadableStream({
            cancel() { cancelled = true; },
        });
        const handle = send(body, controller.signal);
        if (mode === 'dispose') handle.dispose();
        else controller.abort();
        await assert.rejects(handle.response, { name: 'AbortError' });
        assert.equal(cancelled, true);
        assert.equal(body.locked, false);
        assert.equal(fetch.mock.callCount(), 0);
        handle.dispose();
    });
}
