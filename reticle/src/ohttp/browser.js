// Browser IO bridge; framing, encryption, and authentication remain in Rust.
export function ohttpReadable(source) {
    let disposed = false;
    const dispose = () => {
        if (!disposed) {
            disposed = true;
            source.cancel();
            source.free();
        }
    };
    try {
        return new ReadableStream({
            async pull(controller) {
                try {
                    const chunk = await source.next();
                    if (disposed) return;
                    if (chunk === undefined) {
                        controller.close();
                        dispose();
                    } else {
                        controller.enqueue(chunk);
                    }
                } catch (error) {
                    if (!disposed) {
                        controller.error(error);
                        dispose();
                    }
                }
            },
            cancel: dispose,
        }, { highWaterMark: 0 });
    } catch (error) {
        dispose();
        throw error;
    }
}

async function bufferBody(body, signal) {
    const reader = body.getReader();
    const abort = () => reader.cancel().catch(() => {});
    signal.addEventListener('abort', abort, { once: true });
    try {
        const chunks = [];
        let length = 0;
        for (;;) {
            if (signal.aborted) throw signal.reason;
            const { done, value } = await reader.read();
            if (signal.aborted) throw signal.reason;
            if (done) break;
            chunks.push(value);
            length += value.byteLength;
        }
        const result = new Uint8Array(length);
        let offset = 0;
        for (const chunk of chunks) {
            result.set(chunk, offset);
            offset += chunk.byteLength;
        }
        return result;
    } finally {
        signal.removeEventListener('abort', abort);
        await reader.cancel().catch(() => {});
        reader.releaseLock();
    }
}

export function ohttpFetch(url, body, request, requestType, responseType, streamingUploads = false) {
    if (streamingUploads) {
        let duplexRead = false;
        const probe = new Request(url, {
            method: 'POST', body: new ReadableStream(),
            get duplex() { duplexRead = true; return 'half'; },
        });
        if (!duplexRead || probe.headers.has('Content-Type')) {
            throw new TypeError('This browser does not support streaming Fetch uploads');
        }
    }
    const controller = new AbortController();
    const abort = () => controller.abort(request.signal.reason);
    request.signal.addEventListener('abort', abort, { once: true });
    if (request.signal.aborted) abort();
    const dispose = () => {
        request.signal.removeEventListener('abort', abort);
        controller.abort();
        ohttpCancelStream(body);
    };
    try {
        return {
            // Buffer before the first network attempt: Fetch errors cannot safely
            // tell us whether a POST reached the server and is safe to replay.
            response: (async () => fetch(url, {
                method: 'POST',
                body: streamingUploads ? body : await bufferBody(body, controller.signal),
                ...(streamingUploads ? { duplex: 'half' } : {}),
                headers: { 'Content-Type': requestType, 'Accept': responseType },
                redirect: 'error', credentials: 'omit', cache: 'no-store',
                referrerPolicy: 'no-referrer', signal: controller.signal,
            }))(),
            dispose,
        };
    } catch (error) {
        dispose();
        throw error;
    }
}

export function ohttpFetchPromise(handle) { return handle.response; }
export function ohttpAbortFetch(handle) { handle.dispose(); }
export function ohttpCancelStream(stream) { stream.cancel().catch(() => {}); }
export function ohttpGetReader(stream) { return stream.getReader(); }
export async function ohttpRead(reader) {
    const result = await reader.read();
    return result.done ? undefined : result.value;
}
export function ohttpReleaseReader(reader) {
    reader.cancel().catch(() => {});
    reader.releaseLock();
}
export function ohttpRequestBody(request) { return request.body; }
export function ohttpResponseBody(response) { return response.body; }
export function ohttpResponse(body, status, headers) {
    return new Response(body, { status, headers });
}
