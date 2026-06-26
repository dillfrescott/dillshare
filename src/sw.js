/*
 * Dill Share streaming-preview service worker.
 *
 * Intercepts URLs of the form:
 *     /preview-stream/<uuid>/<fileId>
 * and returns decrypted plaintext byte ranges on demand, so a <video>/<audio>
 * element can begin playback immediately while the rest of the file is still
 * being fetched and decrypted from the server.
 *
 * The page supplies the decryption key, file metadata (size, chunked flag,
 * content type) and the upstream encrypted file URL via postMessage before
 * loading the media element's src. This works for ANY media container
 * (mp4, mkv, webm, mov, mp3, wav, flac, opus, aac, m4a, ...) because the
 * browser's media engine performs standard HTTP range requests against this
 * virtual URL; the SW transparently decrypts the requested byte range.
 *
 * Encryption formats supported (mirrors the page crypto):
 *   - Chunked AES-GCM: file is N chunks. Each chunk = IV(12) || ct+tag.
 *     Chunk i covers plaintext [i*CHUNK_SIZE, min((i+1)*CHUNK_SIZE, totalSize)).
 *     Ciphertext chunk boundaries are derived from the known total plaintext
 *     size, so a plaintext byte range maps to a known set of ciphertext chunks.
 *   - Legacy single-block AES-GCM: IV(12) || ct+tag for the whole file.
 *     For this format we decrypt the entire file once (caching it) the first
 *     time a range is requested, because individual byte ranges cannot be
 *     decrypted independently of the surrounding GCM tag.
 */

const CHUNK_SIZE = 4 * 1024 * 1024; // 4 MB plaintext per chunk (matches page)
const STREAM_PREFIX = '/preview-stream/';

// Map<fileKey, { key, size, chunked, ctSize, contentType, url, cached: Uint8Array|null }>
const files = new Map();

function ctSizeFor(totalPlain, chunked) {
    if (!chunked) return null; // unknown without fetching; handled lazily
    const n = Math.max(1, Math.ceil(totalPlain / CHUNK_SIZE));
    // each chunk: 12 + (plain + 16)
    let total = 0;
    let rem = totalPlain;
    for (let i = 0; i < n; i++) {
        const thisPlain = Math.min(CHUNK_SIZE, rem);
        total += 12 + thisPlain + 16;
        rem -= thisPlain;
    }
    return total;
}

// Plain byte range [start, end) -> set of ciphertext byte ranges to fetch.
function plainRangeToCtRanges(start, end, totalPlain) {
    const firstChunk = Math.floor(start / CHUNK_SIZE);
    const lastChunk = Math.floor((end - 1) / CHUNK_SIZE);
    const ranges = [];
    let cursor = 0; // ciphertext offset
    let rem = totalPlain;
    for (let i = 0; i <= lastChunk; i++) {
        const thisPlain = Math.min(CHUNK_SIZE, rem);
        const ctLen = 12 + thisPlain + 16;
        if (i >= firstChunk) {
            const plainStartInChunk = (i === firstChunk) ? (start - i * CHUNK_SIZE) : 0;
            const plainEndInChunk = (i === lastChunk) ? (end - i * CHUNK_SIZE) : thisPlain;
            // ciphertext layout within this chunk: IV(12) then ct(plainLen+16)
            const ctStart = cursor + 12 + plainStartInChunk;
            const ctEnd = cursor + 12 + plainEndInChunk; // exclusive
            ranges.push({ chunkIndex: i, plainStartInChunk, plainEndInChunk, ctStart, ctEnd, ivStart: cursor, ivLen: 12 });
        }
        cursor += ctLen;
        rem -= thisPlain;
    }
    return ranges;
}

async function decryptChunk(ivBytes, ctBytes, key) {
    return new Uint8Array(await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: ivBytes },
        key,
        ctBytes
    ));
}

async function importKeyFromRaw(rawBuf) {
    return crypto.subtle.importKey('raw', rawBuf, { name: 'AES-GCM' }, false, ['decrypt']);
}

self.addEventListener('message', async (event) => {
    const d = event.data;
    if (!d) return;
    if (d.type === 'DILL_PREVIEW_INIT') {
        try {
            const key = await importKeyFromRaw(d.keyRaw);
            const entry = {
                key,
                size: d.size,
                chunked: !!d.chunked,
                ctSize: d.chunked ? ctSizeFor(d.size, true) : null,
                contentType: d.contentType || 'application/octet-stream',
                url: d.url,
                cached: null, // only used for legacy single-block format
            };
            files.set(d.streamPath, entry);
            if (event.source) event.source.postMessage({ type: 'DILL_PREVIEW_READY', streamPath: d.streamPath });
        } catch (e) {
            if (event.source) event.source.postMessage({ type: 'DILL_PREVIEW_READY', streamPath: d.streamPath, error: String(e) });
        }
        return;
    }
});

self.addEventListener('activate', (event) => {
    event.waitUntil((async () => {
        // Take control of all open clients immediately.
        await self.clients.claim();
        const all = await self.clients.matchAll({ includeUncontrolled: true });
        for (const c of all) c.postMessage({ type: 'DILL_SW_ACTIVE' });
    })());
});

self.addEventListener('fetch', (event) => {
    const url = new URL(event.request.url);
    if (!url.pathname.startsWith(STREAM_PREFIX)) return;
    event.respondWith(handleStream(event.request, url.pathname));
});

async function handleStream(request, streamPath) {
    const meta = files.get(streamPath);
    if (!meta) {
        return new Response('Preview stream not initialized', { status: 503 });
    }

    // Determine the plaintext range requested.
    const total = meta.size;

    // HEAD-like request without range: return 200 + full size, no body needed for media probe.
    if (request.method === 'HEAD') {
        return new Response(null, {
            status: 200,
            headers: headHeaders(meta, total),
        });
    }

    const rangeHeader = request.headers.get('Range');
    let start = 0;
    let end = total; // exclusive
    let isRange = false;
    if (rangeHeader && rangeHeader.startsWith('bytes=')) {
        const spec = rangeHeader.slice(6).split(',')[0].trim();
        const m = /^(\d+)-(\d*)$/.exec(spec);
        if (m) {
            start = parseInt(m[1], 10);
            if (m[2] !== '') {
                end = parseInt(m[2], 10) + 1; // inclusive->exclusive
            } else {
                end = total;
            }
            isRange = true;
        }
    }
    if (end > total) end = total;
    if (start > end) start = end;

    try {
        if (meta.chunked) {
            return await respondChunkedRange(meta, start, end, isRange);
        } else {
            return await respondLegacyRange(meta, start, end, isRange, total);
        }
    } catch (e) {
        return new Response('Decryption error: ' + e, { status: 500 });
    }
}

function headHeaders(meta, total) {
    const h = {
        'Content-Type': meta.contentType,
        'Accept-Ranges': 'bytes',
        'Content-Length': String(total),
        'Cache-Control': 'no-store',
    };
    return h;
}

async function respondChunkedRange(meta, start, end, isRange) {
    const ranges = plainRangeToCtRanges(start, end, meta.size);
    const totalLength = end - start;
    const status = isRange ? 206 : 200;
    const headers = {
        'Content-Type': meta.contentType,
        'Accept-Ranges': 'bytes',
        'Content-Length': String(totalLength),
        'Cache-Control': 'no-store',
    };
    if (isRange) {
        headers['Content-Range'] = `bytes ${start}-${end - 1}/${meta.size}`;
    }

    // Stream decrypted chunk slices to the media element as they are produced,
    // so playback can begin after the first chunk arrives instead of waiting
    // for the entire requested range to be decrypted.
    let aborted = false;
    const stream = new ReadableStream({
        async start(controller) {
            try {
                for (const r of ranges) {
                    if (aborted) break;
                    // Fetch IV + the ct slice needed for this chunk in one range request.
                    const fetchStart = r.ivStart;
                    const fetchEnd = r.ctEnd; // exclusive
                    const res = await fetch(meta.url, {
                        headers: { Range: `bytes=${fetchStart}-${fetchEnd - 1}` },
                    });
                    if (!res.ok && res.status !== 206) {
                        throw new Error('Upstream fetch failed: ' + res.status);
                    }
                    const buf = new Uint8Array(await res.arrayBuffer());
                    const iv = buf.subarray(0, 12);
                    const ct = buf.subarray(12, buf.length); // exactly the ct slice we requested
                    const pt = await decryptChunk(iv, ct, meta.key);
                    // Yield only the requested plaintext sub-slice of this chunk.
                    const piece = pt.subarray(r.plainStartInChunk, r.plainEndInChunk);
                    if (piece.length > 0) controller.enqueue(piece);
                }
                controller.close();
            } catch (err) {
                controller.error(err);
            }
        },
        cancel() { aborted = true; }
    });

    return new Response(stream, { status, headers });
}

async function respondLegacyRange(meta, start, end, isRange, total) {
    // Legacy single-block format: must decrypt the whole file once, then slice.
    if (!meta.cached) {
        const res = await fetch(meta.url);
        if (!res.ok) throw new Error('Upstream fetch failed: ' + res.status);
        const ab = await res.arrayBuffer();
        const data = new Uint8Array(ab);
        const iv = data.subarray(0, 12);
        const ct = data.subarray(12);
        const pt = await decryptChunk(iv, ct, meta.key);
        meta.cached = pt;
    }
    const slice = meta.cached.subarray(start, end);
    const status = isRange ? 206 : 200;
    const headers = {
        'Content-Type': meta.contentType,
        'Accept-Ranges': 'bytes',
        'Content-Length': String(slice.length),
        'Cache-Control': 'no-store',
    };
    if (isRange) {
        headers['Content-Range'] = `bytes ${start}-${start + slice.length - 1}/${total}`;
    }
    return new Response(slice, { status, headers });
}

function concat(arrays) {
    let total = 0;
    for (const a of arrays) total += a.length;
    const out = new Uint8Array(total);
    let o = 0;
    for (const a of arrays) { out.set(a, o); o += a.length; }
    return out;
}