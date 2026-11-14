// The file browser of the web client (#69). Every action calls /client/api with the antiforgery token; the server
// checks the permissions and quotas again, so this script only offers what the page shows.
(function () {
    'use strict';
    const root = document.getElementById('file-browser');
    if (!root) return;

    const token = root.dataset.token;
    const directory = root.dataset.path;
    const chunkSize = parseInt(root.dataset.chunk, 10) || 8 * 1024 * 1024;
    const message = document.getElementById('client-message');

    const join = (dir, name) => (dir.endsWith('/') ? dir : dir + '/') + name;
    const reload = () => window.location.reload();

    function show(text, kind) {
        message.textContent = text;
        message.className = 'alert alert-' + (kind || 'danger');
    }

    async function api(method, url, body) {
        const response = await fetch(url, {
            method: method,
            headers: { 'RequestVerificationToken': token, 'Content-Type': 'application/json' },
            body: body === undefined ? undefined : JSON.stringify(body),
            credentials: 'same-origin'
        });
        let data = null;
        try { data = await response.json(); } catch { /* no body */ }
        if (!response.ok) throw new Error((data && data.error) || ('The server answered ' + response.status + '.'));
        return data;
    }

    // Selection
    const boxes = () => Array.from(document.querySelectorAll('.select-entry'));
    const selected = () => boxes().filter(b => b.checked).map(b => b.closest('tr').dataset.path);
    const zipButton = document.getElementById('zip-selected');
    const deleteButton = document.getElementById('delete-selected');
    function updateSelection() {
        const any = selected().length > 0;
        if (zipButton) zipButton.disabled = !any;
        if (deleteButton) deleteButton.disabled = !any;
    }
    boxes().forEach(b => b.addEventListener('change', updateSelection));
    const selectAll = document.getElementById('select-all');
    if (selectAll) selectAll.addEventListener('change', () => { boxes().forEach(b => { b.checked = selectAll.checked; }); updateSelection(); });

    const zipForm = document.getElementById('zip-form');
    if (zipForm) zipForm.addEventListener('submit', event => {
        zipForm.querySelectorAll('input[name="path"]').forEach(i => i.remove());
        const paths = selected();
        if (paths.length === 0) { event.preventDefault(); return; }
        for (const path of paths) {
            const input = document.createElement('input');
            input.type = 'hidden'; input.name = 'path'; input.value = path;
            zipForm.appendChild(input);
        }
    });

    async function remove(paths) {
        if (!window.confirm('Delete ' + (paths.length === 1 ? paths[0] : paths.length + ' entries') + '? Folders are deleted with everything in them.')) return;
        try { await api('POST', '/client/api/delete', { paths: paths }); reload(); } catch (e) { show(e.message); }
    }
    if (deleteButton) deleteButton.addEventListener('click', () => remove(selected()));

    // Name dialog for a new folder and for rename
    const dialog = document.getElementById('name-dialog');
    const nameInput = document.getElementById('name-input');
    let onName = null;
    function askName(title, value, callback) {
        document.getElementById('name-title').textContent = title;
        nameInput.value = value || '';
        onName = callback;
        dialog.showModal();
        nameInput.select();
    }
    document.getElementById('name-cancel').addEventListener('click', () => dialog.close());
    document.getElementById('name-form').addEventListener('submit', event => {
        event.preventDefault();
        const name = nameInput.value.trim();
        dialog.close();
        if (name && onName) onName(name);
    });

    const newFolder = document.getElementById('new-folder');
    if (newFolder) newFolder.addEventListener('click', () => askName('New folder', '', async name => {
        try { await api('POST', '/client/api/mkdir', { path: join(directory, name) }); reload(); } catch (e) { show(e.message); }
    }));

    document.querySelectorAll('tr.entry').forEach(row => {
        const rename = row.querySelector('.action-rename');
        if (rename) rename.addEventListener('click', () => askName('Rename ' + row.dataset.name, row.dataset.name, async name => {
            try { await api('POST', '/client/api/rename', { path: row.dataset.path, newName: name }); reload(); } catch (e) { show(e.message); }
        }));
        const del = row.querySelector('.action-delete');
        if (del) del.addEventListener('click', () => remove([row.dataset.path]));
    });

    // Upload: a check of all files first (permissions, existing files, quota), then each file in chunks with Content-Range.
    const list = document.getElementById('uploads');
    const input = document.getElementById('upload-input');
    const zone = document.getElementById('drop-zone');

    function addItem(file) {
        const item = document.createElement('li');
        item.className = 'upload-item mb-2';
        const title = document.createElement('div');
        title.className = 'd-flex gap-2 small';
        const name = document.createElement('span');
        name.className = 'text-break me-auto';
        name.textContent = file.name;
        const status = document.createElement('span');
        status.className = 'text-body-secondary';
        const cancel = document.createElement('button');
        cancel.type = 'button';
        cancel.className = 'btn btn-link btn-sm p-0';
        cancel.textContent = 'Cancel';
        title.append(name, status, cancel);
        const bar = document.createElement('progress');
        bar.max = Math.max(1, file.size);
        bar.value = 0;
        item.append(title, bar);
        list.appendChild(item);
        return { item, status, bar, cancel };
    }

    function sendChunk(url, blob, first, total, onProgress, state) {
        return new Promise((resolve, reject) => {
            const xhr = new XMLHttpRequest();
            state.xhr = xhr;
            xhr.open('POST', url);
            xhr.setRequestHeader('RequestVerificationToken', token);
            xhr.setRequestHeader('Content-Type', 'application/octet-stream');
            xhr.setRequestHeader('Content-Range', total === 0 ? 'bytes */0' : 'bytes ' + first + '-' + (first + blob.size - 1) + '/' + total);
            xhr.upload.onprogress = e => onProgress(first + e.loaded);
            xhr.onload = () => {
                let data = null;
                try { data = JSON.parse(xhr.responseText); } catch { /* no body */ }
                if (xhr.status >= 200 && xhr.status < 300) resolve(data);
                else reject({ status: xhr.status, message: (data && data.error) || ('The server answered ' + xhr.status + '.'), offset: data && data.offset });
            };
            xhr.onerror = () => reject({ status: 0, message: 'The connection failed.' });
            xhr.onabort = () => reject({ status: -1, message: 'Canceled.' });
            xhr.send(blob);
        });
    }

    async function uploadFile(file, overwrite, ui) {
        const id = (crypto.randomUUID ? crypto.randomUUID() : String(Date.now()) + Math.random()).replace(/[^A-Za-z0-9]/g, '').slice(0, 32);
        const path = join(directory, file.name);
        const url = '/client/api/upload?path=' + encodeURIComponent(path) + '&id=' + id + (overwrite ? '&overwrite=true' : '');
        const state = { canceled: false, xhr: null };
        ui.cancel.onclick = () => {
            state.canceled = true;
            if (state.xhr) state.xhr.abort();
            fetch('/client/api/upload?id=' + id, { method: 'DELETE', headers: { 'RequestVerificationToken': token } });
        };
        let offset = 0;
        let retries = 0;
        do {
            const end = Math.min(file.size, offset + chunkSize);
            try {
                const result = await sendChunk(url, file.slice(offset, end), offset, file.size, loaded => { ui.bar.value = loaded; }, state);
                offset = result.offset;
                retries = 0;
                ui.bar.value = offset;
                ui.status.textContent = Math.floor(100 * offset / Math.max(1, file.size)) + ' %';
                if (result.complete) break;
            } catch (e) {
                if (state.canceled) throw new Error('Canceled.');
                // A lost connection or a chunk out of order: ask the server where the upload is, and go on there.
                if ((e.status === 0 || e.status === 409) && retries < 5) {
                    retries++;
                    await new Promise(r => setTimeout(r, 1000 * retries));
                    const status = await fetch('/client/api/upload?path=' + encodeURIComponent(path) + '&id=' + id, { credentials: 'same-origin' }).then(r => r.json()).catch(() => null);
                    offset = status && status.known ? status.offset : 0;
                    continue;
                }
                throw new Error(e.message);
            }
        } while (offset < file.size || file.size === 0);
        ui.status.textContent = 'done';
        ui.cancel.remove();
    }

    async function upload(files) {
        if (!files || files.length === 0) return;
        files = Array.from(files);
        let checks;
        try {
            checks = await api('POST', '/client/api/upload/check', { files: files.map(f => ({ path: join(directory, f.name), size: f.size })) });
        } catch (e) { show(e.message); return; }
        const problems = checks.filter(c => c.problem);
        if (problems.length > 0) {
            show(problems.map(p => p.path + ': ' + p.problem).join(' '));
        }
        let any = false;
        for (let i = 0; i < files.length; i++) {
            const check = checks[i];
            if (check.problem) continue;
            if (check.exists && !window.confirm(files[i].name + ' exists. Overwrite it?')) continue;
            const ui = addItem(files[i]);
            try {
                await uploadFile(files[i], check.exists, ui);
                any = true;
            } catch (e) {
                ui.status.textContent = e.message;
                ui.status.className = 'text-danger';
                ui.cancel.remove();
            }
        }
        if (any && problems.length === 0) reload();
    }

    if (input) input.addEventListener('change', () => { upload(input.files); input.value = ''; });
    if (zone) {
        zone.addEventListener('dragover', e => { e.preventDefault(); zone.classList.add('drag-over'); });
        zone.addEventListener('dragleave', () => zone.classList.remove('drag-over'));
        zone.addEventListener('drop', e => { e.preventDefault(); zone.classList.remove('drag-over'); upload(e.dataTransfer.files); });
    }
})();
