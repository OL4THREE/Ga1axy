/**
 * Ga1axy Web Interface - Frontend Application
 */

// ─────────────── Initialization ───────────────

document.addEventListener('DOMContentLoaded', () => {
    initTabs();
    initTheme();
    initHashDBStats();
    initFileOperationChange();
});

// ─────────────── Tab Navigation ───────────────

function initTabs() {
    const navItems = document.querySelectorAll('.nav-item');
    navItems.forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            const tabId = item.dataset.tab;
            switchTab(tabId);
        });
    });

    // Handle hash fragment on page load
    if (window.location.hash) {
        const tabId = window.location.hash.slice(1);
        const navItem = document.querySelector(`.nav-item[data-tab="${tabId}"]`);
        if (navItem) {
            switchTab(tabId);
            setTimeout(() => {
                document.querySelector('.main-content')?.scrollTo({ top: 0 });
            }, 50);
        }
    }
}

function switchTab(tabId) {
    // Update nav items
    document.querySelectorAll('.nav-item').forEach(item => {
        item.classList.toggle('active', item.dataset.tab === tabId);
    });

    // Update tab content
    document.querySelectorAll('.tab-content').forEach(tab => {
        tab.classList.toggle('active', tab.id === `tab-${tabId}`);
    });

    // Update URL hash
    history.replaceState(null, '', `#${tabId}`);
}

// ─────────────── Theme ───────────────

function initTheme() {
    const saved = localStorage.getItem('ga1axy-theme');
    if (saved) {
        document.documentElement.setAttribute('data-theme', saved);
    }

    document.getElementById('themeToggle')?.addEventListener('click', () => {
        const current = document.documentElement.getAttribute('data-theme');
        const next = current === 'light' ? 'dark' : 'light';
        document.documentElement.setAttribute('data-theme', next);
        localStorage.setItem('ga1axy-theme', next);
    });
}

// ─────────────── Toast Notifications ───────────────

function showToast(message, type = 'success') {
    const toast = document.getElementById('toast');
    toast.textContent = message;
    toast.className = `toast ${type} show`;
    setTimeout(() => toast.classList.remove('show'), 3000);
}

// ─────────────── Helpers ───────────────

function clearInput(prefix) {
    document.querySelectorAll(`[id^="${prefix}_"]`).forEach(el => {
        if (el.tagName === 'TEXTAREA' || el.tagName === 'INPUT') {
            if (el.type !== 'file') el.value = '';
        }
    });
    // Hide runtime outputs
    if (prefix === 'runtime') {
        document.getElementById('runtime_outputs').style.display = 'none';
    }
    // Hide JWT decode detail pane
    if (prefix === 'jwt') {
        const el = document.getElementById('jwt_decode_result');
        if (el) el.style.display = 'none';
    }
    // Clear file results
    if (prefix === 'file') {
        document.getElementById('file_results_container').style.display = 'none';
    }
}

function swapInputOutput(prefix) {
    // JWT swap: put the output token into the payload field (since that's what gets sent for decode)
    if (prefix === 'jwt') {
        const outputEl = document.getElementById(`${prefix}_output`);
        const payloadEl = document.getElementById('jwt_payload');
        if (!outputEl || !payloadEl) return;
        const outputVal = outputEl.value;
        if (!outputVal || outputVal.startsWith('❌') || outputVal.startsWith('⏳')) {
            showToast('没有可用结果可互换', 'error');
            return;
        }
        payloadEl.value = outputVal;
        outputEl.value = '';
        showToast('Token 已填入 Payload 输入框（解码时输入）');
        return;
    }

    const inputEl = document.getElementById(`${prefix}_text`);
    const outputEl = document.getElementById(`${prefix}_output`);
    if (!inputEl || !outputEl) return;
    const outputVal = outputEl.value;
    if (!outputVal || outputVal.startsWith('❌') || outputVal.startsWith('⏳')) {
        showToast('没有可用结果可互换', 'error');
        return;
    }
    inputEl.value = outputVal;
    outputEl.value = '';
    showToast('输出结果已填入输入框');
}

function swapIntoInput(inputId, outputId) {
    const inputEl = document.getElementById(inputId);
    const outputEl = document.getElementById(outputId);
    if (!inputEl || !outputEl) return;
    const outputVal = outputEl.value;
    if (!outputVal || outputVal.startsWith('❌') || outputVal.startsWith('⏳')) {
        showToast('没有可用结果可互换', 'error');
        return;
    }
    inputEl.value = outputVal;
    outputEl.value = '';
    showToast('输出结果已填入输入框');
}

function copyOutput(elementId) {
    const el = document.getElementById(elementId);
    if (!el || !el.value) {
        showToast('没有内容可复制', 'error');
        return;
    }
    navigator.clipboard.writeText(el.value).then(() => {
        showToast('已复制到剪贴板');
    }).catch(() => {
        // Fallback
        el.select();
        document.execCommand('copy');
        showToast('已复制到剪贴板');
    });
}

// ─────────────── API Calls ───────────────

async function apiCall(url, data) {
    const response = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data),
    });
    if (!response.ok) {
        const err = await response.json().catch(() => ({ error: response.statusText }));
        throw new Error(err.error || `请求失败 (${response.status})`);
    }
    return response.json();
}

// ─────────────── Generic Crypto ───────────────

async function crypto(operation, mode) {
    const text = document.getElementById(`${operation}_text`)?.value;
    if (!text || !text.trim()) {
        showToast('请输入文本内容', 'error');
        return;
    }

    const btn = document.querySelector(`[onclick*="crypto('${operation}','${mode}')"]`);
    if (btn) btn.classList.add('loading');

    try {
        const result = await apiCall(`/api/crypto/${operation}`, { text, mode });

        // Special handling for runtime (uses multi-output, no single _output element)
        if (operation === 'runtime' && mode === 'e' && result.formats) {
            document.getElementById('runtime_outputs').style.display = 'grid';
            document.getElementById('runtime_base64').value = result.result;
            document.getElementById('runtime_bash').value = result.formats.bash || '';
            document.getElementById('runtime_powershell').value = result.formats.powershell || '';
            document.getElementById('runtime_python').value = result.formats.python || '';
            document.getElementById('runtime_perl').value = result.formats.perl || '';
            showToast('操作成功');
            return;
        }

        const outputEl = document.getElementById(`${operation}_output`);
        if (!outputEl) return;

        if (!result.success) {
            outputEl.value = `❌ 操作失败: ${result.error}`;
            showToast('操作失败', 'error');
            return;
        }

        outputEl.value = result.result;

        // Special handling for hex formats
        if (operation === 'hex' && mode === 'e' && result.formats) {
            const formatDiv = document.getElementById('hex_formats');
            const formatList = document.getElementById('hex_format_list');
            if (formatDiv && formatList) {
                formatDiv.style.display = 'block';
                formatList.innerHTML = Object.entries(result.formats)
                    .map(([key, val]) => `<div class="format-item"><strong>${key}:</strong> ${val}</div>`)
                    .join('');
            }
        }

        showToast('操作成功');
    } catch (err) {
        showToast(err.message, 'error');
    } finally {
        if (btn) btn.classList.remove('loading');
    }
}

// ─────────────── Base Crypto ───────────────

async function cryptoBase(mode) {
    const text = document.getElementById('base_text')?.value;
    if (!text || !text.trim()) {
        showToast('请输入文本内容', 'error');
        return;
    }

    const btn = document.querySelector(`[onclick*="cryptoBase('${mode}')"]`);
    if (btn) btn.classList.add('loading');

    try {
        const ops = ['base16', 'base32', 'base64', 'base85'];
        const promises = ops.map(op => apiCall(`/api/crypto/${op}`, { text, mode }));
        const results = await Promise.all(promises);

        ops.forEach((op, idx) => {
            const el = document.getElementById(`${op}_output`);
            if (el && results[idx]) {
                el.value = results[idx].success ? results[idx].result : `❌ ${results[idx].error}`;
            }
        });

        showToast('操作成功');
    } catch (err) {
        showToast(err.message, 'error');
    } finally {
        if (btn) btn.classList.remove('loading');
    }
}

// ─────────────── SHA ───────────────

async function cryptoSHA(mode) {
    const text = document.getElementById('sha_text')?.value;
    const type = document.getElementById('sha_type')?.value;
    if (!text || !text.trim()) {
        showToast('请输入文本内容', 'error');
        return;
    }

    const btn = document.querySelector(`#tab-sha .btn-primary, #tab-sha .btn-secondary`);
    if (btn && [...btn.parentElement.children].includes(btn)) {
        // Find which button was clicked
    }
    const clickedBtn = mode === 'e'
        ? document.querySelector('#tab-sha .btn-primary')
        : document.querySelector('#tab-sha .btn-secondary');
    if (clickedBtn) clickedBtn.classList.add('loading');

    try {
        const result = await apiCall(`/api/crypto/${type}`, { text, mode });
        const outputEl = document.getElementById('sha_output');
        if (!outputEl) return;

        if (!result.success) {
            outputEl.value = `❌ 操作失败: ${result.error}`;
            showToast('操作失败', 'error');
            return;
        }

        outputEl.value = result.result;
        showToast('操作成功');
    } catch (err) {
        showToast(err.message, 'error');
    } finally {
        if (clickedBtn) clickedBtn.classList.remove('loading');
    }
}

// ─────────────── Symmetric (DES/AES) ───────────────

async function cryptoSym(algorithm, mode) {
    const text = document.getElementById(`${algorithm}_text`)?.value;
    const key = document.getElementById(`${algorithm}_key`)?.value;
    const iv = document.getElementById(`${algorithm}_iv`)?.value;
    const cryptoMode = document.getElementById(`${algorithm}_mode`)?.value;
    const resultFormat = document.getElementById(`${algorithm}_result`)?.value;

    if (!text || !text.trim()) {
        showToast('请输入文本内容', 'error');
        return;
    }

    const clickedBtn = mode === 'e'
        ? document.querySelector(`#tab-${algorithm} .btn-primary`)
        : document.querySelector(`#tab-${algorithm} .btn-secondary`);
    if (clickedBtn) clickedBtn.classList.add('loading');

    try {
        const result = await apiCall(`/api/crypto/${algorithm}`, {
            text, mode, key, iv, crypto_mode: cryptoMode, result: resultFormat
        });
        const outputEl = document.getElementById(`${algorithm}_output`);
        if (!outputEl) return;

        if (!result.success) {
            outputEl.value = `❌ 操作失败: ${result.error}`;
            showToast('操作失败', 'error');
            return;
        }

        outputEl.value = result.result;
        showToast('操作成功');
    } catch (err) {
        showToast(err.message, 'error');
    } finally {
        if (clickedBtn) clickedBtn.classList.remove('loading');
    }
}

// ─────────────── JWT ───────────────

async function cryptoJWT(mode) {
    if (mode === 'e') {
        // 编码：从 Header + Payload 生成 Token
        const payload = document.getElementById('jwt_payload')?.value;
        const header = document.getElementById('jwt_header')?.value;
        const key = document.getElementById('jwt_key')?.value;
        const algorithm = document.getElementById('jwt_algorithm')?.value;
        const tokenEl = document.getElementById('jwt_token');

        if (!payload || !payload.trim()) {
            showToast('请输入 Payload 内容', 'error');
            return;
        }

        const clickedBtn = document.querySelector('#tab-jwt .card:first-child .btn-primary');
        if (clickedBtn) clickedBtn.classList.add('loading');

        try {
            const result = await apiCall('/api/crypto/jwt', { text: payload, header, mode, key, algorithm });
            if (!result.success) {
                showToast(`编码失败: ${result.error}`, 'error');
                return;
            }
            if (tokenEl) {
                tokenEl.value = result.result;
                showToast('Token 已生成并填入下方解码区');
            }
        } catch (err) {
            showToast(err.message, 'error');
        } finally {
            if (clickedBtn) clickedBtn.classList.remove('loading');
        }
    } else {
        // 解码：从 Token 解析出 Header / Payload
        const token = document.getElementById('jwt_token')?.value;
        if (!token || !token.trim()) {
            showToast('请输入 JWT Token', 'error');
            return;
        }

        const clickedBtn = document.querySelector('#tab-jwt .card:nth-child(2) .btn-secondary');
        if (clickedBtn) clickedBtn.classList.add('loading');

        try {
            const result = await apiCall('/api/crypto/jwt', { text: token, mode: 'd' });
            const decodeResult = document.getElementById('jwt_decode_result');
            if (!decodeResult) return;

            if (!result.success) {
                showToast(`解码失败: ${result.error}`, 'error');
                decodeResult.style.display = 'none';
                return;
            }

            if (typeof result.result === 'object' && result.result !== null) {
                decodeResult.style.display = 'block';
                document.getElementById('jwt_decode_header').value =
                    typeof result.result.header === 'string'
                        ? formatJsonString(result.result.header)
                        : JSON.stringify(result.result.header, null, 2);
                document.getElementById('jwt_decode_payload').value =
                    typeof result.result.payload === 'string'
                        ? formatJsonString(result.result.payload)
                        : JSON.stringify(result.result.payload, null, 2);
                document.getElementById('jwt_decode_signature').value = result.result.signature || '';
                showToast('解码成功');
            } else {
                decodeResult.style.display = 'none';
                showToast('解码结果格式异常', 'error');
            }
        } catch (err) {
            showToast(err.message, 'error');
        } finally {
            if (clickedBtn) clickedBtn.classList.remove('loading');
        }
    }
}

function formatJsonString(str) {
    try {
        return JSON.stringify(JSON.parse(str), null, 2);
    } catch {
        try {
            // Python dict style -> JSON
            return JSON.stringify(eval('(' + str.replace(/'/g, '"') + ')'), null, 2);
        } catch {
            return str;
        }
    }
}

// ─────────────── Base64 Image ───────────────

async function encodeBase64Img() {
    const fileInput = document.getElementById('baseimg_encode_file');
    if (!fileInput.files || !fileInput.files[0]) {
        showToast('请选择图片文件', 'error');
        return;
    }

    const btn = document.querySelector('#tab-baseimg .card:first-child .btn-primary');
    if (btn) btn.classList.add('loading');

    try {
        const formData = new FormData();
        formData.append('file', fileInput.files[0]);
        formData.append('mode', 'e');

        const response = await fetch('/api/crypto/base64img', {
            method: 'POST',
            body: formData,
        });
        const result = await response.json();

        const outputEl = document.getElementById('baseimg_encode_output');
        if (!outputEl) return;

        if (!result.success) {
            outputEl.value = `❌ 操作失败: ${result.error}`;
            showToast('编码失败', 'error');
            return;
        }

        outputEl.value = result.result;
        showToast('编码成功');
    } catch (err) {
        showToast(err.message, 'error');
    } finally {
        if (btn) btn.classList.remove('loading');
    }
}

async function decodeBase64Img() {
    const fileInput = document.getElementById('baseimg_decode_file');
    const outputEl = document.getElementById('baseimg_decode_output');
    if (!outputEl) return;

    if (!fileInput.files || !fileInput.files[0]) {
        showToast('请选择 Base64 文本文件', 'error');
        return;
    }

    const btn = document.querySelector('#tab-baseimg .card:last-child .btn-secondary');
    if (btn) btn.classList.add('loading');

    try {
        const formData = new FormData();
        formData.append('file', fileInput.files[0]);
        formData.append('mode', 'd');

        const response = await fetch('/api/crypto/base64img', {
            method: 'POST',
            body: formData,
        });
        const result = await response.json();

        if (!result.success) {
            outputEl.value = `❌ 操作失败: ${result.error}`;
            showToast('解码失败', 'error');
            return;
        }

        outputEl.value = result.result;
        showToast('解码成功，图片已生成');
    } catch (err) {
        showToast(err.message, 'error');
    } finally {
        if (btn) btn.classList.remove('loading');
    }
}

async function decodeBase64ImgText() {
    const text = document.getElementById('baseimg_decode_text')?.value;
    const outputEl = document.getElementById('baseimg_decode_output');
    if (!outputEl) return;

    if (!text || !text.trim()) {
        showToast('请输入 Base64 文本内容', 'error');
        return;
    }

    const btn = document.querySelector('#tab-baseimg .card:nth-child(2) .btn-secondary');
    if (btn) btn.classList.add('loading');

    try {
        const result = await apiCall('/api/crypto/base64img', { text, mode: 'd' });

        if (!result.success) {
            outputEl.value = `❌ 操作失败: ${result.error}`;
            showToast('解码失败', 'error');
            return;
        }

        outputEl.value = result.result;
        showToast('解码成功，图片已生成');
    } catch (err) {
        showToast(err.message, 'error');
    } finally {
        if (btn) btn.classList.remove('loading');
    }
}

// ─────────────── ALL Crypto ───────────────

async function cryptoAll(mode) {
    const text = document.getElementById('all_text')?.value;
    if (!text || !text.trim()) {
        showToast('请输入文本内容', 'error');
        return;
    }

    const key = document.getElementById('all_key')?.value || '';
    const iv = document.getElementById('all_iv')?.value || '';
    const cryptoMode = document.getElementById('all_mode')?.value || 'CBC';
    const resultFormat = document.getElementById('all_result')?.value || 'base64';
    const jwtHeader = document.getElementById('all_jwt_header')?.value || '';
    const jwtAlgorithm = document.getElementById('all_jwt_algorithm')?.value || 'HS256';
    const outputEl = document.getElementById('all_output');
    if (!outputEl) return;

    const clickedBtn = mode === 'e'
        ? document.querySelector('#tab-all .btn-primary')
        : document.querySelector('#tab-all .btn-secondary');
    if (clickedBtn) clickedBtn.classList.add('loading');

    try {
        outputEl.value = '⏳ 正在处理...\n';

        const operations = mode === 'e'
            ? ['url', 'unicode', 'hex', 'base16', 'base32', 'base64', 'base85', 'html',
               'md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512', 'des', 'aes', 'jwt', 'time', 'morse', 'runtime']
            : ['url', 'unicode', 'hex', 'base16', 'base32', 'base64', 'base85', 'html',
               'md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512', 'des', 'aes', 'jwt', 'time', 'morse'];

        const results = [];

        for (const op of operations) {
            try {
                let result;
                if (op === 'des' || op === 'aes') {
                    result = await apiCall(`/api/crypto/${op}`, { text, mode, key, iv, crypto_mode: cryptoMode, result: resultFormat });
                } else if (op === 'jwt') {
                    result = mode === 'e'
                        ? await apiCall(`/api/crypto/${op}`, { text, mode, key, algorithm: jwtAlgorithm, header: jwtHeader })
                        : await apiCall(`/api/crypto/${op}`, { text, mode });
                } else {
                    result = await apiCall(`/api/crypto/${op}`, { text, mode });
                }

                const opName = op.toUpperCase();
                if (result.success) {
                    if (op === 'runtime' && mode === 'e' && result.formats) {
                        results.push(`[${opName}]           ${result.result}`);
                        results.push(`[Runtime Bash]      ${result.formats.bash}`);
                        results.push(`[Runtime PowerShell] ${result.formats.powershell}`);
                        results.push(`[Runtime Python]     ${result.formats.python}`);
                        results.push(`[Runtime Perl]       ${result.formats.perl}`);
                    } else if (op === 'hex' && mode === 'e' && result.formats) {
                        results.push(`[HEX (plain)]       ${result.formats.plain}`);
                        results.push(`[HEX (0x)]          ${result.formats['0x']}`);
                        results.push(`[HEX (\\x)]          ${result.formats['x']}`);
                    } else if (op === 'jwt' && mode === 'd' && typeof result.result === 'object') {
                        results.push(`[JWT Header]        ${result.result.header || ''}`);
                        results.push(`[JWT Payload]       ${result.result.payload || ''}`);
                        results.push(`[JWT Signature]     ${result.result.signature || ''}`);
                    } else {
                        results.push(`[${opName}]           ${result.result}`);
                    }
                } else {
                    results.push(`[${opName}]           ❌ ${result.error}`);
                }
            } catch (err) {
                results.push(`[${op.toUpperCase()}]           ❌ ${err.message}`);
            }
        }

        outputEl.value = results.join('\n');
        showToast(`全部操作完成 (${operations.length} 项)`);
    } catch (err) {
        outputEl.value += `\n❌ 错误: ${err.message}`;
        showToast(err.message, 'error');
    } finally {
        if (clickedBtn) clickedBtn.classList.remove('loading');
    }
}

// ─────────────── HashDB ───────────────

async function initHashDBStats() {
    try {
        const result = await fetch('/api/hashdb/list').then(r => r.json());
        if (result.success && result.stats) {
            Object.entries(result.stats).forEach(([type, stat]) => {
                const item = document.querySelector(`.stat-item[data-type="${type}"] .stat-count`);
                if (item) item.textContent = stat.count;
            });
        }
    } catch { /* ignore */ }
}

async function refreshHashDBStats() {
    const btn = document.querySelector('#tab-hashdb .btn-outline');
    if (btn) btn.classList.add('loading');
    await initHashDBStats();
    if (btn) btn.classList.remove('loading');
    showToast('统计已刷新');
}

async function queryHashDB() {
    const type = document.getElementById('hashdb_query_type')?.value;
    const hashValue = document.getElementById('hashdb_query_value')?.value;
    const outputEl = document.getElementById('hashdb_query_output');

    if (!hashValue || !hashValue.trim()) {
        showToast('请输入 Hash 值', 'error');
        return;
    }

    const btn = document.querySelector('#tab-hashdb .card:nth-child(2) .btn-primary');
    if (btn) btn.classList.add('loading');

    try {
        const result = await apiCall('/api/hashdb/query', { type, hash: hashValue });
        if (!outputEl) return;

        if (!result.success) {
            outputEl.value = `❌ 查询失败: ${result.error}`;
            showToast('未在样本库中找到匹配', 'error');
            return;
        }

        outputEl.value = `✅ 匹配结果: ${result.result}`;
        showToast('查询成功');
    } catch (err) {
        showToast(err.message, 'error');
    } finally {
        if (btn) btn.classList.remove('loading');
    }
}

async function addHashDB() {
    const type = document.getElementById('hashdb_add_type')?.value;
    const plaintext = document.getElementById('hashdb_add_text')?.value;
    const outputEl = document.getElementById('hashdb_add_output');

    if (!plaintext || !plaintext.trim()) {
        showToast('请输入明文', 'error');
        return;
    }

    const btn = document.querySelector('#tab-hashdb .card:nth-child(3) .btn-primary');
    if (btn) btn.classList.add('loading');

    try {
        const result = await apiCall('/api/hashdb/encode', { type, text: plaintext });
        if (!outputEl) return;

        if (!result.success) {
            outputEl.value = `❌ 保存失败: ${result.error}`;
            showToast('保存失败', 'error');
            return;
        }

        outputEl.value = `✅ ${type.toUpperCase()}: ${plaintext} → ${result.result}\n📦 已保存到本地样本库`;
        showToast('已保存到样本库');
        initHashDBStats(); // Refresh stats
    } catch (err) {
        showToast(err.message, 'error');
    } finally {
        if (btn) btn.classList.remove('loading');
    }
}

// ─────────────── File Processing ───────────────

function initFileOperationChange() {
    const opSelect = document.getElementById('file_operation');
    if (opSelect) {
        opSelect.addEventListener('change', () => {
            const paramsDiv = document.getElementById('file_crypto_params');
            const op = opSelect.value;
            if (paramsDiv) {
                paramsDiv.style.display = (op === 'des' || op === 'aes') ? 'block' : 'none';
            }
        });
    }
}

async function processFile() {
    const fileInput = document.getElementById('file_file');
    if (!fileInput.files || !fileInput.files[0]) {
        showToast('请选择文件', 'error');
        return;
    }

    const operation = document.getElementById('file_operation')?.value || 'base64';
    const mode = document.getElementById('file_mode')?.value || 'e';
    const key = document.getElementById('file_key')?.value || '';
    const iv = document.getElementById('file_iv')?.value || '';
    const cryptoMode = document.getElementById('file_crypto_mode')?.value || 'CBC';
    const resultFormat = document.getElementById('file_result')?.value || 'base64';

    const btn = document.querySelector('#tab-file .btn-primary');
    if (btn) {
        btn.classList.add('loading');
        btn.textContent = '⏳ 处理中...';
    }

    try {
        const formData = new FormData();
        formData.append('file', fileInput.files[0]);
        formData.append('operation', operation);
        formData.append('mode', mode);
        formData.append('key', key);
        formData.append('iv', iv);
        formData.append('crypto_mode', cryptoMode);
        formData.append('result', resultFormat);

        const response = await fetch('/api/file/process', {
            method: 'POST',
            body: formData,
        });
        const result = await response.json();

        const container = document.getElementById('file_results_container');
        const countEl = document.getElementById('file_result_count');
        const tbody = document.getElementById('file_results_body');
        if (!container || !countEl || !tbody) return;

        if (!result.success) {
            showToast(`处理失败: ${result.error}`, 'error');
            return;
        }

        container.style.display = 'block';
        countEl.textContent = result.count || 0;

        tbody.innerHTML = result.results.map((r, idx) =>
            `<tr>
                <td>${idx + 1}</td>
                <td title="${escapeHtml(r.input)}">${escapeHtml(r.input)}</td>
                <td title="${escapeHtml(r.output)}">${escapeHtml(r.output)}</td>
            </tr>`
        ).join('');

        showToast(`处理完成 (${result.count} 条)`);
    } catch (err) {
        showToast(err.message, 'error');
    } finally {
        if (btn) {
            btn.classList.remove('loading');
            btn.textContent = '🚀 开始处理';
        }
    }
}

// ─────────────── Utility ───────────────

function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

// ─────────────── Keyboard shortcuts ───────────────

document.addEventListener('keydown', (e) => {
    // Ctrl+Enter on textareas triggers the first primary button
    if (e.ctrlKey && e.key === 'Enter') {
        const activeTab = document.querySelector('.tab-content.active');
        if (activeTab) {
            const primaryBtn = activeTab.querySelector('.btn-primary');
            if (primaryBtn) {
                e.preventDefault();
                primaryBtn.click();
            }
        }
    }
});
