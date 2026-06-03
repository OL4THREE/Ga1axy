#!/usr/bin/env python3
"""
Ga1axy Web Interface - 多功能加解密工具 Web 版本
"""
import os
import sys
import json
import traceback
from flask import Flask, request, jsonify, render_template, send_file
from werkzeug.utils import secure_filename
import Ga1axy as gx

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max
ALLOWED_EXTENSIONS = {'txt', 'png', 'jpg', 'jpeg', 'gif', 'bmp', 'webp'}

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# ────────────────────────── 工具函数 ──────────────────────────

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def strip_ansi(text):
    """Remove ANSI color codes from CLI output for web display."""
    import re
    return re.sub(r'\033\[[0-9;]*m', '', str(text))


def safe_call(func, *args, **kwargs):
    """Call a Ga1axy function and return structured result."""
    try:
        result = func(*args, **kwargs)
        if isinstance(result, str):
            cleaned = strip_ansi(result)
            if '失败' in cleaned:
                return {'success': False, 'error': cleaned}
            return {'success': True, 'result': cleaned}
        return {'success': True, 'result': str(result)}
    except Exception as e:
        return {'success': False, 'error': str(e)}


# ────────────────────────── 静态页面路由 ──────────────────────────

@app.route('/')
def index():
    return render_template('index.html')

# ────────────────────────── API 路由 ──────────────────────────

# --- 通用加解密操作 ---

OPERATIONS = {
    'url':      (gx.Encode_Url,      gx.Decode_Url),
    'unicode':  (gx.Encode_Unicode,  gx.Decode_Unicode),
    'hex':      (gx.Encode_Hex,      gx.Decode_Hex),
    'base16':   (gx.Encode_Base16,   gx.Decode_Base16),
    'base32':   (gx.Encode_Base32,   gx.Decode_Base32),
    'base64':   (gx.Encode_Base64,   gx.Decode_Base64),
    'base85':   (gx.Encode_Base85,   gx.Decode_Base85),
    'html':     (gx.Encode_Html,     gx.Decode_Html),
    'time':     (gx.Encode_Time,     gx.Decode_Time),
    'morse':    (gx.Encode_Morse,    gx.Decode_Morse),
    'md5':      (gx.Encode_MD5,      gx.Decode_MD5),
    'sha1':     (gx.Encode_sha1,     gx.Decode_sha1),
    'sha224':   (gx.Encode_sha224,   gx.Decode_sha224),
    'sha256':   (gx.Encode_sha256,   gx.Decode_sha256),
    'sha384':   (gx.Encode_sha384,   gx.Decode_sha384),
    'sha512':   (gx.Encode_sha512,   gx.Decode_sha512),
    'runtime':  (gx.Encode_Runtime,  gx.Decode_Runtime),
}

# These operations have special handling defined in their route functions
SPECIAL_OPS = {'des', 'aes', 'jwt', 'base64img', 'base', 'file'}


@app.route('/api/crypto/<operation>', methods=['POST'])
def api_crypto(operation):
    """
    Generic crypto endpoint.
    JSON body: { "text": "...", "mode": "e"|"d", "key": "...", "iv": "...", "mode_detail": "...", "result": "...", "algorithm": "..." }
    """
    if operation not in OPERATIONS:
        return jsonify({'success': False, 'error': f'未知操作: {operation}'}), 400

    data = request.get_json(force=True) or {}
    text = data.get('text', '')
    mode = data.get('mode', 'e')

    encode_func, decode_func = OPERATIONS[operation]

    # Special handling
    if operation == 'hex':
        if mode == 'e':
            result = safe_call(encode_func, text)
            if result['success']:
                result['result'] = result['result'].replace('%', '')
                # Also provide other formats
                result['formats'] = {
                    'plain': result['result'],
                    '0x': encode_func(text).replace('%', '0x'),
                    'x': encode_func(text).replace('%', '\\x'),
                }
            return jsonify(result)
        else:
            return jsonify(safe_call(decode_func, text))

    if operation == 'url':
        if mode == 'e':
            return jsonify(safe_call(encode_func, text))
        else:
            return jsonify(safe_call(decode_func, text))

    if operation == 'time':
        if mode == 'e':
            return jsonify(safe_call(encode_func, text))
        else:
            return jsonify(safe_call(decode_func, text))

    # Hash operations (MD5, SHA*) — decode uses local hash DB
    if operation in ('md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512'):
        if mode == 'e':
            return jsonify(safe_call(encode_func, text))
        else:
            return jsonify(safe_call(decode_func, text))

    # Runtime
    if operation == 'runtime':
        if mode == 'e':
            result = safe_call(encode_func, text)
            if result['success']:
                b64 = result['result']
                result['formats'] = {
                    'bash': f"bash -c {{echo,{b64}}}|{{base64,-d}}|{{bash,-i}}",
                    'powershell': f"powershell.exe -NonI -W Hidden -NoP -Exec Bypass -Enc {b64}",
                    'python': f"python -c exec('{b64}'.decode('base64'))",
                    'perl': f"perl -MMIME::Base64 -e eval(decode_base64('{b64}'))",
                }
            return jsonify(result)
        else:
            return jsonify(safe_call(decode_func, text))

    if mode == 'e':
        return jsonify(safe_call(encode_func, text))
    else:
        return jsonify(safe_call(decode_func, text))


# --- DES / AES ---

@app.route('/api/crypto/des', methods=['POST'])
def api_des():
    data = request.get_json(force=True) or {}
    text = data.get('text', '')
    mode = data.get('mode', 'e')
    key = data.get('key', '')
    iv = data.get('iv', '')
    crypto_mode = data.get('crypto_mode', 'ECB')
    result_format = data.get('result', 'base64')

    if mode == 'e':
        return jsonify(safe_call(gx.Encode_Des, text, key, iv, crypto_mode, result_format))
    else:
        return jsonify(safe_call(gx.Decode_Des, text, key, iv, crypto_mode, result_format))


@app.route('/api/crypto/aes', methods=['POST'])
def api_aes():
    data = request.get_json(force=True) or {}
    text = data.get('text', '')
    mode = data.get('mode', 'e')
    key = data.get('key', '')
    iv = data.get('iv', '')
    crypto_mode = data.get('crypto_mode', 'ECB')
    result_format = data.get('result', 'base64')

    if mode == 'e':
        return jsonify(safe_call(gx.Encode_AES, text, key, iv, crypto_mode, result_format))
    else:
        return jsonify(safe_call(gx.Decode_AES, text, key, iv, crypto_mode, result_format))


# --- JWT ---

@app.route('/api/crypto/jwt', methods=['POST'])
def api_jwt():
    data = request.get_json(force=True) or {}
    text = data.get('text', '')
    mode = data.get('mode', 'e')
    key = data.get('key', '')
    algorithm = data.get('algorithm', 'HS256')
    header = data.get('header', '')

    if mode == 'e':
        result = safe_call(gx.Encode_JWT, text, key, algorithm, header)
        return jsonify(result)
    else:
        result = safe_call(gx.Decode_JWT, text)
        # Try to parse structured JSON from the result
        if result['success']:
            try:
                parsed = json.loads(result['result'])
                result['result'] = parsed
            except (json.JSONDecodeError, KeyError):
                pass
        return jsonify(result)


# --- Base64 Image ---

def _decode_base64img_json(text_content):
    """Decode base64 text to image and return JSON result."""
    try:
        out_path = 'result/BaseImg.png'
        result_path = gx.Decode_Base64Img(text_content.strip(), out_path)
        cleaned = strip_ansi(str(result_path))
        if '解密失败' in cleaned or '失败' in cleaned:
            return jsonify({'success': False, 'error': '解码失败，请检查 Base64 文本是否有效'}), 400
        return jsonify({'success': True, 'result': f'图片已保存到: {cleaned}', 'file': cleaned, 'filename': 'BaseImg.png'})
    except Exception as e:
        return jsonify({'success': False, 'error': f'解码失败: {str(e)}'}), 500


@app.route('/api/crypto/base64img', methods=['POST'])
def api_base64img():
    """Encode image to base64 text file, or decode base64 text to image."""
    # JSON request (from textarea)
    if request.content_type and 'application/json' in request.content_type:
        data = request.get_json(force=True) or {}
        mode = data.get('mode', 'e')
        if mode == 'd':
            text_content = data.get('text', '')
            if not text_content:
                return jsonify({'success': False, 'error': '请提供 base64 文本内容'}), 400
            return _decode_base64img_json(text_content)
        return jsonify({'success': False, 'error': '编码仅支持文件上传'}), 400

    # Form request (file upload)
    mode = request.form.get('mode', 'e')

    if mode == 'e':
        file = request.files.get('file')
        if not file or not allowed_file(file.filename):
            return jsonify({'success': False, 'error': '请上传有效的图片文件'}), 400
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        try:
            result_text, out_path = gx.Encode_Base64Img(filepath, None)
            with open(out_path, 'r') as f:
                content = f.read()
            os.remove(filepath)
            return jsonify({'success': True, 'result': content, 'file': out_path, 'filename': os.path.basename(out_path)})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500
    else:
        text_content = request.form.get('text', '')
        if not text_content:
            file = request.files.get('file')
            if file:
                text_content = file.read().decode('utf-8')
            else:
                return jsonify({'success': False, 'error': '请提供 base64 文本内容'}), 400

        try:
            out_path = 'result/BaseImg.png'
            result_path = gx.Decode_Base64Img(text_content.strip(), out_path)
            cleaned = strip_ansi(str(result_path))
            if '解密失败' in cleaned or '失败' in cleaned:
                return jsonify({'success': False, 'error': '解码失败，请检查 Base64 文本是否有效'}), 400
            return jsonify({'success': True, 'result': f'图片已保存到: {cleaned}', 'file': cleaned, 'filename': 'BaseImg.png'})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500


# --- 批量文件处理 ---

@app.route('/api/file/process', methods=['POST'])
def api_file_process():
    """Process a file with the given crypto operation."""
    file = request.files.get('file')
    if not file:
        return jsonify({'success': False, 'error': '请上传文件'}), 400

    operation = request.form.get('operation', 'base64')
    mode = request.form.get('mode', 'e')
    key = request.form.get('key', '')
    iv = request.form.get('iv', '')
    crypto_mode = request.form.get('crypto_mode', 'ECB')
    result_format = request.form.get('result', 'base64')

    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)

    try:
        lines = gx.collect_File(filepath)
        results = []
        mode_map = {
            'url': ('url', gx.Encode_Url, gx.Decode_Url),
            'unicode': ('unicode', gx.Encode_Unicode, gx.Decode_Unicode),
            'hex': ('hex', lambda t: gx.Encode_Hex(t).replace('%', ''), gx.Decode_Hex),
            'base16': ('base16', gx.Encode_Base16, gx.Decode_Base16),
            'base32': ('base32', gx.Encode_Base32, gx.Decode_Base32),
            'base64': ('base64', gx.Encode_Base64, gx.Decode_Base64),
            'base85': ('base85', gx.Encode_Base85, gx.Decode_Base85),
            'html': ('html', gx.Encode_Html, gx.Decode_Html),
            'md5': ('md5', gx.Encode_MD5, gx.Decode_MD5),
            'sha1': ('sha1', gx.Encode_sha1, gx.Decode_sha1),
            'sha224': ('sha224', gx.Encode_sha224, gx.Decode_sha224),
            'sha256': ('sha256', gx.Encode_sha256, gx.Decode_sha256),
            'sha384': ('sha384', gx.Encode_sha384, gx.Decode_sha384),
            'sha512': ('sha512', gx.Encode_sha512, gx.Decode_sha512),
            'des': ('des', lambda t: gx.Encode_Des(t, key, iv, crypto_mode, result_format), lambda t: gx.Decode_Des(t, key, iv, crypto_mode, result_format)),
            'aes': ('aes', lambda t: gx.Encode_AES(t, key, iv, crypto_mode, result_format), lambda t: gx.Decode_AES(t, key, iv, crypto_mode, result_format)),
        }

        if operation.lower() not in mode_map:
            return jsonify({'success': False, 'error': f'不支持的操作: {operation}'}), 400

        op_name, enc_func, dec_func = mode_map[operation.lower()]
        func = enc_func if mode == 'e' else dec_func

        for line in lines:
            stripped = line.strip()
            if stripped:
                try:
                    r = func(stripped)
                    results.append({'input': stripped, 'output': strip_ansi(str(r))})
                except Exception as e:
                    results.append({'input': stripped, 'output': f'错误: {str(e)}'})

        out_path = f'result/{op_name}_{mode}.txt'
        gx.Write_File([r['output'] for r in results], out_path)

        return jsonify({
            'success': True,
            'results': results,
            'output_file': out_path,
            'count': len(results)
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if os.path.exists(filepath):
            os.remove(filepath)


# --- HashDB 管理 ---

@app.route('/api/hashdb/query', methods=['POST'])
def api_hashdb_query():
    """查询本地 Hash 样本库"""
    data = request.get_json(force=True) or {}
    hash_type = data.get('type', 'sha256')
    hash_value = data.get('hash', '').strip()

    if not hash_value:
        return jsonify({'success': False, 'error': '请输入 Hash 值'}), 400

    hash_db = {
        'md5': gx.Decode_MD5,
        'sha1': gx.Decode_sha1,
        'sha224': gx.Decode_sha224,
        'sha256': gx.Decode_sha256,
        'sha384': gx.Decode_sha384,
        'sha512': gx.Decode_sha512,
    }

    if hash_type not in hash_db:
        return jsonify({'success': False, 'error': f'不支持的 Hash 类型: {hash_type}'}), 400

    result = safe_call(hash_db[hash_type], hash_value)
    return jsonify(result)


@app.route('/api/hashdb/encode', methods=['POST'])
def api_hashdb_encode():
    """加密并保存到本地 Hash 样本库"""
    data = request.get_json(force=True) or {}
    hash_type = data.get('type', 'sha256')
    plaintext = data.get('text', '').strip()

    if not plaintext:
        return jsonify({'success': False, 'error': '请输入明文'}), 400

    hash_funcs = {
        'md5': gx.Encode_MD5,
        'sha1': gx.Encode_sha1,
        'sha224': gx.Encode_sha224,
        'sha256': gx.Encode_sha256,
        'sha384': gx.Encode_sha384,
        'sha512': gx.Encode_sha512,
    }

    if hash_type not in hash_funcs:
        return jsonify({'success': False, 'error': f'不支持的 Hash 类型: {hash_type}'}), 400

    hash_value = hash_funcs[hash_type](plaintext)
    config_file = f'config/{hash_type}.txt'

    # Append to hash DB
    try:
        import json
        if os.path.exists(config_file):
            with open(config_file, 'r') as f:
                content = f.read()
                db = json.loads(content) if content.strip() else {}
        else:
            db = {}
        db[plaintext] = hash_value
        with open(config_file, 'w') as f:
            json.dump(db, f)
        return jsonify({'success': True, 'result': hash_value, 'stored': True})
    except Exception as e:
        return jsonify({'success': False, 'error': f'保存失败: {str(e)}'}), 500


@app.route('/api/hashdb/list', methods=['GET'])
def api_hashdb_list():
    """列出 Hash 库统计信息"""
    hash_types = ['md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512']
    stats = {}
    for ht in hash_types:
        config_file = f'config/{ht}.txt'
        try:
            if os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    content = f.read()
                    db = json.loads(content) if content.strip() else {}
                stats[ht] = {'count': len(db), 'file': config_file}
            else:
                stats[ht] = {'count': 0, 'file': config_file}
        except:
            stats[ht] = {'count': 0, 'file': config_file}
    return jsonify({'success': True, 'stats': stats})


# --- 文件下载 ---

@app.route('/api/file/download/<path:filename>')
def api_file_download(filename):
    """Download a result file."""
    safe_name = secure_filename(filename)
    path = os.path.join('result', safe_name)
    if os.path.exists(path):
        return send_file(os.path.abspath(path), as_attachment=True)
    return jsonify({'success': False, 'error': '文件不存在'}), 404


# ────────────────────────── 启动 ──────────────────────────

if __name__ == '__main__':
    import socket

    # Find available port
    port = 5000
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(('0.0.0.0', port))
        sock.close()
    except OSError:
        for port in range(5000, 5010):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                sock.bind(('0.0.0.0', port))
                sock.close()
                break
            except OSError:
                continue

    print(f'''
\033[32m
 ╔═══════════════════════════════════════════╗
 ║         Ga1axy Web Interface              ║
 ║         Author: ol4three                  ║
 ║         Version: 2.0                      ║
 ╚═══════════════════════════════════════════╝
\033[0m
\033[36m  ✦ Web 界面启动成功! ✦
  ✦ 访问地址: http://127.0.0.1:{port}
  ✦ 局域网: http://{socket.gethostbyname(socket.gethostname())}:{port}
\033[0m
    ''')
    app.run(host='0.0.0.0', port=port, debug=False)
