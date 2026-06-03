#!/usr/bin/env python3
"""
HashDB - 本地 Hash 样本库管理工具
支持 MD5 / SHA-1 / SHA-224 / SHA-256 / SHA-384 / SHA-512
"""
import sys, json, os

# config Ga1axy path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
import Ga1axy

def rebuild_hash_db(hash_type='sha256', dic_file='base/dic.txt'):
    """从字典文件重建指定类型的 Hash 样本库"""
    hash_funcs = {
        'md5': Ga1axy.Encode_MD5,
        'sha1': Ga1axy.Encode_sha1,
        'sha224': Ga1axy.Encode_sha224,
        'sha256': Ga1axy.Encode_sha256,
        'sha384': Ga1axy.Encode_sha384,
        'sha512': Ga1axy.Encode_sha512,
    }

    if hash_type not in hash_funcs:
        print(f"\033[31m不支持的 Hash 类型: {hash_type}\033[0m")
        print(f"可用类型: {', '.join(hash_funcs.keys())}")
        return

    lines = Ga1axy.collect_File(dic_file)
    db = {}
    for line in lines:
        text = line.strip()
        if text:
            db[text] = hash_funcs[hash_type](text)

    output_path = f'config/{hash_type}.txt'
    os.makedirs('config', exist_ok=True)
    with open(output_path, 'w') as f:
        json.dump(db, f)

    print(f"\033[32m成功重建 {hash_type.upper()} 样本库: {len(db)} 条\033[0m")
    print(f"\033[36m保存路径: {output_path}\033[0m")


def merge_hash_db(hash_type='sha256', dic_file='base/dic.txt'):
    """从字典文件合并新增条目到指定类型的 Hash 样本库"""
    hash_funcs = {
        'md5': Ga1axy.Encode_MD5,
        'sha1': Ga1axy.Encode_sha1,
        'sha224': Ga1axy.Encode_sha224,
        'sha256': Ga1axy.Encode_sha256,
        'sha384': Ga1axy.Encode_sha384,
        'sha512': Ga1axy.Encode_sha512,
    }

    if hash_type not in hash_funcs:
        print(f"\033[31m不支持的 Hash 类型: {hash_type}\033[0m")
        return

    output_path = f'config/{hash_type}.txt'
    # Load existing if any
    db = {}
    if os.path.exists(output_path):
        with open(output_path, 'r') as f:
            content = f.read()
            if content.strip():
                try:
                    db = json.loads(content)
                except json.JSONDecodeError:
                    # Try to recover multiple JSON objects
                    raw = content
                    depth = 0
                    start = 0
                    for i, ch in enumerate(raw):
                        if ch == '{':
                            if depth == 0:
                                start = i
                            depth += 1
                        elif ch == '}':
                            depth -= 1
                            if depth == 0:
                                try:
                                    obj = json.loads(raw[start:i+1])
                                    db.update(obj)
                                except:
                                    pass
                    print(f"\033[33m从损坏文件中恢复 {len(db)} 条记录\033[0m")

    before = len(db)
    lines = Ga1axy.collect_File(dic_file)
    for line in lines:
        text = line.strip()
        if text:
            db[text] = hash_funcs[hash_type](text)

    with open(output_path, 'w') as f:
        json.dump(db, f)

    added = len(db) - before
    print(f"\033[32m{hash_type.upper()} 样本库: 原有 {before} 条, 新增 {added} 条, 总计 {len(db)} 条\033[0m")


def show_stats():
    """显示所有 Hash 样本库统计"""
    hash_types = ['md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512']
    total = 0
    for ht in hash_types:
        config_file = f'config/{ht}.txt'
        if os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    content = f.read()
                    db = json.loads(content) if content.strip() else {}
                print(f"\033[36m{ht.upper():8s}: {len(db):>6} 条\033[0m")
                total += len(db)
            except:
                print(f"\033[31m{ht.upper():8s}: 文件损坏\033[0m")
        else:
            print(f"\033[33m{ht.upper():8s}: 不存在\033[0m")
    print(f"\033[32m总计: {total} 条记录\033[0m")


def interactive_mode():
    """交互式添加单个条目"""
    print("\033[36mHash 样本库 - 交互添加\033[0m")
    print("可用类型: md5, sha1, sha224, sha256, sha384, sha512")
    hash_type = input("Hash 类型 (默认 sha256): ").strip() or 'sha256'

    hash_funcs = {
        'md5': Ga1axy.Encode_MD5,
        'sha1': Ga1axy.Encode_sha1,
        'sha224': Ga1axy.Encode_sha224,
        'sha256': Ga1axy.Encode_sha256,
        'sha384': Ga1axy.Encode_sha384,
        'sha512': Ga1axy.Encode_sha512,
    }

    if hash_type not in hash_funcs:
        print(f"\033[31m不支持的 Hash 类型: {hash_type}\033[0m")
        return

    plaintext = input("输入明文: ").strip()
    if not plaintext:
        print("\033[31m明文不能为空\033[0m")
        return

    hash_value = hash_funcs[hash_type](plaintext)
    print(f"\033[33m{hash_type.upper()} 值: {hash_value}\033[0m")

    confirm = input("是否保存到本地样本库? (y/n): ").strip().lower()
    if confirm == 'y':
        config_file = f'config/{hash_type}.txt'
        if os.path.exists(config_file):
            with open(config_file, 'r') as f:
                content = f.read()
                db = json.loads(content) if content.strip() else {}
        else:
            db = {}
        db[plaintext] = hash_value
        with open(config_file, 'w') as f:
            json.dump(db, f)
        print(f"\033[32m已保存 ({len(db)} 条)\033[0m")


if __name__ == '__main__':
    if len(sys.argv) == 1:
        # Default: rebuild all + show stats
        for ht in ['md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512']:
            rebuild_hash_db(ht)
        show_stats()
    elif sys.argv[1] == 'stats':
        show_stats()
    elif sys.argv[1] == 'add':
        interactive_mode()
    elif sys.argv[1] in ('rebuild', '--rebuild'):
        hash_type = sys.argv[2] if len(sys.argv) > 2 else 'sha256'
        rebuild_hash_db(hash_type)
    elif sys.argv[1] in ('merge', '--merge'):
        hash_type = sys.argv[2] if len(sys.argv) > 2 else 'sha256'
        merge_hash_db(hash_type)
    else:
        print("用法:")
        print("  python3 HashDB.py              # 重建所有 Hash 样本库")
        print("  python3 HashDB.py stats        # 查看统计")
        print("  python3 HashDB.py add          # 交互式添加")
        print("  python3 HashDB.py rebuild md5  # 重建指定类型")
        print("  python3 HashDB.py merge sha256 # 合并新增条目")
