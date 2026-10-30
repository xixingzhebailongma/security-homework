"""
初始化数据库：创建 users / posts 两张表，并内置一个测试用户 alice。

    密码以 bcrypt cost=12 哈希后落库，数据库里不出现明文密码。
"""
import sqlite3

import bcrypt


def init_db(db_path: str = "app.db") -> None:
    conn = sqlite3.connect(db_path)

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            author_id INTEGER NOT NULL,
            FOREIGN KEY (author_id) REFERENCES users(id)
        )
        """
    )

    # 测试用户 alice / Alice#2026!（哈希后存储，原文不落库）
    hashed = bcrypt.hashpw(b"Alice#2026!", bcrypt.gensalt(rounds=12))
    conn.execute(
        "INSERT OR IGNORE INTO users (username, password_hash) VALUES (?, ?)",
        ("alice", hashed.decode()),
    )
    conn.commit()
    conn.close()
    print(f"[+] 数据库 {db_path} 初始化完成，测试用户：alice / Alice#2026!")


if __name__ == "__main__":
    init_db()
