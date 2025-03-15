import os
import sqlite3
from werkzeug.security import generate_password_hash
from datetime import datetime

# 获取数据库文件路径
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'askbox.db')

# 创建数据库连接
conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

# 创建用户表
cursor.execute('''
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    created TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
)
''')

# 创建问题表
cursor.execute('''
CREATE TABLE IF NOT EXISTS questions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    content TEXT NOT NULL,
    created TIMESTAMP NOT NULL,
    answered INTEGER NOT NULL DEFAULT 0
)
''')

# 创建回答表
cursor.execute('''
CREATE TABLE IF NOT EXISTS answers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    question_id INTEGER NOT NULL,
    content TEXT NOT NULL,
    attachment TEXT,
    attachment_type TEXT,
    created TIMESTAMP NOT NULL,
    FOREIGN KEY (question_id) REFERENCES questions (id)
)
''')

# 检查是否已有管理员账号
cursor.execute('SELECT * FROM users WHERE username = ?', ('admin',))
if not cursor.fetchone():
    # 创建默认管理员账号
    hashed_password = generate_password_hash('admin123', method='sha256')
    cursor.execute(
        'INSERT INTO users (username, password, created) VALUES (?, ?, ?)',
        ('admin', hashed_password, datetime.now())
    )
    print('创建默认管理员账号: admin / admin123')
else:
    print('管理员账号已存在')

# 提交更改并关闭连接
conn.commit()
conn.close()

print('数据库初始化完成')