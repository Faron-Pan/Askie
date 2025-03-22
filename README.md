<div style="display: flex; align-items: center;">
  <img src="static/logo.svg" alt="问匣LOGO" width="32" height="32" style="margin-right: 10px;">
  <h1 style="margin: 0;">问匣：新一代年轻人匿名社交方式</h1>
</div>


这是一个基于Flask和SQLite的匿名提问系统，允许用户在不登录的情况下提问，管理员可以登录后台进行回答和管理。

## 功能特点

- 匿名提问功能
- 历史问答列表与分页展示
- 问答详情查看
- 管理员后台登录
- 管理员回答、编辑、删除问题功能
- 支持文本、图片、语音、文件等多种回答形式

## 技术栈

- 前端：HTML, CSS, JavaScript
- 后端：Python Flask
- 数据库：SQLite

## 安装与运行

1. 安装依赖：
   ```
   pip install -r requirements.txt
   ```

2. 初始化数据库：
   ```
   python init_db.py
   ```

3. 运行应用：
   ```
   python app.py
   ```

4. 访问应用：
   - 前台：http://localhost:5000
   - 后台：http://localhost:5000/admin

## 默认管理员密码

- 密码：admin123

可以在初次运行后通过后台修改密码。