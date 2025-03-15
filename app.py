import os
import sqlite3
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, g, abort, send_from_directory
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from forms import LoginForm, QuestionForm, AnswerForm

# 应用配置
app = Flask(__name__)
app.config['SECRET_KEY'] = 'dev'
app.config['DATABASE'] = os.path.join(app.root_path, 'askbox.db')
app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB 最大上传限制
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif', 'mp3', 'wav', 'pdf', 'doc', 'docx'}

# 确保上传目录存在
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# 登录管理
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# 数据库连接
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(
            app.config['DATABASE'],
            detect_types=sqlite3.PARSE_DECLTYPES
        )
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()

# 用户模型
class User(UserMixin):
    def __init__(self, id, username, password_hash):
        self.id = id
        self.username = username
        self.password_hash = password_hash

@login_manager.user_loader
def load_user(user_id):
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    if user is None:
        return None
    return User(user['id'], user['username'], user['password'])

# 辅助函数
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# 添加上下文处理器，为所有模板提供当前时间
@app.context_processor
def inject_now():
    return {'now': datetime.now()}

# 路由
@app.route('/')
def index():
    page = request.args.get('page', 1, type=int)
    per_page = 20
    offset = (page - 1) * per_page
    
    db = get_db()
    total = db.execute('SELECT COUNT(*) FROM questions WHERE answered = 1').fetchone()[0]
    questions = db.execute(
        'SELECT q.id, q.content, q.created, q.answered, a.content as answer_content '
        'FROM questions q LEFT JOIN answers a ON q.id = a.question_id '
        'WHERE q.answered = 1 ORDER BY q.created DESC LIMIT ? OFFSET ?',
        (per_page, offset)
    ).fetchall()
    
    total_pages = (total + per_page - 1) // per_page
    
    return render_template('index.html', 
                           questions=questions, 
                           page=page, 
                           total_pages=total_pages,
                           total=total)

@app.route('/ask', methods=['GET', 'POST'])
def ask():
    form = QuestionForm()
    if form.validate_on_submit():
        content = form.content.data
        db = get_db()
        db.execute(
            'INSERT INTO questions (content, created, answered) VALUES (?, ?, ?)',
            (content, datetime.now(), 0)
        )
        db.commit()
        flash('您的问题已提交，等待回答。', 'success')
        return redirect(url_for('index'))
    return render_template('ask.html', form=form)

@app.route('/question/<int:question_id>')
def question_detail(question_id):
    db = get_db()
    question = db.execute(
        'SELECT q.*, a.content as answer_content, a.attachment as answer_attachment, '
        'a.attachment_type as answer_attachment_type '
        'FROM questions q LEFT JOIN answers a ON q.id = a.question_id '
        'WHERE q.id = ?', (question_id,)
    ).fetchone()
    
    if question is None or not question['answered']:
        abort(404)
        
    return render_template('question_detail.html', question=question)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('admin_dashboard'))
    
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        
        if user and check_password_hash(user['password'], password):
            user_obj = User(user['id'], user['username'], user['password'])
            login_user(user_obj)
            next_page = request.args.get('next')
            return redirect(next_page or url_for('admin_dashboard'))
        
        flash('用户名或密码错误', 'danger')
    
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/admin')
@login_required
def admin_dashboard():
    db = get_db()
    unanswered = db.execute(
        'SELECT * FROM questions WHERE answered = 0 ORDER BY created DESC'
    ).fetchall()
    answered = db.execute(
        'SELECT q.*, a.content as answer_content FROM questions q '
        'LEFT JOIN answers a ON q.id = a.question_id '
        'WHERE q.answered = 1 ORDER BY q.created DESC'
    ).fetchall()
    
    return render_template('admin/dashboard.html', 
                           unanswered=unanswered, 
                           answered=answered)

@app.route('/admin/answer/<int:question_id>', methods=['GET', 'POST'])
@login_required
def answer_question(question_id):
    db = get_db()
    question = db.execute('SELECT * FROM questions WHERE id = ?', (question_id,)).fetchone()
    
    if question is None:
        abort(404)
    
    # 检查是否已有回答
    existing_answer = None
    if question['answered']:
        existing_answer = db.execute(
            'SELECT * FROM answers WHERE question_id = ?', (question_id,)
        ).fetchone()
    
    form = AnswerForm()
    if form.validate_on_submit():
        content = form.content.data
        attachment = form.attachment.data
        attachment_path = None
        attachment_type = None
        
        if attachment and allowed_file(attachment.filename):
            filename = secure_filename(attachment.filename)
            file_ext = filename.rsplit('.', 1)[1].lower()
            saved_filename = f"{question_id}_{datetime.now().strftime('%Y%m%d%H%M%S')}.{file_ext}"
            attachment_path = saved_filename
            attachment.save(os.path.join(app.config['UPLOAD_FOLDER'], saved_filename))
            
            # 确定附件类型
            if file_ext in ['jpg', 'jpeg', 'png', 'gif']:
                attachment_type = 'image'
            elif file_ext in ['mp3', 'wav']:
                attachment_type = 'audio'
            elif file_ext in ['pdf']:
                attachment_type = 'pdf'
            elif file_ext in ['doc', 'docx']:
                attachment_type = 'document'
            else:
                attachment_type = 'file'
        
        if existing_answer:
            # 更新现有回答
            db.execute(
                'UPDATE answers SET content = ?, attachment = ?, attachment_type = ? '
                'WHERE question_id = ?',
                (content, attachment_path, attachment_type, question_id)
            )
        else:
            # 创建新回答
            db.execute(
                'INSERT INTO answers (question_id, content, attachment, attachment_type, created) '
                'VALUES (?, ?, ?, ?, ?)',
                (question_id, content, attachment_path, attachment_type, datetime.now())
            )
            # 更新问题状态为已回答
            db.execute(
                'UPDATE questions SET answered = 1 WHERE id = ?', (question_id,)
            )
        
        db.commit()
        flash('回答已保存', 'success')
        return redirect(url_for('admin_dashboard'))
    
    # 如果是编辑现有回答，预填表单
    if existing_answer:
        form.content.data = existing_answer['content']
    
    return render_template('admin/answer.html', question=question, form=form, existing_answer=existing_answer)

@app.route('/admin/delete_question/<int:question_id>', methods=['POST'])
@login_required
def delete_question(question_id):
    db = get_db()
    
    # 检查是否有附件需要删除
    answer = db.execute('SELECT * FROM answers WHERE question_id = ?', (question_id,)).fetchone()
    if answer and answer['attachment']:
        try:
            os.remove(os.path.join(app.config['UPLOAD_FOLDER'], answer['attachment']))
        except OSError:
            pass  # 文件可能不存在，忽略错误
    
    # 删除回答和问题
    db.execute('DELETE FROM answers WHERE question_id = ?', (question_id,))
    db.execute('DELETE FROM questions WHERE id = ?', (question_id,))
    db.commit()
    
    flash('问题已删除', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

if __name__ == '__main__':
    app.run(debug=True)