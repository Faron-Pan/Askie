from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, PasswordField, FileField, SubmitField
from wtforms.validators import DataRequired, Length

class LoginForm(FlaskForm):
    password = PasswordField('密码', validators=[DataRequired()])
    submit = SubmitField('登录')

class QuestionForm(FlaskForm):
    content = TextAreaField('问题内容', validators=[DataRequired(), Length(min=5, max=500)])
    submit = SubmitField('提交问题')

class AnswerForm(FlaskForm):
    content = TextAreaField('回答内容', validators=[DataRequired()])
    attachment = FileField('附件（可选）')
    submit = SubmitField('提交回答')