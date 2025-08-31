from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.fields.simple import EmailField, PasswordField
from wtforms.validators import DataRequired, URL, Length, Email
from flask_ckeditor import CKEditorField


# WTForm for creating a blog post
class CreatePostForm(FlaskForm):
    title = StringField("Blog Gönderi Başlık", validators=[DataRequired()])
    subtitle = StringField("Alt Başlık", validators=[DataRequired()])
    img_url = StringField("Blog Resim URL", validators=[DataRequired(), URL()])
    body = CKEditorField("Blog İçerik", validators=[DataRequired()])
    submit = SubmitField("Gönderiyi Gönder")


# TODO: Create a RegisterForm to register new users
class RegisterForm(FlaskForm):
    name=StringField(label="İsim",validators=[DataRequired()])
    email=EmailField(label="Email",validators=[DataRequired(),Email()])
    password=PasswordField(label="Şifre",validators=[DataRequired()])
    sign_up=SubmitField(label="KAYIT OL!")

# TODO: Create a LoginForm to login existing users
class LoginForm(FlaskForm):
    email=EmailField(label="Email",validators=[DataRequired(),Email()])
    password=PasswordField(label="Şifre",validators=[DataRequired()])
    login=SubmitField(label="GİRİŞ YAP")

# TODO: Create a CommentForm so users can leave comments below posts
class CommentForm(FlaskForm):
    comment_text=CKEditorField(label="Yorum",validators=[DataRequired()])
    submit=SubmitField(label="Yorumu Gönder")