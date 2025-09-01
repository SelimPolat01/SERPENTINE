import os
from datetime import date
from flask import Flask, abort, render_template, redirect, url_for, flash,request
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor, CKEditorField
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user, login_required
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship, DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String, Text, ForeignKey, UniqueConstraint
from functools import wraps
from flask_gravatar import Gravatar
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
import forms
from forms import CreatePostForm, LoginForm, CommentForm
from itsdangerous import URLSafeTimedSerializer
from email_validator import validate_email, EmailNotValidError
from babel.dates import format_date
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("FLASK_SECRET_KEY")
ckeditor = CKEditor(app)
Bootstrap5(app)

OWN_EMAIL = os.environ.get("OWN_EMAIL")
OWN_PASSWORD = os.environ.get("OWN_PASSWORD")
GMAIL_API_KEY= os.environ.get("GMAIL_API_KEY")

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = OWN_EMAIL
app.config['MAIL_PASSWORD'] = GMAIL_API_KEY  # Gmail için uygulama şifresi kullan
app.config['MAIL_DEFAULT_SENDER'] = 'your_email@gmail.com'
mail = Mail(app)

s = URLSafeTimedSerializer(app.secret_key)

def generate_confirmation_token(user_dict):
    return s.dumps(user_dict, salt='email-confirm')

def confirm_token(token, expiration=3600):
    try:
        user_dict = s.loads(token, salt='email-confirm', max_age=expiration)
    except:
        return False
    return user_dict

# TODO: Configure Flask-Login
login_manager=LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User,user_id)

# CREATE DATABASE
class Base(DeclarativeBase):
    pass
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DB_URI","sqlite:///blog.db")
db = SQLAlchemy(model_class=Base)
db.init_app(app)

# CONFIGURE TABLES
class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    author_id:Mapped[int]=mapped_column(Integer,db.ForeignKey("blog_users.id"),nullable=False)
    author=relationship("User",back_populates="posts")
    title: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    subtitle: Mapped[str] = mapped_column(String(250), nullable=False)
    date: Mapped[str] = mapped_column(String(250), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    img_url: Mapped[str] = mapped_column(String(250), nullable=False)
    comments = relationship("Comment", back_populates="parent_post",cascade="all, delete-orphan")
    likes = relationship("Like", back_populates="post", cascade="all, delete-orphan")

# TODO: Create a User table for all your registered users.
class User(db.Model,UserMixin):
    __tablename__="blog_users"
    id:Mapped[int]=mapped_column(primary_key=True)
    name:Mapped[str]=mapped_column(String(30),nullable=False)
    email:Mapped[str]=mapped_column(String(50),unique=True,nullable=False)
    email_confirmed: Mapped[bool] = mapped_column(default=False, nullable=False)
    password:Mapped[str]=mapped_column(String(150),nullable=False)
    posts=relationship("BlogPost",back_populates="author")
    comments=relationship("Comment",back_populates="comment_author")
    likes = relationship("Like", back_populates="user", cascade="all, delete")

class Comment(db.Model):
    __tablename__="post_comments"
    id:Mapped[int]=mapped_column(Integer,primary_key=True)
    text:Mapped[str]=mapped_column(String(250),nullable=False)
    author_id:Mapped[int]=mapped_column(Integer,db.ForeignKey("blog_users.id"),nullable=False)
    post_id:Mapped[int]=mapped_column(Integer,db.ForeignKey("blog_posts.id"),nullable=False)
    comment_author=relationship("User",back_populates="comments")
    parent_post=relationship("BlogPost",back_populates="comments")
    likes=relationship("Like",back_populates="comment",cascade="all, delete-orphan")


class Like(db.Model):
    __tablename__ = "post_and_comment_likes"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(Integer, db.ForeignKey("blog_users.id"), nullable=False)
    post_id: Mapped[int] = mapped_column(Integer, db.ForeignKey("blog_posts.id"), nullable=True)
    comment_id: Mapped[int] = mapped_column(Integer, db.ForeignKey("post_comments.id"), nullable=True)

    user = relationship("User", back_populates="likes")
    post = relationship("BlogPost", back_populates="likes")
    comment = relationship("Comment", back_populates="likes")

    __table_args__ = (
        db.UniqueConstraint("user_id", "post_id", name="unique_user_post"),
        db.UniqueConstraint("user_id", "comment_id", name="unique_user_comment"),
    )

with app.app_context():
    db.create_all()

gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

# TODO: Use Werkzeug to hash the user's password when creating a new user.
@app.route('/register',methods=["GET","POST"])
def register():
    register_form=forms.RegisterForm()
    if register_form.validate_on_submit():
        name=register_form.name.data
        email=register_form.email.data
        password=register_form.password.data
        hash_and_salted_password=generate_password_hash(password=password,method="pbkdf2:sha256",salt_length=8)

        try:
            valid = validate_email(email)
            email = valid.email
        except EmailNotValidError as e:
            flash(str(e), 'danger')
            return redirect(url_for('register'))

        if db.session.execute(db.select(User).where(User.email==email)).scalar():
            flash("Zaten bu e-postayla kaydoldunuz, bunun yerine giriş yapın!")
            return redirect(url_for("login"))

        hash_password = generate_password_hash(password, method="pbkdf2:sha256", salt_length=8)
        user_data = {'name': name, 'email': email, 'password': hash_password}
        token = generate_confirmation_token(user_data)
        confirm_url = url_for('confirm_email', token=token, _external=True)
        html = render_template('email_confirmation.html', confirm_url=confirm_url)
        msg = Message("Confirm Your Email", recipients=[email], html=html)
        mail.send(msg)

        flash('Onay e-postası gönderildi. Kaydı tamamlamak için lütfen onaylayın.', 'info')
        return redirect(url_for('login'))
    return render_template("register.html",form=register_form,logged_in=current_user.is_authenticated)


    return s.dumps(user_dict, salt='email-confirm')

def confirm_token(token, expiration=3600):
    try:
        user_dict = s.loads(token, salt='email-confirm', max_age=expiration)
    except:
        return False
    return user_dict

@app.route('/confirm/<token>')
def confirm_email(token):
    user_data = confirm_token(token)
    if not user_data:
        flash("Onay bağlantısı geçersiz veya süresi dolmuş.", "danger")
        return redirect(url_for("register"))

    email = user_data['email']

    # Tekrar kontrol et: zaten kayıtlı mı?
    existing_user = db.session.execute(db.select(User).where(User.email == email)).scalar()
    if existing_user:
        flash("Hesap zaten onaylandı. Lütfen giriş yapın.", "info")
        return redirect(url_for("login"))

    # Yeni kullanıcıyı kaydet
    new_user = User(
        name=user_data['name'],
        email=user_data['email'],
        password=user_data['password'],
        email_confirmed=True  # eğer bu alan hâlâ varsa
    )
    db.session.add(new_user)
    db.session.commit()

    flash("E-postanız doğrulandı ve hesabınız artık aktif. Lütfen giriş yapın.", "success")
    return redirect(url_for("login"))

# TODO: Retrieve a user from the database based on their email. 
@app.route('/login',methods=["GET","POST"])
def login():
    login_form=LoginForm()
    if login_form.validate_on_submit():
        email=login_form.email.data
        password=login_form.password.data
        user=db.session.execute(db.select(User).where(User.email==email)).scalar()
        if not user:
            flash("Bu e-posta mevcut değil. Lütfen kaydolup, tekrar deneyin.")
            return redirect(url_for("login"))
        elif not check_password_hash(user.password,password):
            login_form=LoginForm(email=email)
            flash("Şifre hatalı, lütfen tekrar deneyin.")
            return render_template("login.html",form=login_form)
        else:
            login_user(user)
            return redirect(url_for("get_all_posts"))
    return render_template("login.html",form=login_form,logged_in=current_user.is_authenticated)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/')
def get_all_posts():
    result = db.session.execute(db.select(BlogPost))
    posts = result.scalars().all()
    return render_template("index.html", all_posts=posts,logged_in=current_user.is_authenticated)

# TODO: Allow logged-in users to comment on posts
@app.route("/post/<int:post_id>",methods=["GET","POST"])
def show_post(post_id):
    comment_form=CommentForm()
    requested_post = db.get_or_404(BlogPost, post_id)
    has_liked=False
    if current_user.is_authenticated:
        has_liked = False
        if current_user.is_authenticated:
            like = db.session.execute(
                db.select(Like).where(
                    Like.user_id == current_user.id,
                    Like.post_id == post_id
                )
            ).scalar_one_or_none()
            has_liked = like is not None
    if comment_form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("Yorum yapabilmek için giriş yapmanız veya kayıt olmanız gerekmektedir.")
            return redirect(url_for("login"))
        comment=comment_form.comment_text.data
        new_comment=Comment(text=comment,comment_author=current_user,post_id=post_id)
        db.session.add(new_comment)
        db.session.commit()
        return redirect(url_for("show_post",post_id=post_id))
    return render_template("post.html", post=requested_post,form=comment_form,logged_in=current_user.is_authenticated,has_liked=has_liked)


def admin_only(func):
    @wraps(func)
    def decorated_func(*args,**kwargs):
        if current_user.id!=1:
            return abort(403)
        return func(*args,**kwargs)
    return decorated_func

# TODO: Use a decorator so only an admin user can create a new post
@app.route("/new-post", methods=["GET", "POST"])
@login_required
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=format_date(date.today(), format="d MMMM y", locale="tr_TR")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form,current_user=current_user,logged_in=current_user.is_authenticated)


# TODO: Use a decorator so only an admin user can edit a post
@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@login_required
def edit_post(post_id):
    post = db.get_or_404(BlogPost, post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = current_user
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=edit_form, is_edit=True,current_user=current_user,logged_in=current_user.is_authenticated)


# TODO: Use a decorator so only an admin user can delete a post
@app.route("/delete/<int:post_id>")
@login_required
def delete_post(post_id):
    delete_to_post = db.session.get(BlogPost, post_id)
    db.session.delete(delete_to_post)
    db.session.commit()
    return redirect(url_for("get_all_posts"))

@app.route("/delete-comment/<int:comment_id>")
def delete_comment(comment_id):
    delete_to_comment=db.session.execute(db.select(Comment).where(Comment.id==comment_id)).scalar()
    post_id=delete_to_comment.post_id
    db.session.delete(delete_to_comment)
    db.session.commit()
    return redirect(url_for("show_post",post_id=post_id))

@app.route("/like-post/<int:post_id>")
@login_required
def like_post(post_id):
    # Postun beğenisini kontrol et
    like = db.session.execute(
        db.select(Like).where(
            Like.user_id == current_user.id,
            Like.post_id == post_id,  # Postun beğenisini kontrol et
        )
    ).scalar_one_or_none()

    if like:
        db.session.delete(like)  # Eğer post beğenildiyse, beğeni sil
    else:
        new_like = Like(user_id=current_user.id, post_id=post_id)
        db.session.add(new_like)  # Postun beğenisini ekle

    db.session.commit()
    return redirect(url_for("show_post", post_id=post_id))

@app.route("/like-comment/<int:comment_id>")
@login_required
def like_comment(comment_id):
    comment = db.get_or_404(Comment, comment_id)

    # Yorumun beğenisini kontrol et
    like = db.session.execute(
        db.select(Like).where(
            Like.user_id == current_user.id,
            Like.comment_id == comment_id  # Yorumun beğenisini kontrol et
        )
    ).scalar_one_or_none()

    if like:
        db.session.delete(like)  # Yorum daha önce beğenildiyse, beğeni sil
    else:
        new_like = Like(user_id=current_user.id, comment_id=comment_id)
        db.session.add(new_like)  # Yorumun beğenisini ekle

    db.session.commit()
    return redirect(url_for("show_post", post_id=comment.post_id))

@app.route("/about")
def about():
    return render_template("about.html",logged_in=current_user.is_authenticated)


@app.route("/contact",methods=["GET","POST"])
def contact():
    if request.method=="POST":
        name=request.form.get("name")
        email=request.form.get("email")
        phone=request.form.get("phone")
        message=request.form.get("message")
        send_email(subject="Web Blog Hk.",to=OWN_EMAIL,body=f"Name: {name}\nEmail: {email}\nPhone: {phone}\n{message}")
    return render_template("contact.html",logged_in=current_user.is_authenticated)

@app.route('/send-email')
def send_email(subject,to,body):
    msg = Message(subject=subject,
                  recipients=[to],
                  body=body)
    mail.send(msg)
    return "Email sent!"

@app.route("/profile",methods=["GET","POST"])
def profile():
    return render_template("profile.html",logged_in=current_user.is_authenticated)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port,debug=True)
