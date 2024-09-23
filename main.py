from datetime import date
from flask import Flask, abort, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
# from flask_gravatar import Gravatar
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user, login_required
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship, DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String, Text, ForeignKey
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from forms import *
from forms import CreatePostForm


'''
Make sure the required packages are installed: 
Open the Terminal in PyCharm (bottom left). 

On Windows type:
python -m pip install -r requirements.txt

On MacOS type:
pip3 install -r requirements.txt

This will install the packages from the requirements.txt for this project.
'''

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap5(app)


#  !!!!!!!HAVE TO DOWNGRADE FLASK FOR GRAVATAR TO WORK!!!!!!!!!!!!!!
# gravatar = Gravatar(app,
#                     size=100,
#                     rating='g',
#                     default='retro',
#                     force_default=False,
#                     force_lower=False,
#                     use_ssl=False,
#                     base_url=None)



# CREATE DATABASE
class Base(DeclarativeBase):
    pass
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///posts.db'
db = SQLAlchemy(model_class=Base)
login_manager = LoginManager()
login_manager.init_app(app)
db.init_app(app)



def salt_hash(password):
    """
    Hashes a password for storing.

    Uses the pbkdf2:sha256 hashing algorithm with a salt length of 8.

    :param password: The password to hash.
    :return: The hashed password.
    """
    
    hashed_password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)
    return hashed_password



@login_manager.user_loader
def load_user(user_id):
    """
    Loads a user object given an ID.

    This function is used by Flask-Login to load a user object given an ID.  If
    the user does not exist, None is returned.

    :param user_id: The ID of the user to load.
    :return: The user object, or None if the user does not exist.
    """
    
    with app.app_context():
        try:
            user =  db.get_or_404(User, user_id)
        except:
            return None
        else:
            return user
        
    
        
# CONFIGURE TABLES
class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    subtitle: Mapped[str] = mapped_column(String(250), nullable=False)
    date: Mapped[str] = mapped_column(String(250), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    img_url: Mapped[str] = mapped_column(String(250), nullable=False)
    author: Mapped["User"] = relationship("User", back_populates="blog_posts")
    author_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), nullable=False)
    comments : Mapped[list["Comment"]] = relationship("Comment", back_populates="post")
   
   
    
class User(db.Model, UserMixin):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name : Mapped[str] = mapped_column(String(250), nullable=False)
    email : Mapped[str] = mapped_column(String(250), nullable=False, unique=True)
    password : Mapped[str] = mapped_column(String(250), nullable=False)
    blog_posts : Mapped[list["BlogPost"]] = relationship("BlogPost", back_populates="author")
    comments : Mapped[list["Comment"]] = relationship("Comment", back_populates="author")


class Comment(db.Model):
    __tablename__ = "comments"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    text : Mapped[str] = mapped_column(String(250), nullable=False)
    author: Mapped["User"] = relationship("User", back_populates="comments")
    author_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), nullable=False)
    post: Mapped["BlogPost"] = relationship("BlogPost", back_populates="comments")
    post_id: Mapped[int] = mapped_column(Integer, ForeignKey("blog_posts.id"), nullable=False)



with app.app_context():
    db.create_all()



def admin_only(func):
    """
    Decorator that checks if a user is an admin before allowing them to access a route.

    If the user is not an admin, a 403 error is raised.

    :param func: The route to be decorated.
    :return: A decorated version of the route.
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        if current_user.id == 1:
            return func(*args, **kwargs)
        else:
            return abort(403)
    return wrapper



@app.route('/register', methods = ['GET', 'POST'])
def register():
    """
    Handle a user registration request.

    If the request is a POST, check if the email already exists in the database.
    If it does, flash an error message and redirect to the login page.
    If not, create a new User with the given name, email, and hashed password,
    and add them to the database.

    If the request is a GET, render the registration form.

    :return: The rendered HTML page.
    """
    register_form = RegisterForm()
    values = [register_form.name.data, register_form.email.data, register_form.password.data]
    if request.method == "POST":
        with app.app_context():
            existing_user = db.session.query(User).filter_by(email=values[1]).first()
            if existing_user:
                flash("You've already signed up with that email, log in instead!")
                redirect(url_for('login'))
            else:
                new_user = User(
                    name = values[0],
                    email = values[1],
                    password = salt_hash(values[2])
                )
                db.session.add(new_user)
                db.session.commit()
                flash("Login", "success")
                return redirect(url_for('login'))
    return render_template("register.html", form=register_form, values=values)




@app.route('/login', methods = ['GET', 'POST'])
def login():
    """
    Handle a user login request.

    If the request is a POST, check if the given email is in the database.
    If it is, check if the given password matches the stored password hash.
    If both conditions are met, log in the user and redirect to the homepage.
    If either condition is not met, flash an error message and redirect to
    the login page.

    If the request is a GET, render the login form.

    :return: The rendered HTML page.
    """
    
    login_form = LoginForm()
    values = [login_form.email.data, login_form.password.data]
    if request.method == "POST":
        if values[0] and values[1]:
            with app.app_context():
                user = db.session.query(User).filter_by(email=values[0]).first()
                if user:
                    if check_password_hash(user.password, values[1]):
                        login_user(user)
                        print("Login works!")
                        return redirect(url_for('get_all_posts'))
                    else:
                        flash("Password incorrect, please try again.", "error")
                        return redirect(url_for('login'))
                else:
                    flash("That email does not exist, please try again.", "error")
                    return redirect(url_for('login'))
    return render_template("login.html", form=login_form, values=values)




@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))




@app.route('/')
def get_all_posts():
    if current_user.is_authenticated:
        print("True")
    else:
        print("False")
    result = db.session.execute(db.select(BlogPost))
    posts = result.scalars().all()
    return render_template("index.html", all_posts=posts)




@app.route("/post/<int:post_id>", methods=["GET", "POST"])
@login_required
def show_post(post_id):
    comment_form = CommentForm()
    requested_post = db.get_or_404(BlogPost, post_id)
    with app.app_context():
        if request.method == "POST":
            if comment_form.validate_on_submit():
                comment = Comment(
                    text=comment_form.body.data,
                    author_id=current_user.id,
                    author=current_user,
                    post=db.get_or_404(BlogPost, post_id),
                    post_id=post_id
                )
                db.session.add(comment)
                db.session.commit()
                return redirect(url_for('show_post', post_id=post_id))
        
        result = db.session.execute(db.select(Comment).filter_by(post_id=post_id))
        comments = result.scalars().all()
        final_list = [
            {
                "text": comment.text,
                "author": comment.author.name
            }
            for comment in comments
        ]
    return render_template("post.html", post=requested_post, form=comment_form, comments=final_list)




@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    """
    Allow admin users to create a new blog post.

    If the request is a POST, validate the form data. If the form is valid,
    create a new BlogPost with the given title, subtitle, body, image URL,
    the current user as the author, and today's date. Add the new post to
    the database and commit the changes. Redirect to the page showing all
    blog posts.

    If the request is a GET, render the form to create a new blog post.
    """
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)




@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    """
    Allow admin users to edit an existing blog post.

    If the request is a POST, validate the form data. If the form is valid,
    update the post with the given title, subtitle, body, image URL, the
    current user as the author, and the current date. Commit the changes
    to the database and redirect to the page showing the post.

    If the request is a GET, render the form to edit a blog post.
    """
    post = db.get_or_404(BlogPost, post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author.name,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author.name = post.author.name
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form, is_edit=True)




@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    """
    Allow admin users to delete an existing blog post.

    If the request is valid, retrieve the post with the given ID from the
    database, delete it, commit the changes, and redirect to the page
    showing all blog posts.
    """
    post_to_delete = db.get_or_404(BlogPost, post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))




@app.route("/about")
def about():
    return render_template("about.html")




@app.route("/contact")
def contact():
    return render_template("contact.html")




if __name__ == "__main__":
    app.run(debug=True, port=5002)
