from flask import Flask, render_template, request, flash, redirect, url_for, session, send_from_directory, abort
from werkzeug.utils import secure_filename
from forms import RegistrationForm, LoginForm, FirstProfileForm, LoveHateForm, AboutMeForm
from flask_bootstrap import Bootstrap5
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import update, delete
from sqlalchemy.orm import relationship, DeclarativeBase, Mapped, mapped_column
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user, login_required
from sqlalchemy import Integer, String, Text
from flask_ckeditor import CKEditor
from werkzeug.utils import secure_filename
from functools import wraps
from typing import List
import os
import uuid
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv("FLASK_KEY")
UPLOAD_FOLDER = os.getenv("UPLOAD_FOLDER")
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}
ckeditor = CKEditor(app)
bootstrap = Bootstrap5(app)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


class Base(DeclarativeBase):
    pass


app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DB_URI", "sqlite:///Singles.db")
db = SQLAlchemy(model_class=Base)
db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(500), unique=True, nullable=False)
    age: Mapped[int] = mapped_column(Integer, nullable=True)
    password: Mapped[str] = mapped_column(String(100), nullable=False)
    mobile: Mapped[int] = mapped_column(Integer, unique=True)
    mail: Mapped[str] = mapped_column(String(200), unique=True, nullable=False)
    gender: Mapped[str] = mapped_column(String(100), unique=False, nullable=True)
    interested_in: Mapped[str] = mapped_column(String(200), unique=False, nullable=True)
    pp_path: Mapped[str] = mapped_column(String(1000), unique=True, nullable=True)
    tags: Mapped[List["Tag"]] = relationship("Tag", back_populates="user")
    about: Mapped[str] = mapped_column(String(1500), unique=False, nullable=True)


class Tag(db.Model):
    __tablename__ = "tags"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(Integer, db.ForeignKey("users.id"))
    tag: Mapped[str] = mapped_column(String(100), unique=False, nullable=False)
    tag_value: Mapped[str] = mapped_column(String(250), unique=False, nullable=False)
    user: Mapped["User"] = relationship("User", back_populates="tags")


with app.app_context():
    db.create_all()


def verify_user(function):
    @wraps(function)
    def wrapper_function(*args, **kwargs):
        if 'name' not in session:
            return abort(403)
        return function(*args, **kwargs)

    return wrapper_function


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/login", methods=["POST", "GET"])
def login():
    new_form = LoginForm()
    if new_form.validate_on_submit():
        result = db.session.execute(db.select(User).where(User.mail == new_form.email.data))
        user = result.scalar_one_or_none()
        if user:
            if check_password_hash(user.password, new_form.password.data):
                session['name'] = user.name
                login_user(user)
                return redirect(url_for('profile', username=user.name))
            else:
                flash("Password incorrect. Please try again")
                return redirect(url_for('login'))
        else:
            flash("This email does not exist. Please try again.")
            return redirect(url_for('login'))

    return render_template("login.html", form=new_form)


@app.route("/register", methods=["POST", "GET"])
def register():
    new_form = RegistrationForm()
    if new_form.validate_on_submit():
        result = db.session.execute(db.select(User).where(User.mail == new_form.email.data))
        user = result.scalar_one_or_none()
        if user is None:
            new_user = User(
                name=new_form.name.data,
                password=generate_password_hash(new_form.password.data, "pbkdf2:sha256", salt_length=8),
                mobile=new_form.mobile.data,
                mail=new_form.email.data,
            )
            db.session.add(new_user)
            db.session.commit()
            session['name'] = new_form.name.data
            return redirect(url_for('complete_profile1', username=new_user.name))
        else:
            flash("You have already signed up with that email, login instead")
            return redirect(url_for('login'))

    return render_template("register.html", form=new_form)


@app.route("/complete1/<username>", methods=["POST", "GET"])
@verify_user
def complete_profile1(username):
    new_form = FirstProfileForm()
    result = db.session.execute(db.select(User).where(User.name == username))
    user = result.scalar_one_or_none()
    if user:
        if request.method == "GET":
            # Pre-fill the form with existing data
            new_form.age.data = user.age
            new_form.gender.data = user.gender
            new_form.interested_in.data = user.interested_in

        if new_form.validate_on_submit():
            age = new_form.age.data
            gender = new_form.gender.data
            interested_in = new_form.interested_in.data

            print(f"Age: {age}, Gender: {gender}, Interested In: {interested_in}")
            #  push to db
            stmt = (update(User).where(User.name == username).values(age=age, gender=gender,
                                                                     interested_in=interested_in))
            db.session.execute(stmt)
            db.session.commit()
            # session['age'] = new_form.age.data
            return redirect(url_for('complete_profile2', username=username))

    return render_template("complete_profile1.html", form=new_form)


@app.route("/complete2/<username>", methods=["POST", "GET"])
@verify_user
def complete_profile2(username):
    result = db.session.execute(db.select(User).where(User.name == username))
    user = result.scalar_one_or_none()
    new_form = LoveHateForm()
    if user:
        if request.method == "GET":
            new_form.love.data = ",".join([item.tag_value for item in user.tags if item.tag == "love"])
            new_form.hate.data = ",".join([item.tag_value for item in user.tags if item.tag == "hate"])

        if new_form.validate_on_submit():
            # push to db
            love_data = new_form.love.data.strip()
            hate_data = new_form.hate.data.strip()
            love_list = love_data.split(",")
            hate_list = hate_data.split(",")
            stmt = (delete(Tag).where(Tag.user_id == user.id))
            db.session.execute(stmt)
            db.session.commit()
            for love in love_list:
                new_tag = Tag(user_id=user.id, tag='love', tag_value=love)
                db.session.add(new_tag)

            for hate in hate_list:
                new_tag = Tag(user_id=user.id, tag='hate', tag_value=hate)
                db.session.add(new_tag)

            db.session.commit()

            # session['love'] = new_form.love.data
            # session['hate'] = new_form.hate.data

            return redirect(url_for('upload_pics', username=username))

    return render_template("complete_profile2.html", form=new_form)


def verify_files(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route("/pic/<username>", methods=["POST", "GET"])
@verify_user
def upload_pics(username):
    new_form = AboutMeForm()
    result = db.session.execute(db.select(User).where(User.name == username))
    user = result.scalar_one_or_none()
    if user:
        if request.method == "GET":
            new_form.about.data = user.about

        if request.method == "POST":
            if new_form.validate_on_submit():
                file = request.files.get('photo')

                if file and file.filename != '':
                    if verify_files(file.filename):
                        unique_filename = str(uuid.uuid4()) + "_" + secure_filename(file.filename)
                        file.save(os.path.join(app.config['UPLOAD_FOLDER'], unique_filename))
                        pp_path = unique_filename
                    else:
                        flash("Invalid file type")
                        return render_template("upload_pic.html", form=new_form, user=user)
                else:
                    pp_path = user.pp_path  # Retain the existing profile picture path

                stmt = (
                    update(User).where(User.name == username).values(
                        pp_path=pp_path, about=new_form.about.data))
                db.session.execute(stmt)
                db.session.commit()
                return redirect(url_for('profile', username=username))
            else:
                return render_template("upload_pic.html", form=new_form, user=user)

    return render_template("upload_pic.html", form=new_form, user=user)


@app.route("/profile/<username>", methods=["POST", "GET"])
@verify_user
def profile(username):
    if request.method == "POST":
        action = request.form.get('action')
        if action == 'edit':
            return redirect(url_for('complete_profile1', username=username))
        else:
            return redirect(url_for('swiper', username=username))
    # handle get request
    result = db.session.execute(db.select(User).where(User.name == username))
    user = result.scalar_one_or_none()
    if user:
        file_name = user.pp_path
        text_data = user.about
        name = user.name
        age = user.age
        love_list = [item.tag_value for item in user.tags if item.tag == "love"]
        hate_list = [item.tag_value for item in user.tags if item.tag == "hate"]
        # print(love_list)
        # print(hate_list)
        return render_template("profile.html", file_name=file_name, text_data=text_data, name=name, age=age,
                               love=love_list,
                               hate=hate_list)
    return "User not found", 404


@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


def cupid(user):
    user_is_into = user.interested_in  # into male
    user_gender = user.gender
    user_name = user.name
    potential_matches = []

    # need to modify the query which shows the same user , user!= itself
    if user_gender == "male":
        if user_is_into == "female":  # straight
            print(f"User is into: {user_is_into}, User gender: {user_gender}")
            result = db.session.execute(
                db.select(User).where(
                    (User.gender == "female") & ((User.interested_in == "male") | (User.interested_in == "both"))
                )
            )
            potential_matches = result.scalars().all()

        elif user_is_into == "male":  # gay
            print(f"User is into: {user_is_into}, User gender: {user_gender}")
            result = db.session.execute(
                db.select(User).where(
                    (User.name != user_name) & (User.gender == "male") & (
                            (User.interested_in == "male") | (User.interested_in == "both"))
                )
            )
            potential_matches = result.scalars().all()

        else:  # bi
            print(f"User is into: {user_is_into}, User gender: {user_gender}")
            result = db.session.execute(
                db.select(User).where(
                    (User.name != user_name) & (((User.gender == "female") & (User.interested_in != "female")) |
                                                ((User.gender == "male") & (User.interested_in != "female")))
                )
            )
            potential_matches = result.scalars().all()

    if user_gender == "female":
        if user_is_into == "male":  # straight
            print(f"User is into: {user_is_into}, User gender: {user_gender}")
            result = db.session.execute(
                db.select(User).where(
                    (User.gender == "male") & ((User.interested_in == "female") | (User.interested_in == "both"))
                )
            )
            potential_matches = result.scalars().all()

        elif user_is_into == "female":  # lesbian
            print(f"User is into: {user_is_into}, User gender: {user_gender}")
            result = db.session.execute(
                db.select(User).where(
                    (User.name != user_name) & (User.gender == "female") & (
                            (User.interested_in == "female") | (User.interested_in == "both"))
                )
            )

            potential_matches = result.scalars().all()

        else:  # bi
            print(f"User is into: {user_is_into}, User gender: {user_gender}")
            result = db.session.execute(
                db.select(User).where(
                    (User.name != user_name) & (((User.gender == "male") & (User.interested_in != "male")) |
                                                ((User.gender == "female") & (User.interested_in != "male")))
                )
            )
            potential_matches = result.scalars().all()

    for match in potential_matches:
        print(match.name)
    return potential_matches


@app.route('/swipe/<username>', methods=["POST", "GET"])
@login_required
def swiper(username):
    result = db.session.execute(db.select(User).where(User.name == username))
    user = result.scalar_one_or_none()

    if user:
        targets = cupid(user)
        print(targets)

        if 'target_index' not in session:
            session['target_index'] = 0

        if request.method == "POST":
            action = request.form.get('action')

            if action == "smash":
                session['target_index'] += 1
            else:
                session['target_index'] += 1

            if session['target_index'] >= len(targets):
                session['target_index'] = 0

        current_target = targets[session['target_index']]
        return render_template("swipe.html", target=current_target, username=username)


@app.route('/logout', methods=["POST", "GET"])
def logout():
    logout_user()
    return redirect(url_for('login'))


if __name__ == "__main__":
    app.run(debug=True)
