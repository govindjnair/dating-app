from flask import Flask, render_template, request, flash, redirect, url_for, session, send_from_directory, abort, \
    jsonify
from werkzeug.utils import secure_filename
from forms import RegistrationForm, LoginForm, FirstProfileForm, LoveHateForm, AboutMeForm
from flask_bootstrap import Bootstrap5
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import update, delete
from sqlalchemy.orm import relationship, DeclarativeBase, Mapped, mapped_column
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, login_user, LoginManager, logout_user, login_required
from sqlalchemy import Integer, String, Text
from flask_ckeditor import CKEditor
from werkzeug.utils import secure_filename
from functools import wraps
from typing import List
import os
import uuid
from dotenv import load_dotenv
from pymongo import MongoClient
from flask_pymongo import PyMongo
from flask_socketio import SocketIO, send, emit, join_room, leave_room
import datetime as dt
from collections import Counter

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv("FLASK_KEY")
UPLOAD_FOLDER = os.getenv("UPLOAD_FOLDER")
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}
ckeditor = CKEditor(app)
bootstrap = Bootstrap5(app)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
socketio = SocketIO(app)

# MongoDB setup
app.config['MONGO_URI'] = os.environ.get("MONGO_DB_URI")
mongo = PyMongo(app)
liked_profiles = mongo.db.liked_profiles  # This accesses the liked_profiles collection within the userLikes database.
chats = mongo.db.chats


# A collection in MongoDB is similar to a table in a relational database like SQLite.


# SQLite setup
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
                new_like = {
                    "user_id": user.id,
                    "liked_users": []
                }
                liked_profiles.insert_one(new_like)
                print(liked_profiles)
                return redirect(url_for('profile', username=username))
            else:
                return render_template("upload_pic.html", form=new_form, user=user)

    return render_template("upload_pic.html", form=new_form, user=user)


@app.route("/profile/<username>", methods=["POST", "GET"])
@verify_user
def profile(username):
    current_user = session.get('name')
    room_code = request.args.get('room_code')
    result = chats.find({"users": {"$in": [username]}}, {"_id": 0, "chats": 1})
    result_list = list(result)
    print(result_list)
    # for item in result_list:
    #     for thing in item['chats']:
    #         if thing['read'] is False and thing['user'] != username:
    #             answer.append(thing['user'])

    answer = [element['user'] for item in result_list for element in item['chats'] if
              element['read'] is False and element['user'] != username]

    total_message_notifications = len(answer)
    print(answer)
    print(total_message_notifications)

    # print(room_code)
    # print(current_user)
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
                               hate=hate_list, current_user=current_user, room_code=room_code,
                               total_message_notifications=total_message_notifications)
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
            # print(f"User is into: {user_is_into}, User gender: {user_gender}")
            result = db.session.execute(
                db.select(User).where(
                    (User.gender == "female") & ((User.interested_in == "male") | (User.interested_in == "both"))
                )
            )
            potential_matches = result.scalars().all()

        elif user_is_into == "male":  # gay
            # print(f"User is into: {user_is_into}, User gender: {user_gender}")
            result = db.session.execute(
                db.select(User).where(
                    (User.name != user_name) & (User.gender == "male") & (
                            (User.interested_in == "male") | (User.interested_in == "both"))
                )
            )
            potential_matches = result.scalars().all()

        else:  # bi
            # print(f"User is into: {user_is_into}, User gender: {user_gender}")
            result = db.session.execute(
                db.select(User).where(
                    (User.name != user_name) & (((User.gender == "female") & (User.interested_in != "female")) |
                                                ((User.gender == "male") & (User.interested_in != "female")))
                )
            )
            potential_matches = result.scalars().all()

    if user_gender == "female":
        if user_is_into == "male":  # straight
            # print(f"User is into: {user_is_into}, User gender: {user_gender}")
            result = db.session.execute(
                db.select(User).where(
                    (User.gender == "male") & ((User.interested_in == "female") | (User.interested_in == "both"))
                )
            )
            potential_matches = result.scalars().all()

        elif user_is_into == "female":  # lesbian
            # print(f"User is into: {user_is_into}, User gender: {user_gender}")
            result = db.session.execute(
                db.select(User).where(
                    (User.name != user_name) & (User.gender == "female") & (
                            (User.interested_in == "female") | (User.interested_in == "both"))
                )
            )

            potential_matches = result.scalars().all()

        else:  # bi
            # print(f"User is into: {user_is_into}, User gender: {user_gender}")
            result = db.session.execute(
                db.select(User).where(
                    (User.name != user_name) & (((User.gender == "male") & (User.interested_in != "male")) |
                                                ((User.gender == "female") & (User.interested_in != "male")))
                )
            )
            potential_matches = result.scalars().all()

    # for match in potential_matches:
    #     print(match.name)

    result = chats.find({"users": {"$in": [user.name]}}, {"_id": 0, "users": 1})
    result_list = (list(result))
    matches = [name for item in result_list for name in item['users'] if name != user.name]
    print(matches)
    for match in potential_matches[:]: # shallow copy
        if match.name in matches:
            print(match.name)
            potential_matches.remove(match)

    return potential_matches


@app.route('/swipe/<username>', methods=["POST", "GET"])
@login_required
def swiper(username):
    result = db.session.execute(db.select(User).where(User.name == username))
    user = result.scalar_one_or_none()
    mutual_match = False
    room_code = None
    if user:
        targets = cupid(user)
        print(targets)

        if 'target_index' not in session:
            print("target_index not in session")
            session['target_index'] = 0
        print("Initial target_index:", session['target_index'])

        if session['target_index'] >= len(targets):
            session['target_index'] = 0
        print("Adjusted target_index:", session['target_index'])

        if request.method == "POST":
            action = request.form.get('action')

            if action == "smash":
                query_filter = {"user_id": user.id}
                update_operation = {"$addToSet": {"liked_users": targets[session['target_index']].id}}
                liked_profiles.update_one(query_filter, update_operation)
                # checking if target user likes back
                likes_back = liked_profiles.find_one({"user_id": targets[session['target_index']].id})
                if user.id in likes_back['liked_users']:
                    mutual_match = True
                    couple = chats.find_one({"users": {"$all": [username, targets[session['target_index']].name]}})
                    if couple:
                        room_code = couple["room_code"]
                    else:
                        room_code = str(uuid.uuid4())
                        potential_couple = {
                            "users": [username, targets[session['target_index']].name],
                            "room_code": room_code,
                            "chats": []
                        }
                        chats.insert_one(potential_couple)
                    print(room_code)
                    # return redirect(url_for('chat'))
            else:
                pass
            session['target_index'] += 1

        if session['target_index'] >= len(targets):
            session['target_index'] = 0

        print("Updated target_index:", session['target_index'])
        current_target = targets[session['target_index']]
        print("Current target:", current_target.name)
        return render_template("swipe.html", target=current_target, username=username, mutual_match=mutual_match,
                               room_code=room_code)


@app.route('/chat/<user>/<room_code>', methods=["POST", "GET"])
@login_required
def chat(room_code, user):
    print(room_code)
    print(user)
    result = chats.find_one({"room_code": room_code}, {"_id": 0, "users": 1})
    target = [item for item in result['users'] if item != user][0]
    print(target)
    return render_template("chat.html", room_code=room_code, user=user, target=target)


@app.route('/logout', methods=["POST", "GET"])
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/chat-list/<user>')
@login_required
def chat_list(user):
    result = chats.find({"users": {"$in": [user]}}, {"_id": 0, "room_code": 1, "users": 1, "chats": 1})
    result_list = list(result)
    print(result_list)
    answer = [element['user'] for item in result_list for element in item['chats'] if
              element['read'] is False and element['user'] != user]
    notifications_per_user = Counter(answer)
    print(notifications_per_user)
    texted_with = [people for item in result_list for people in item['users'] if people != user]
    room_codes = [item['room_code'] for item in result_list]
    user_and_room = dict(zip(texted_with, room_codes))
    print(user_and_room)
    return render_template("chat_list.html", user_and_room=user_and_room, user=user,
                           notifications_per_user=notifications_per_user)


@socketio.on('connect')
def handle_connect():
    print("client connected")


@socketio.on('disconnect')
def handle_disconnect():
    print("client disconnected")


rooms_and_users = {}


@socketio.on('join_room')
def handle_join(data):
    username = data['username']
    room = data['room']
    join_room(room)

    # marking all unread messages to the user as read when user joins the room
    query_filter = {"room_code": room}
    update_operation = {"$set": {"chats.$[elem].read": True}}
    array_filters = [{"elem.user": {"$ne": username}, "elem.read": False}]
    chats.update_many(query_filter, update_operation, array_filters=array_filters)

    if room in rooms_and_users:
        if username not in rooms_and_users[room]:
            rooms_and_users[room].append(username)
    else:
        rooms_and_users[room] = [username]
    print(rooms_and_users)
    messages = get_messages(room)
    emit('loadMessages', messages, to=room)
    # send(username + ' has entered the room.', to=room)
    print(f"{username} has entered the room {room}")


@socketio.on('join_notification_room')
def handle_notification(data):
    username = data['username']
    room = data['room']
    join_room(room)
    print(f"{username} has joined their notification room {room}")


@socketio.on('leave_room')
def handle_leave(data):
    username = data['username']
    room = data['room']
    leave_room(room)
    # send(username + ' has left the room.', to=room)
    if room in rooms_and_users:
        if username in rooms_and_users[room]:
            rooms_and_users[room].remove(username)
    print(rooms_and_users)
    print(f"{username} has left the room {room}")


@socketio.on('message')
def handle_message(data):
    time_now = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    room = data['room']
    message = data['message']
    username = data['user']
    target = data['target']
    query_filter = {"room_code": room}
    if target in rooms_and_users[room]:
        # Adding to DB but need to implement end-to-end encryption.
        update_operation = {
            "$addToSet": {"chats": {"user": username, "time_stamp": time_now, "message": message, "read": True}}}
        to_emit = {'user': username, 'time_stamp': time_now, 'message': message, "read": True}
    else:
        update_operation = {
            "$addToSet": {"chats": {"user": username, "time_stamp": time_now, "message": message, "read": False}}}
        to_emit = {'user': username, 'time_stamp': time_now, 'message': message, "read": False}

    chats.update_one(query_filter, update_operation)
    emit('notification', {'from': username, 'to': target, 'type': 'New message'}, to=target)
    print(f"Notification emitted to {target}")

    print(f"received message {message} from {username} from {room} ")
    # Emitting back the received message to client
    emit('message', to_emit, to=room)


def get_messages(room_code):
    result = chats.find_one({"room_code": room_code}, {"_id": 0, "chats": 1})
    if result:
        return result['chats']
    else:
        return []


if __name__ == "__main__":
    # app.run(debug=True)
    socketio.run(app, debug=True, allow_unsafe_werkzeug=True)
