from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, TextAreaField, SelectMultipleField, RadioField
from wtforms.validators import DataRequired
from flask_ckeditor import CKEditorField


class RegistrationForm(FlaskForm):
    name = StringField('name', validators=[DataRequired()], render_kw={"class": "form-control fs-4"})
    email = StringField("email", validators=[DataRequired()], render_kw={"class": "form-control fs-4"})
    mobile = StringField("mobile", validators=[DataRequired()], render_kw={"class": "form-control fs-4"})
    password = PasswordField("password", validators=[DataRequired()], render_kw={"class": "form-control fs-4"})
    submit = SubmitField("Sign me up")


class LoginForm(FlaskForm):
    email = StringField("email", validators=[DataRequired()], render_kw={"class": "form-control fs-4"})
    password = PasswordField("password", validators=[DataRequired()], render_kw={"class": "form-control fs-4"})
    submit = SubmitField("Log in")


class FirstProfileForm(FlaskForm):
    age = StringField('Age', validators=[DataRequired()], )
    gender = RadioField(u'Select your gender', choices=[('male', 'Male'), ('female', 'Female'), ])
    interested_in = RadioField(u'Interested in', choices=[('male', 'Male'), ('female', 'Female'), ('both', 'Both')])
    next_page = SubmitField("Continue")


class LoveHateForm(FlaskForm):
    love = TextAreaField('What you love', validators=[DataRequired()])
    hate = TextAreaField('What you hate', validators=[DataRequired()])
    next_page = SubmitField("Continue")


class AboutMeForm(FlaskForm):
    about = CKEditorField("", validators=[DataRequired()])
    finish = SubmitField("Finish")
