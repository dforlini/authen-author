from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from forms import RegistrationForm, LoginForm  
from models import User, Feedback
from config import Config
from flask_bootstrap import Bootstrap

from dotenv import load_dotenv
load_dotenv()  

app = Flask(__name__)
app.config.from_object(Config)
bootstrap = Bootstrap(app)

# Initialize extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def home():
    return redirect(url_for('register'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('secret'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')  # Hashing and decoding
        user = User(username=form.username.data, email=form.email.data,
                    password_hash=hashed_password,
                    first_name=form.first_name.data, last_name=form.last_name.data)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('secret'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password_hash, form.password.data):  # Checking the hash
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('secret'))
        else:
            flash('Login Unsuccessful. Please check username and password', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/secret')
@login_required
def secret():
    return "You made it!"

@app.route('/users/<username>')
@login_required
def user_profile(username):
    if current_user.username != username:
        flash("You don't have permission to view this page.", 'danger')
        return redirect(url_for('home'))
    user = User.query.filter_by(username=username).first_or_404()
    feedbacks = Feedback.query.filter_by(username=username).all()
    return render_template('user_profile.html', user=user, feedbacks=feedbacks)

@app.route('/users/<username>/delete', methods=['POST'])
@login_required
def delete_user(username):
    if current_user.username != username:
        flash("You don't have permission to perform this action.", 'danger')
        return redirect(url_for('home'))
    user = User.query.filter_by(username=username).first_or_404()
    Feedback.query.filter_by(username=username).delete()
    db.session.delete(user)
    db.session.commit()
    logout_user()
    flash("User and all feedback deleted.", 'success')
    return redirect(url_for('home'))

@app.route('/users/<username>/feedback/add', methods=['GET', 'POST'])
@login_required
def add_feedback(username):
    if current_user.username != username:
        flash("You're not authorized to access this page.", "warning")
        return redirect(url_for('home'))

    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        feedback = Feedback(title=title, content=content, username=username)
        db.session.add(feedback)
        db.session.commit()
        return redirect(url_for('show_user', username=username))
    
    return render_template('add_feedback.html')

@app.route('/feedback/<int:feedback_id>/update', methods=['GET', 'POST'])
@login_required
def update_feedback(feedback_id):
    feedback = Feedback.query.get_or_404(feedback_id)
    if current_user.username != feedback.username:
        flash("You're not authorized to edit this feedback.", "warning")
        return redirect(url_for('home'))

    if request.method == 'POST':
        feedback.title = request.form['title']
        feedback.content = request.form['content']
        db.session.commit()
        return redirect(url_for('show_user', username=current_user.username))
    
    return render_template('edit_feedback.html', feedback=feedback)

@app.route('/feedback/<int:feedback_id>/delete', methods=['POST'])
@login_required
def delete_feedback(feedback_id):
    feedback = Feedback.query.get_or_404(feedback_id)
    if current_user.username != feedback.username:
        flash("You're not authorized to delete this feedback.", "warning")
        return redirect(url_for('home'))

    db.session.delete(feedback)
    db.session.commit()
    return redirect(url_for('show_user', username=current_user.username))



if __name__ == '__main__':
    app.run(debug=True)