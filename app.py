from flask import Flask, render_template, redirect, session, flash
from flask_debugtoolbar import DebugToolbarExtension
from models import connect_db, db, User, Feedback
from forms import UserForm, LoginForm, FeedbackForm
from sqlalchemy.exc import IntegrityError, DataError

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql:///auth_demo_2"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ECHO"] = True
app.config["SECRET_KEY"] = "abc123"
app.config['DEBUG_TB_INTERCEPT_REDIRECTS'] = False


connect_db(app)

toolbar = DebugToolbarExtension(app)


@app.route('/')
def home_page():

    return redirect('/register')


@app.route('/register', methods=['GET', 'POST'])
def register_user():
    form = UserForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        email = form.email.data
        first_name = form.first_name.data
        last_name = form.last_name.data

        new_user = User.register(
            username, password, email, first_name, last_name)
        db.session.add(new_user)
        try:
            db.session.commit()
        except DataError:
            form.username.errors.append(
                'Username To Long. Please Pick Another')
            return render_template('register.html', form=form)

        flash('Welcome! Successfully Created Your Account!', 'success')
        return redirect('/secrets')

    return render_template('register.html', form=form)


@app.route('/secrets')
def secrets():
    if 'user_id' not in session:
        flash('Please login', 'login')
        return redirect('/login')
    return 'You Made it!'


@app.route('/login', methods=['GET', 'POST'])
def login_user():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        user = User.authenticate(username, password)
        if user:
            flash(f'Welcome Back! {user.username}', 'primary')
            session['user_id'] = user.id
            return redirect(f'/users/{user.id}')
        else:
            form.username.errors = ['Invalid login']
    return render_template('login.html', form=form)


@app.route('/logout')
def logout_user():
    session.pop('user_id')
    flash('Goodbye!', 'info')
    return redirect('/')


@app.route('/users/<int:id>')
def dislay_user(id):
    if 'user_id' not in session:
        flash('Please login', 'login')
        return redirect('/login')
    # fetch the user from the database using the `id`
    user = User.query.filter_by(id=id).first()

    # render the user profile template
    feedbacks = Feedback.query.all()

    return render_template('user_profile.html', user=user, feedbacks=feedbacks)


@app.route('/users/<int:id>/feedback', methods=['GET', 'POST'])
def add_feedback(id):
    if 'user_id' not in session:
        flash('Please login', 'login')
        return redirect('/login')
    form = FeedbackForm()
    if form.validate_on_submit():
        title = form.title.data
        content = form.content.data

        user_id = session['user_id']
        user = User.query.get(user_id)
        username = user.username

        new_feedback = Feedback(
            title=title, content=content, username=username)
        db.session.add(new_feedback)
        db.session.commit()

        flash('Feedback added successfully!', 'success')
        return redirect(f'/users/{id}')

    return render_template('add_feedback.html', form=form)


@app.route('/users/<int:id>/delete', methods=['POST'])
def delete_user(id):
    """Delete user"""
    if 'user_id' not in session:
        flash('Please login', 'login')
        return redirect('/login')

    user = User.query.get_or_404(id)

    if user.id == session['user_id']:
        # Deleting all the feedback associated with the user.
        Feedback.query.filter_by(username=user.username).delete()

        db.session.delete(user)
        db.session.commit()

        session.pop('user_id', None)
        flash('User deleted!', 'info')
        return redirect('/')
    flash('Do not have the required permission', 'danger')
    return redirect('/')


@app.route('/feedback/<int:id>/edit', methods=['GET', 'POST'])
def edit_feedback(id):
    """Edit existing feedback."""
    if 'user_id' not in session:
        flash('Please login', 'login')
        return redirect('/login')

    feedback = Feedback.query.get_or_404(id)

    if feedback.user.id != session['user_id']:
        flash('You do not have permission to edit this feedback', 'danger')
        return redirect('/')

    form = FeedbackForm(obj=feedback)

    if form.validate_on_submit():
        feedback.title = form.title.data
        feedback.content = form.content.data
        db.session.commit()
        flash('Feedback updated!', 'success')
        return redirect(f'/users/{feedback.user.id}')

    return render_template('edit_feedback.html', form=form, feedback=feedback)


@app.route('/feedback/<int:feedback_id>/delete', methods=['POST'])
def delete_feedback(feedback_id):
    """Delete feedback"""
    if 'user_id' not in session:
        flash('Please login', 'login')
        return redirect('/login')

    feedback = Feedback.query.get_or_404(feedback_id)

    if feedback.user.id == session['user_id']:
        db.session.delete(feedback)
        db.session.commit()
        flash('Feedback deleted!', 'info')
        return redirect(f'/users/{feedback.user.id}')
    flash('Do not have the required permission', 'danger')
    return redirect('/')
