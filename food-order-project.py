from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'  # Database URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'your_secret_key'  # Change this to a random secret key
db = SQLAlchemy(app)

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)

# Use application context to create tables
with app.app_context():
    db.create_all()  # Create the database and tables

# Home route
@app.route('/')
def home():
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Check if username already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists. Please choose a different one.')
            return redirect(url_for('register'))

        # Hash the password and create a new user
        hashed_password = generate_password_hash(password)  # or use method='pbkdf2:sha256'
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful! You can now log in.')
        return redirect(url_for('home'))

    return render_template('register.html')

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['username'] = username
            flash('Login successful!')
            return redirect(url_for('dashboard'))  # Redirect to a dashboard or homepage
        flash('Invalid username or password.')
        return redirect(url_for('home'))

    return render_template('login.html')

# Dashboard
@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        # Retrieve user-specific data or other relevant information
        # For now, we'll just display a welcome message
        return render_template('dashboard.html', username=session['username'])
    return redirect(url_for('home'))

# Logout route
@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('You have been logged out.')
    return redirect(url_for('home'))

# Run the app
if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=5000)



























#  dummy source code
# from flask import Flask, render_template, request, redirect, url_for, flash, session
# from werkzeug.security import generate_password_hash, check_password_hash

# app = Flask(__name__)
# app.secret_key = 'your_secret_key'  # Change this to a random secret key

# # Simulated user database
# users = {
#     "admin": generate_password_hash("password")  # Example user
# }

# @app.route('/')
# def home():
#     return render_template('login.html')

# @app.route('/login', methods=['POST'])
# def login():
#     username = request.form['username']
#     password = request.form['password']

#     # Check if the user exists
#     if username in users and check_password_hash(users[username], password):
#         session['username'] = username
#         return redirect(url_for('dashboard'))
#     else:
#         flash('Invalid username or password')
#         return redirect(url_for('home'))

# @app.route('/dashboard')
# def dashboard():
#     if 'username' in session:
#         return f'Welcome, {session["username"]}! <br> <a href="/logout">Logout</a>'
#     return redirect(url_for('home'))

# @app.route('/logout')
# def logout():
#     session.pop('username', None)
#     return redirect(url_for('home'))

# if __name__ == '__main__':
#     app.run(debug=True)
