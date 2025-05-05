from flask import Flask, render_template, request, redirect, url_for, flash, send_file, jsonify, g
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os
import io
from datetime import datetime
from PIL import Image
import uuid

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24).hex()
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///discators.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize database
db = SQLAlchemy(app)

# Initialize login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Database models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    discators = db.relationship('Discator', backref='owner', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Discator(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(36), unique=True, nullable=False)
    name = db.Column(db.String(50), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    views = db.relationship('DiscatorView', backref='discator', lazy=True)
    first_view = db.Column(db.DateTime, nullable=True)
    
    @property
    def view_count(self):
        return len(self.views)

class DiscatorView(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    discator_id = db.Column(db.Integer, db.ForeignKey('discator.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(50), nullable=True)
    user_agent = db.Column(db.String(255), nullable=True)

# User loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('register'))
        
        user = User(username=username)
        user.set_password(password)
        
        db.session.add(user)
        db.session.commit()
        
        flash('Account created successfully')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        
        if not user or not user.check_password(password):
            flash('Invalid username or password')
            return redirect(url_for('login'))
        
        login_user(user)
        return redirect(url_for('dashboard'))
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', discators=current_user.discators)

@app.route('/create-discator', methods=['POST'])
@login_required
def create_discator():
    discator_name = request.form['name']
    discator_uuid = uuid.uuid4().hex
    
    discator = Discator(
        uuid=discator_uuid,
        name=discator_name,
        user_id=current_user.id
    )
    
    db.session.add(discator)
    db.session.commit()
    
    flash(f'Discator "{discator_name}" created successfully')
    return redirect(url_for('dashboard'))

@app.route('/discator/<uuid>')
def serve_discator(uuid):
    discator = Discator.query.filter_by(uuid=uuid).first_or_404()
    
    # Record this view
    view = DiscatorView(
        discator_id=discator.id,
        ip_address=request.remote_addr,
        user_agent=request.user_agent.string
    )
    db.session.add(view)
    
    # Set first view time if this is the first time
    if not discator.first_view:
        discator.first_view = datetime.utcnow()
    
    db.session.commit()
    
    # Create a transparent 1x1 pixel image
    img = Image.new('RGBA', (1, 1), (0, 0, 0, 0))
    img_io = io.BytesIO()
    img.save(img_io, 'PNG')
    img_io.seek(0)
    
    return send_file(img_io, mimetype='image/png')

@app.route('/discator-details/<int:discator_id>')
@login_required
def discator_details(discator_id):
    discator = Discator.query.get_or_404(discator_id)
    
    # Make sure the current user owns this discator
    if discator.user_id != current_user.id:
        flash('You do not have permission to view this discator')
        return redirect(url_for('dashboard'))
    
    views_data = [{"timestamp": view.timestamp, "user_agent": view.user_agent} for view in discator.views]
    
    return render_template('discator_details.html', discator=discator, views=views_data)

@app.route('/api/discator-stats/<int:discator_id>')
@login_required
def discator_stats(discator_id):
    discator = Discator.query.get_or_404(discator_id)
    
    # Make sure the current user owns this discator
    if discator.user_id != current_user.id:
        return jsonify({"error": "Unauthorized"}), 403
    
    views = [{"timestamp": view.timestamp.isoformat(), "user_agent": view.user_agent} for view in discator.views]
    
    return jsonify({
        "name": discator.name,
        "uuid": discator.uuid,
        "created_at": discator.created_at.isoformat(),
        "first_view": discator.first_view.isoformat() if discator.first_view else None,
        "view_count": discator.view_count,
        "views": views
    })

# Initialize database if it doesn't exist
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)