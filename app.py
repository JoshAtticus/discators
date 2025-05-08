from flask import Flask, render_template, request, redirect, url_for, flash, send_file, jsonify, g, session
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO, emit, join_room
from werkzeug.security import generate_password_hash, check_password_hash
import os
import io
from datetime import datetime, timedelta
from PIL import Image
import uuid

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', os.urandom(24).hex())
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///discators.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize database
db = SQLAlchemy(app)

# Initialize SocketIO
socketio = SocketIO(app, cors_allowed_origins="*")

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
    auto_delete = db.Column(db.Boolean, default=False)
    auto_delete_after = db.Column(db.Integer, default=24)  # Hours after first view
    waiting_for_discord = db.Column(db.Boolean, default=True)  # Flag to track if we're waiting for Discord bot view
    waiting_since = db.Column(db.DateTime, default=datetime.utcnow)  # When we started waiting
    track_type = db.Column(db.String(10), default="server") # "dm" for message sent/read or "server" for message views
    
    @property
    def view_count(self):
        return len(self.views)
    
    @property
    def should_delete(self):
        if not self.auto_delete or not self.first_view:
            return False
            
        hours_since_first_view = (datetime.utcnow() - self.first_view).total_seconds() / 3600
        return hours_since_first_view >= self.auto_delete_after
    
    @property
    def expired_waiting(self):
        """Check if the discator has been waiting for too long (30 minutes)"""
        if not self.waiting_for_discord:
            return False
            
        minutes_waiting = (datetime.utcnow() - self.waiting_since).total_seconds() / 60
        return minutes_waiting >= 30

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
    track_type = request.form.get('track_type', 'server')
    
    # Check if auto-delete is enabled
    auto_delete = 'auto_delete' in request.form
    auto_delete_after = request.form.get('auto_delete_after', 24, type=int)
    
    discator = Discator(
        uuid=discator_uuid,
        name=discator_name,
        user_id=current_user.id,
        waiting_for_discord=True,
        auto_delete=auto_delete,
        auto_delete_after=auto_delete_after,
        track_type=track_type,
        waiting_since=datetime.utcnow()
    )
    
    db.session.add(discator)
    db.session.commit()
    
    # Redirect to the waiting page instead of dashboard
    return redirect(url_for('waiting_for_discord', discator_id=discator.id))

@app.route('/waiting/<int:discator_id>')
@login_required
def waiting_for_discord(discator_id):
    discator = Discator.query.get_or_404(discator_id)
    
    # Make sure the current user owns this discator
    if discator.user_id != current_user.id:
        flash('You do not have permission to view this discator')
        return redirect(url_for('dashboard'))
    
    # If discator is no longer waiting, redirect to details page
    if not discator.waiting_for_discord:
        flash('This discator has already received its first view.')
        return redirect(url_for('discator_details', discator_id=discator_id))
    
    # If discator waiting has expired, delete it and redirect to dashboard
    if discator.expired_waiting:
        flash(f'Discator "{discator.name}" was deleted because it was not used within 30 minutes.')
        db.session.delete(discator)
        db.session.commit()
        return redirect(url_for('dashboard'))
    
    return render_template('waiting_for_discord.html', discator=discator)

@app.route('/update-discator/<int:discator_id>', methods=['POST'])
@login_required
def update_discator(discator_id):
    discator = Discator.query.get_or_404(discator_id)
    
    # Make sure the current user owns this discator
    if discator.user_id != current_user.id:
        flash('You do not have permission to update this discator')
        return redirect(url_for('dashboard'))
    
    if 'auto_delete' in request.form:
        discator.auto_delete = True
        discator.auto_delete_after = request.form.get('auto_delete_after', 24, type=int)
    else:
        discator.auto_delete = False
    
    db.session.commit()
    flash(f'Discator "{discator.name}" updated successfully')
    return redirect(url_for('discator_details', discator_id=discator_id))

@app.route('/delete-discator/<int:discator_id>', methods=['POST'])
@login_required
def delete_discator(discator_id):
    discator = Discator.query.get_or_404(discator_id)
    
    # Make sure the current user owns this discator
    if discator.user_id != current_user.id:
        flash('You do not have permission to delete this discator')
        return redirect(url_for('dashboard'))
    
    # Delete all associated views first
    DiscatorView.query.filter_by(discator_id=discator_id).delete()
    
    # Delete the discator
    db.session.delete(discator)
    db.session.commit()
    
    flash(f'Discator "{discator.name}" deleted successfully')
    return redirect(url_for('dashboard'))

@app.route('/discator/<uuid>')
def serve_discator(uuid):
    discator = Discator.query.filter_by(uuid=uuid).first_or_404()
    
    # Check if this is a Discord bot view (typically contains "Discordbot" in user agent)
    is_discord_bot = "Discordbot" in request.user_agent.string
    
    # Record this view
    view = DiscatorView(
        discator_id=discator.id,
        ip_address=request.remote_addr,
        user_agent=request.user_agent.string
    )
    db.session.add(view)
    
    # If we're waiting for Discord and this is a Discord bot view, 
    # mark that we're no longer waiting and set first_view
    if discator.waiting_for_discord and is_discord_bot:
        discator.waiting_for_discord = False
        discator.first_view = datetime.utcnow()
        
        # Notify clients via WebSocket
        socketio.emit('discator_status', {
            'status': 'viewed',
            'discator_id': discator.id
        }, room=f'discator_{discator.id}')
        
    # If we're not waiting and there's no first_view yet (backwards compatibility)
    elif not discator.waiting_for_discord and not discator.first_view:
        discator.first_view = datetime.utcnow()
    
    # Check if this discator should be auto-deleted
    if discator.should_delete:
        # Record that we're going to delete this discator
        # We'll implement a cleanup job that regularly checks for discators to delete
        # For now, just mark it as potentially deletable by adding a view count
        pass
    
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

@app.route('/api/discator-status/<int:discator_id>')
@login_required
def discator_status(discator_id):
    """API endpoint to check discator status"""
    discator = Discator.query.get_or_404(discator_id)
    
    # Make sure the current user owns this discator
    if discator.user_id != current_user.id:
        return jsonify({"error": "Unauthorized"}), 403
    
    return jsonify({
        "waiting_for_discord": discator.waiting_for_discord,
        "expired_waiting": discator.expired_waiting,
        "first_view": discator.first_view.isoformat() if discator.first_view else None,
    })

@app.before_request
def check_auto_delete():
    """Check for and delete any discators that meet auto-delete criteria"""
    # Only run this check occasionally (not on every request)
    if request.endpoint in ('static', 'serve_discator') or not hasattr(g, 'cleanup_run'):
        return
    
    g.cleanup_run = True
    
    with app.app_context():
        # Find all discators with auto-delete enabled that have a first view
        auto_delete_discators = Discator.query.filter(
            Discator.auto_delete == True,
            Discator.first_view.isnot(None)
        ).all()
        
        count = 0
        for discator in auto_delete_discators:
            if discator.should_delete:
                # Delete views first
                DiscatorView.query.filter_by(discator_id=discator.id).delete()
                # Then delete the discator
                db.session.delete(discator)
                count += 1
        
        if count > 0:
            db.session.commit()
            app.logger.info(f"Auto-deleted {count} discators")

# WebSocket event handlers
@socketio.on('join_discator_room')
def handle_join_room(data):
    """Handle client joining a room for a specific discator"""
    discator_id = data.get('discator_id')
    if discator_id:
        room = f'discator_{discator_id}'
        join_room(room)

# Initialize database if it doesn't exist
with app.app_context():
    db.create_all()

# Update main to use socketio instead of app.run
if __name__ == '__main__':
    socketio.run(app, debug=True, port=4500)