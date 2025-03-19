from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime, date
from PIL import Image, ImageDraw, ImageFont
import random
import string
import io
import os
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///construction.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['CAPTCHA_ENABLE'] = True
app.config['CAPTCHA_LENGTH'] = 6
app.config['CAPTCHA_WIDTH'] = 200
app.config['CAPTCHA_HEIGHT'] = 70
app.config['CAPTCHA_FONT_SIZE'] = 36

def generate_captcha_text(length=6):
    """Generate random CAPTCHA text"""
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))

def create_captcha_image(text):
    """Create a simple CAPTCHA image"""
    # Create a new image with white background
    width = 200
    height = 70
    image = Image.new('RGB', (width, height), 'white')
    draw = ImageDraw.Draw(image)
    
    # Draw text
    text_color = (0, 0, 0)  # Black color
    # Draw each character with slight random position
    x = 20  # Start further from the left edge
    for char in text:
        y = random.randint(10, 20)  # Adjust vertical range
        draw.text((x, y), char, fill=text_color, font=None, font_size=36)
        x += 30  # Increase space between characters
    
    # Add some noise (reduced amount for better readability)
    for _ in range(300):
        x = random.randint(0, width-1)
        y = random.randint(0, height-1)
        draw.point((x, y), fill=(random.randint(0, 255), random.randint(0, 255), random.randint(0, 255)))
    
    return image

@app.route('/captcha')
def get_captcha():
    """Generate and serve a new CAPTCHA image"""
    # Generate random text
    captcha_text = generate_captcha_text()
    # Store in session
    session['captcha_text'] = captcha_text
    # Create image
    image = create_captcha_image(captcha_text)
    # Save to bytes
    img_io = io.BytesIO()
    image.save(img_io, 'PNG')
    img_io.seek(0)
    return send_file(img_io, mimetype='image/png')

def verify_captcha(user_input):
    """Verify user's CAPTCHA input"""
    if not user_input:
        return False
    stored_captcha = session.get('captcha_text', '')
    # Clear the stored CAPTCHA after checking
    session.pop('captcha_text', None)
    return user_input.upper() == stored_captcha.upper()

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    role = db.Column(db.String(20), nullable=False, default='data_entry')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    # Define relationships
    submitted_projects = db.relationship('ConstructionProject', foreign_keys='ConstructionProject.submitted_by', backref='submitter', lazy='dynamic')
    approved_projects = db.relationship('ConstructionProject', foreign_keys='ConstructionProject.approver_id', backref='approver', lazy='dynamic')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def is_admin(self):
        return self.role == 'admin'

    def is_data_entry(self):
        return self.role == 'data_entry'

class ConstructionProject(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.String(50), unique=True, nullable=False)
    old_project_id = db.Column(db.String(50), nullable=True)  # Store previous ID
    project_name = db.Column(db.String(100), nullable=False)
    development_type = db.Column(db.String(50), nullable=False)
    start_date = db.Column(db.Date, nullable=False)
    end_date = db.Column(db.Date, nullable=False)
    estimated_days = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(20), nullable=False)
    cost = db.Column(db.Float, nullable=False)
    village = db.Column(db.String(100), nullable=False)
    taluka = db.Column(db.String(100), nullable=False)
    district = db.Column(db.String(100), nullable=False)
    state = db.Column(db.String(100), nullable=False)
    contractor_name = db.Column(db.String(100), nullable=False)
    contractor_contact = db.Column(db.String(20), nullable=False)
    contractor_email = db.Column(db.String(100), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    approval_status = db.Column(db.String(20), default='pending')  # pending, approved, rejected, pending_update
    approver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    approval_date = db.Column(db.DateTime, nullable=True)
    rejection_reason = db.Column(db.Text, nullable=True)
    submitted_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    delay_reason = db.Column(db.Text, nullable=True)
    changes_log = db.Column(db.JSON, nullable=True)  # Store list of changes made
    needs_duplicate_review = db.Column(db.Boolean, default=False)
    similar_project_id = db.Column(db.Integer, db.ForeignKey('construction_project.id'))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        role = request.form.get('role')
        captcha_response = request.form.get('captcha')
        
        if not verify_captcha(captcha_response):
            flash('Invalid CAPTCHA code. Please try again.', 'danger')
            return redirect(url_for('register'))
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
            return redirect(url_for('register'))
            
        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'danger')
            return redirect(url_for('register'))
            
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return redirect(url_for('register'))
            
        user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password),
            role=role
        )
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
        
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        if current_user.is_admin():
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('data_entry_dashboard'))
        
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        captcha_response = request.form.get('captcha')
        
        if not verify_captcha(captcha_response):
            flash('Invalid CAPTCHA code. Please try again.', 'danger')
            return redirect(url_for('login'))
        
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            flash('Logged in successfully!', 'success')
            if user.is_admin():
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('data_entry_dashboard'))
        else:
            flash('Invalid username or password', 'danger')
    return render_template('login.html')

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if current_user.is_authenticated:
        if current_user.is_admin():
            return redirect(url_for('admin_dashboard'))
        else:
            flash('You do not have admin privileges', 'danger')
            return redirect(url_for('data_entry_dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        captcha_response = request.form.get('captcha')
        
        if not verify_captcha(captcha_response):
            flash('Invalid CAPTCHA code. Please try again.', 'danger')
            return redirect(url_for('admin_login'))
        
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password) and user.is_admin():
            login_user(user)
            flash('Logged in successfully as Admin!', 'success')
            return redirect(url_for('admin_dashboard'))
        flash('Invalid admin credentials', 'danger')
    return render_template('admin_login.html')

@app.route('/data-entry/login', methods=['GET', 'POST'])
def data_entry_login():
    if current_user.is_authenticated:
        if current_user.is_data_entry():
            return redirect(url_for('data_entry_dashboard'))
        else:
            return redirect(url_for('admin_dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        captcha_response = request.form.get('captcha')
        
        if not verify_captcha(captcha_response):
            flash('Invalid CAPTCHA code. Please try again.', 'danger')
            return redirect(url_for('data_entry_login'))
        
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password) and user.is_data_entry():
            login_user(user)
            flash('Logged in successfully as Data Entry Officer!', 'success')
            return redirect(url_for('data_entry_dashboard'))
        flash('Invalid data entry credentials', 'danger')
    return render_template('data_entry_login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.is_admin():
        return redirect(url_for('admin_dashboard'))
    else:
        return redirect(url_for('data_entry_dashboard'))

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if not current_user.is_authenticated or current_user.role != 'admin':
        flash('You do not have permission to access the admin dashboard.', 'danger')
        return redirect(url_for('dashboard'))

    # Get projects that need duplicate review
    duplicate_projects = ConstructionProject.query.filter_by(needs_duplicate_review=True).all()
    
    # Get pending approval projects
    pending_projects = ConstructionProject.query.filter_by(approval_status='pending').all()
    
    return render_template('admin_dashboard.html', 
                         duplicate_projects=duplicate_projects,
                         pending_projects=pending_projects)

@app.route('/data-entry/dashboard')
@login_required
def data_entry_dashboard():
    if not current_user.is_data_entry():
        return redirect(url_for('admin_dashboard'))
    
    # Fetch projects submitted by this user
    submitted_projects = ConstructionProject.query.filter_by(submitted_by=current_user.id).all()
    # Group projects by approval status
    pending_projects = [p for p in submitted_projects if p.approval_status == 'pending']
    approved_projects = [p for p in submitted_projects if p.approval_status == 'approved']
    rejected_projects = [p for p in submitted_projects if p.approval_status == 'rejected']
    
    return render_template('data_entry_dashboard.html',
                          pending_projects=pending_projects,
                          approved_projects=approved_projects,
                          rejected_projects=rejected_projects)

def check_duplicate_project(project_data):
    """Check if a similar project already exists"""
    existing_project = ConstructionProject.query.filter_by(
        development_type=project_data['development_type'],
        village=project_data['village'],
        taluka=project_data['taluka'],
        district=project_data['district'],
        state=project_data['state'],
        contractor_name=project_data['contractor_name'],
        contractor_contact=project_data['contractor_contact'],
        cost=project_data['cost']
    ).first()
    
    return existing_project

def generate_project_id(development_type, district, taluka, village):
    """Generate a project ID based on project details"""
    # Format: DEV-ST-COST-GU-DIS-TA-VI-NO-XXXX-YEAR
    dev_type = development_type[:3].upper()
    district_code = district[:3].upper()
    taluka_code = taluka[:2].upper()
    village_code = village[:2].upper()
    
    # Generate a random 4-digit number
    random_number = ''.join(random.choices(string.digits, k=4))
    year = str(datetime.now().year)
    
    return f"{dev_type}-IN-1000-GU-{district_code}-{taluka_code}-{village_code}-NO-{random_number}-{year}"

@app.route('/project/new', methods=['GET', 'POST'])
def new_project():
    if not current_user.is_authenticated:
        flash('Please login to continue.', 'warning')
        return redirect(url_for('login'))
    
    if current_user.role not in ['admin', 'data_entry']:
        flash('You do not have permission to add new projects.', 'danger')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        try:
            # Get form data
            development_type = request.form.get('development_type')
            if development_type == 'other':
                development_type = request.form.get('other_development_type')
            
            project_name = request.form.get('project_name')
            status = request.form.get('status')
            
            # Handle dates based on status
            start_date = None
            end_date = None
            if status != 'proposal':
                try:
                    start_date = datetime.strptime(request.form.get('start_date'), '%Y-%m-%d')
                    if status in ['completed', 'delayed']:
                        end_date = datetime.strptime(request.form.get('end_date'), '%Y-%m-%d')
                except ValueError:
                    flash('Please enter valid dates.', 'danger')
                    return redirect(url_for('new_project'))

            estimated_days = int(request.form.get('estimated_days'))
            cost = float(request.form.get('cost'))
            
            # Location details
            state = request.form.get('state')
            district = request.form.get('district')
            taluka = request.form.get('taluka')
            village = request.form.get('village')
            
            # Contractor details
            contractor_name = request.form.get('contractor_name')
            contractor_contact = request.form.get('contractor_contact')
            contractor_email = request.form.get('contractor_email')

            # Generate project ID
            project_id = generate_project_id(
                development_type=development_type,
                district=district,
                taluka=taluka,
                village=village
            )

            # Check for similar projects - but only store the info, don't block submission
            similar_project = None
            if current_user.role == 'admin':
                similar_project = ConstructionProject.query.filter_by(
                    development_type=development_type,
                    district=district,
                    taluka=taluka,
                    village=village,
                    project_name=project_name
                ).first()

            # Create new project
            new_project = ConstructionProject(
                project_id=project_id,
                development_type=development_type,
                project_name=project_name,
                status=status,
                start_date=start_date,
                end_date=end_date,
                estimated_days=estimated_days,
                cost=cost,
                state=state,
                district=district,
                taluka=taluka,
                village=village,
                contractor_name=contractor_name,
                contractor_contact=contractor_contact,
                contractor_email=contractor_email,
                submitted_by=current_user.id,
                approval_status='pending',
                delay_reason=request.form.get('delay_reason') if status == 'delayed' else None
            )

            db.session.add(new_project)
            
            # If admin and similar project found, mark it for review
            if current_user.role == 'admin' and similar_project:
                new_project.needs_duplicate_review = True
                new_project.similar_project_id = similar_project.project_id
                flash(f'Project added but marked for duplicate review. Similar project exists with ID: {similar_project.project_id}', 'warning')
            else:
                flash('Project added successfully.', 'success')
            
            db.session.commit()
            return redirect(url_for('dashboard'))

        except Exception as e:
            db.session.rollback()
            flash(f'Error adding project: {str(e)}', 'danger')
            return redirect(url_for('new_project'))

    return render_template('new_project.html')

@app.route('/project/<int:id>')
@login_required
def project_details(id):
    project = ConstructionProject.query.get_or_404(id)
    similar_projects = ConstructionProject.query.filter(
        ConstructionProject.id != id,
        ConstructionProject.village == project.village,
        ConstructionProject.development_type == project.development_type
    ).limit(3).all()
    return render_template('project_details.html', project=project, similar_projects=similar_projects)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully!', 'success')
    return redirect(url_for('index'))

@app.route('/admin/review/<int:id>', methods=['GET'])
@login_required
def admin_review_project(id):
    if not current_user.is_admin():
        flash('You do not have permission to review projects', 'danger')
        return redirect(url_for('data_entry_dashboard'))
    
    project = ConstructionProject.query.get_or_404(id)
    
    # Find similar projects for comparison
    similar_projects = ConstructionProject.query.filter(
        ConstructionProject.id != id,
        ConstructionProject.village == project.village,
        ConstructionProject.development_type == project.development_type
    ).all()
    
    return render_template('admin_review.html', 
                          project=project, 
                          similar_projects=similar_projects)

@app.route('/admin/approve/<int:id>', methods=['POST'])
@login_required
def approve_project(id):
    if not current_user.is_admin():
        flash('You do not have permission to approve projects', 'danger')
        return redirect(url_for('data_entry_dashboard'))
    
    project = ConstructionProject.query.get_or_404(id)
    if project.approval_status != 'pending':
        flash('This project has already been reviewed', 'warning')
        return redirect(url_for('admin_dashboard'))
    
    project.approval_status = 'approved'
    project.approver_id = current_user.id
    project.approval_date = datetime.utcnow()
    
    db.session.commit()
    flash(f'Project {project.project_id} has been approved', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/reject/<int:id>', methods=['POST'])
@login_required
def reject_project(id):
    if not current_user.is_admin():
        flash('You do not have permission to reject projects', 'danger')
        return redirect(url_for('data_entry_dashboard'))
    
    project = ConstructionProject.query.get_or_404(id)
    if project.approval_status != 'pending':
        flash('This project has already been reviewed', 'warning')
        return redirect(url_for('admin_dashboard'))
    
    rejection_reason = request.form.get('rejection_reason')
    if not rejection_reason:
        flash('Please provide a reason for rejection', 'danger')
        return redirect(url_for('admin_review_project', id=id))
    
    project.approval_status = 'rejected'
    project.approver_id = current_user.id
    project.approval_date = datetime.utcnow()
    project.rejection_reason = rejection_reason
    
    db.session.commit()
    flash(f'Project {project.project_id} has been rejected', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/project/update/<int:id>', methods=['GET', 'POST'])
@login_required
def update_project(id):
    if not current_user.is_data_entry():
        flash('Only data entry officers can update projects', 'danger')
        return redirect(url_for('dashboard'))
    
    project = ConstructionProject.query.get_or_404(id)
    
    # Check if project is approved
    if project.approval_status != 'approved':
        flash('Only approved projects can be updated', 'warning')
        return redirect(url_for('project_details', id=id))
    
    # Check if the project was submitted by the current user
    if project.submitted_by != current_user.id:
        flash('You can only update projects that you submitted', 'danger')
        return redirect(url_for('project_details', id=id))

    if request.method == 'POST':
        try:
            # Get dates from form if provided
            new_status = request.form.get('status')
            new_cost = float(request.form.get('cost'))
            
            if new_status in ['completed', 'delayed']:
                try:
                    end_date_str = request.form.get('end_date')
                    if not end_date_str:
                        flash('End date is required for completed or delayed projects', 'danger')
                        return redirect(url_for('update_project', id=id))
                        
                    end_date = datetime.strptime(end_date_str, '%Y-%m-%d')
                    # Convert both dates to date objects for comparison
                    if end_date.date() < project.start_date.date():
                        flash('End date must be after start date', 'danger')
                        return redirect(url_for('update_project', id=id))
                    project.end_date = end_date
                    project.estimated_days = (end_date.date() - project.start_date.date()).days + 1
                except ValueError:
                    flash('Invalid end date format. Please use YYYY-MM-DD format', 'danger')
                    return redirect(url_for('update_project', id=id))
            
            # Update project details
            project.status = new_status
            project.cost = new_cost
            project.updated_at = datetime.utcnow()
            
            # If status is delayed, store the delay reason
            if new_status == 'delayed':
                delay_reason = request.form.get('delay_reason')
                if not delay_reason:
                    flash('Please provide a reason for delay', 'danger')
                    return redirect(url_for('update_project', id=id))
                project.delay_reason = delay_reason
            
            # Set approval status to 'pending_update' for admin review
            project.approval_status = 'pending_update'
            project.approval_date = None
            project.approver_id = None
            
            db.session.commit()
            flash('Project updated successfully! Awaiting admin review of updates.', 'success')
            return redirect(url_for('project_details', id=id))
            
        except ValueError as e:
            flash(f'Error: {str(e)}', 'danger')
            return redirect(url_for('update_project', id=id))
        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred: {str(e)}', 'danger')
            return redirect(url_for('update_project', id=id))
    
    return render_template('update_project.html', project=project)

@app.route('/project/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_project(id):
    if not current_user.is_data_entry():
        flash('Only data entry officers can edit projects', 'danger')
        return redirect(url_for('dashboard'))
    
    project = ConstructionProject.query.get_or_404(id)
    
    # Check if the project was submitted by the current user
    if project.submitted_by != current_user.id:
        flash('You can only edit projects that you submitted', 'danger')
        return redirect(url_for('project_details', id=id))

    if request.method == 'POST':
        try:
            # Store original values for change tracking
            changes = []
            original_values = {
                'project_name': project.project_name,
                'development_type': project.development_type,
                'status': project.status,
                'cost': project.cost,
                'start_date': project.start_date,
                'end_date': project.end_date,
                'village': project.village,
                'taluka': project.taluka,
                'district': project.district,
                'contractor_name': project.contractor_name,
                'contractor_contact': project.contractor_contact,
                'contractor_email': project.contractor_email
            }

            # Get dates from form
            start_date_str = request.form.get('start_date')
            end_date_str = request.form.get('end_date')
            status = request.form.get('status')
            
            # Validate dates based on status
            if status != 'proposal':
                if not start_date_str:
                    flash('Start date is required', 'danger')
                    return redirect(url_for('edit_project', id=id))
                try:
                    start_date = datetime.strptime(start_date_str, '%Y-%m-%d')
                except ValueError:
                    flash('Invalid start date format. Please use YYYY-MM-DD format', 'danger')
                    return redirect(url_for('edit_project', id=id))
                    
                if status in ['completed', 'delayed']:
                    if not end_date_str:
                        flash('End date is required for completed or delayed projects', 'danger')
                        return redirect(url_for('edit_project', id=id))
                    try:
                        end_date = datetime.strptime(end_date_str, '%Y-%m-%d')
                        if end_date.date() < start_date.date():
                            flash('End date must be after start date', 'danger')
                            return redirect(url_for('edit_project', id=id))
                    except ValueError:
                        flash('Invalid end date format. Please use YYYY-MM-DD format', 'danger')
                        return redirect(url_for('edit_project', id=id))
                else:
                    end_date = start_date
            else:
                start_date = datetime.now()
                end_date = start_date

            # If project was rejected or approved, generate new project ID and reset status
            if project.approval_status in ['rejected', 'approved']:
                project_data = {
                    'development_type': request.form.get('development_type'),
                    'status': status,
                    'cost': float(request.form.get('cost')),
                    'state': request.form.get('state'),
                    'district': request.form.get('district'),
                    'taluka': request.form.get('taluka'),
                    'village': request.form.get('village'),
                    'contractor_name': request.form.get('contractor_name'),
                    'contractor_contact': request.form.get('contractor_contact')
                }
                # Store old project ID before generating new one
                project.old_project_id = project.project_id
                project.project_id = generate_project_id(project_data)
                changes.append(f"Project ID changed from {project.old_project_id} to {project.project_id}")
                project.approval_status = 'pending'  # Reset to pending for admin review
                project.approval_date = None
                project.approver_id = None
                project.rejection_reason = None

            # Update project details and track changes
            new_values = {
                'project_name': request.form.get('project_name'),
                'development_type': request.form.get('development_type'),
                'status': status,
                'cost': float(request.form.get('cost')),
                'start_date': start_date.date(),
                'end_date': end_date.date(),
                'village': request.form.get('village'),
                'taluka': request.form.get('taluka'),
                'district': request.form.get('district'),
                'contractor_name': request.form.get('contractor_name'),
                'contractor_contact': request.form.get('contractor_contact'),
                'contractor_email': request.form.get('contractor_email')
            }

            # Record changes
            for field, new_value in new_values.items():
                old_value = original_values[field]
                if old_value != new_value:
                    if isinstance(old_value, (datetime, date)):
                        old_value = old_value.strftime('%Y-%m-%d')
                    if isinstance(new_value, (datetime, date)):
                        new_value = new_value.strftime('%Y-%m-%d')
                    changes.append(f"{field.replace('_', ' ').title()}: {old_value} → {new_value}")

            # Update project with new values
            project.project_name = new_values['project_name']
            project.development_type = new_values['development_type']
            project.start_date = start_date
            project.end_date = end_date
            project.estimated_days = (end_date.date() - start_date.date()).days + 1
            project.status = status
            project.cost = new_values['cost']
            project.village = new_values['village']
            project.taluka = new_values['taluka']
            project.district = new_values['district']
            project.contractor_name = new_values['contractor_name']
            project.contractor_contact = new_values['contractor_contact']
            project.contractor_email = new_values['contractor_email']
            project.updated_at = datetime.utcnow()
            
            # If status is delayed, store the delay reason
            if status == 'delayed':
                delay_reason = request.form.get('delay_reason')
                if not delay_reason:
                    flash('Please provide a reason for delay', 'danger')
                    return redirect(url_for('edit_project', id=id))
                if project.delay_reason != delay_reason:
                    changes.append(f"Delay Reason: {project.delay_reason if project.delay_reason else 'None'} → {delay_reason}")
                project.delay_reason = delay_reason
            else:
                if project.delay_reason:
                    changes.append(f"Delay Reason removed: {project.delay_reason}")
                project.delay_reason = None
            
            # Store changes log
            if changes:
                project.changes_log = changes
            
            db.session.commit()
            flash('Project edited successfully! Awaiting admin review.', 'success')
            return redirect(url_for('project_details', id=id))
            
        except ValueError as e:
            flash(f'Error: {str(e)}', 'danger')
            return redirect(url_for('edit_project', id=id))
        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred: {str(e)}', 'danger')
            return redirect(url_for('edit_project', id=id))
    
    return render_template('edit_project.html', project=project)

def init_db():
    with app.app_context():
        # Drop all tables
        db.drop_all()
        # Create all tables
        db.create_all()
        print('Database initialized successfully!')

def create_admin_user():
    with app.app_context():
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            admin = User(
                username='admin',
                email='admin@example.com',
                role='admin'
            )
            admin.set_password('admin123')
            db.session.add(admin)
            
        data_entry_user = User.query.filter_by(username='data_entry').first()
        if not data_entry_user:
            data_entry_user = User(
                username='data_entry',
                email='data_entry@example.com',
                role='data_entry'
            )
            data_entry_user.set_password('data123')
            db.session.add(data_entry_user)
            
        db.session.commit()
        print('Admin and data entry users created successfully!')

if __name__ == '__main__':
    # Uncomment to reset database
    init_db()
    # Create admin user if it doesn't exist
    create_admin_user()
    app.run(debug=True) 