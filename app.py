from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, ForeignKey
from sqlalchemy.orm import sessionmaker, declarative_base
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
import google.generativeai as genai
import os
from datetime import datetime, timedelta
import logging
import threading
import re
import random
import secrets

# Setup basic logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load environment variables from .env file
load_dotenv()

# Initialize Flask web application
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-key-for-testing')
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)  # Session expires after 30 minutes
app.config['APP_NAME'] = 'AutoGraderX'

# Setup database connection
DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{os.path.abspath('codeapp.db')}")
engine = create_engine(DATABASE_URL)
Base = declarative_base()
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Setup Google's Gemini AI for code analysis
gemini_api_key = os.getenv("GEMINI_API_KEY")
genai.configure(api_key=gemini_api_key)
model = genai.GenerativeModel('gemini-1.5-pro')

# List of programming motivational quotes to display with grading results
PROGRAMMING_QUOTES = [
    "Code is like humor. When you have to explain it, it's bad. – Cory House",
    "First, solve the problem. Then, write the code. – John Johnson",
    "Experience is the name everyone gives to their mistakes. – Oscar Wilde",
    "The only way to learn a new programming language is by writing programs in it. – Dennis Ritchie",
    "Programming isn't about what you know; it's about what you can figure out. – Chris Pine",
    "The most disastrous thing that you can ever learn is your first programming language. – Alan Kay",
    "Simplicity is the soul of efficiency. – Austin Freeman",
    "Any fool can write code that a computer can understand. Good programmers write code that humans can understand. – Martin Fowler",
    "The best error message is the one that never shows up. – Thomas Fuchs",
    "Clean code always looks like it was written by someone who cares. – Robert C. Martin"
]

# Database Models
class User(Base):
    """User model for storing user login information"""
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    username = Column(String(150), unique=True, nullable=False)
    password = Column(String(150), nullable=False)  # Stores hashed password

class CodeSubmission(Base):
    """Model for storing code submissions and their analysis results"""
    __tablename__ = 'submissions'
    id = Column(Integer, primary_key=True)
    code = Column(Text, nullable=False)  # The submitted code
    line_analysis = Column(Text, nullable=True)  # Analysis of code
    restructured_code = Column(Text, nullable=True)  # Improved version of code
    grade = Column(Text, nullable=True)  # Grade and feedback
    timestamp = Column(DateTime, default=datetime.utcnow)  # When code was submitted
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)  # Who submitted the code
    language = Column(String(50), nullable=True)  # Programming language detected

# Create all database tables
Base.metadata.create_all(engine)

# Helper functions for templates
@app.context_processor
def utility_processor():
    """Adds helper functions and variables to all templates"""
    def is_logged_in():
        return 'user_id' in session
    
    return {
        'is_logged_in': is_logged_in,
        'app_name': app.config.get('APP_NAME', 'AutoGraderX'),
        'now': datetime.now()
    }

# Authentication helper functions
def is_logged_in():
    """Check if user is logged in"""
    return 'user_id' in session

def login_required(f):
    """Decorator to require login for certain pages"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not is_logged_in():
            flash('Please log in to access this page', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Fix missing import for wraps
from functools import wraps

# Database health check
def check_database_health():
    """Verify database connection and schema are working correctly"""
    db_session = None
    try:
        db_session = SessionLocal()
        # Try to query tables to check if they exist and have expected columns
        db_session.query(User).first()
        submission = db_session.query(CodeSubmission).first()
        
        if submission:
            # Access all columns to check schema
            _ = submission.id
            _ = submission.code
            _ = submission.line_analysis
            _ = submission.restructured_code
            _ = submission.grade
            _ = submission.timestamp
            _ = submission.user_id
            _ = submission.language
        return True
    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        return False
    finally:
        if db_session:
            db_session.close()

# Code analysis functions
def detect_programming_language(code):
    """Determine what programming language the code is written in"""
    language_patterns = {
        'Python': [r'\bdef\b', r'\bclass\b', r':\s*$'],
        'JavaScript': [r'\bfunction\b', r'\bconst\b', r'\blet\b'],
        'Java': [r'\bpublic\s+(class|void|int)\b', r'\bimport\b'],
        'C++': [r'\b#include\b', r'\bclass\b', r'\bstd::\b'],
    }
    
    # Check for language patterns in the code
    for lang, patterns in language_patterns.items():
        if all(re.search(pattern, code) for pattern in patterns):
            return lang
    
    return 'Unknown'

def chunk_code(code, max_chunk_size=2000):
    """Split large code into smaller chunks for analysis"""
    if len(code) <= max_chunk_size:
        return [code]
    
    chunks = []
    lines = code.split('\n')
    current_chunk = []
    current_size = 0
    
    for line in lines:
        line_size = len(line) + 1  # +1 for newline character
        
        # If adding this line would exceed chunk size, start a new chunk
        if current_size + line_size > max_chunk_size and current_chunk:
            chunks.append('\n'.join(current_chunk))
            current_chunk = []
            current_size = 0
        
        current_chunk.append(line)
        current_size += line_size
    
    # Add the last chunk if not empty
    if current_chunk:
        chunks.append('\n'.join(current_chunk))
    
    return chunks

def analyze_code_chunk(chunk, language):
    """Have AI analyze a single chunk of code"""
    prompt = f"""
    Analyze the following code chunk and provide a brief explanation of what it does.
    Focus on the key functionality and any notable patterns or techniques.
    
    ```{language}
    {chunk}
    ```
    
    Keep your explanation concise and clear.
    """
    
    try:
        response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        logger.error(f"Error during chunk analysis: {str(e)}", exc_info=True)
        return f"Error analyzing this code section: {str(e)}"

def restructure_code_chunk(chunk, language):
    """Have AI improve a single chunk of code"""
    prompt = f"""
    Improve the following code chunk. Make it more readable, maintainable and efficient.
    
    ```{language}
    {chunk}
    ```
    
    Return only the improved code with brief comments explaining key changes.
    """
    
    try:
        response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        logger.error(f"Error during chunk restructuring: {str(e)}", exc_info=True)
        return f"Error restructuring this code section: {str(e)}"

def combine_chunk_analyses(analyses):
    """Combine multiple chunk analyses into a single summary"""
    if len(analyses) == 1:
        return analyses[0]
    
    summary_prompt = f"""
    Combine the following code analyses into a coherent, unified summary.
    Make sure the summary is concise, clear, and captures the key points from all analyses.
    
    Analyses to combine:
    {' '.join(analyses)}
    
    Format your response in simple markdown, keeping it under 300 words.
    """
    
    try:
        response = model.generate_content(summary_prompt)
        return response.text
    except Exception as e:
        logger.error(f"Error combining analyses: {str(e)}", exc_info=True)
        return "\n\n".join(["# Combined Analysis"] + analyses)

def combine_restructured_code(restructured_chunks, language):
    """Combine multiple restructured code chunks into a complete solution"""
    if len(restructured_chunks) == 1:
        return restructured_chunks[0]
    
    # Add section labels to each chunk
    combined = []
    for i, chunk in enumerate(restructured_chunks):
        combined.append(f"# Section {i+1}\n{chunk}")
    
    return "\n\n".join(combined)

def grade_code_with_chunking(code, language):
    """Grade the code quality and provide feedback"""
    if len(code) <= 3000:  # For smaller code snippets, grade directly
        grade_prompt = f"""
        Evaluate the following code and give it a simple grade (A, B, C, D, or F) with a very brief explanation.
        Keep your explanation concise and helpful, like giving quick feedback to a student.
        
        CODE:
        ```{language}
        {code}
        ```
        
        Format your response EXACTLY as follows - VERY IMPORTANT:
        Grade: [single letter grade A, B, C, D, or F]
        
        Assessment:
        [Your brief assessment in 2-3 sentences maximum]
        """
        
        try:
            response = model.generate_content(grade_prompt)
            return response.text
        except Exception as e:
            logger.error(f"Error during grading: {str(e)}", exc_info=True)
            return f"Error during grading: {str(e)}"
    
    # For larger code, analyze in chunks
    chunks = chunk_code(code)
    chunk_analyses = []
    
    for chunk in chunks:
        chunk_prompt = f"""
        Analyze this code chunk for quality and best practices.
        
        ```{language}
        {chunk}
        ```
        
        Provide a brief quality assessment highlighting strengths and weaknesses.
        """
        
        try:
            response = model.generate_content(chunk_prompt)
            chunk_analyses.append(response.text)
        except Exception as e:
            logger.error(f"Error during chunk quality assessment: {str(e)}", exc_info=True)
            chunk_analyses.append(f"Error analyzing this code section: {str(e)}")
    
    # Combine analyses and determine final grade
    final_grade_prompt = f"""
    Based on the following code quality assessments, provide a final grade (A, B, C, D, or F) with a very brief explanation.
    
    Assessments:
    {' '.join(chunk_analyses)}
    
    Format your response EXACTLY as follows - VERY IMPORTANT:
    Grade: [single letter grade A, B, C, D, or F]
    
    Assessment:
    [Your brief assessment in 2-3 sentences maximum]
    """
    
    try:
        response = model.generate_content(final_grade_prompt)
        return response.text
    except Exception as e:
        logger.error(f"Error during final grading: {str(e)}", exc_info=True)
        return f"Error during grading: {str(e)}"

# Analysis status check route
@app.route('/check_analysis_status/<int:submission_id>')
@login_required
def check_analysis_status(submission_id):
    """Check if code analysis is complete for a submission"""
    user_id = session.get('user_id')
    db_session = None
    try:
        db_session = SessionLocal()
        submission = db_session.query(CodeSubmission).filter_by(id=submission_id, user_id=user_id).first()
        
        if not submission:
            return jsonify({"status": "error", "message": "Submission not found"}), 404
        
        # Check status of each analysis component
        analysis_status = "complete" if submission.line_analysis and "in progress" not in submission.line_analysis.lower() else "pending"
        restructured_status = "complete" if submission.restructured_code and "in progress" not in submission.restructured_code.lower() else "pending"
        grade_status = "complete" if submission.grade and "in progress" not in submission.grade.lower() else "pending"
        
        # Check for errors
        if submission.line_analysis and "error" in submission.line_analysis.lower():
            analysis_status = "error"
        if submission.restructured_code and "error" in submission.restructured_code.lower():
            restructured_status = "error"
        if submission.grade and "error" in submission.grade.lower():
            grade_status = "error"
        
        return jsonify({
            "analysis_status": analysis_status,
            "restructured_status": restructured_status,
            "grade_status": grade_status,
            "all_complete": all(status == "complete" for status in [analysis_status, restructured_status, grade_status])
        })
        
    except Exception as e:
        logger.error(f"Status check error: {str(e)}", exc_info=True)
        return jsonify({"status": "error", "message": str(e)}), 500
    finally:
        if db_session:
            db_session.close()

# Background processing function
def process_code_analysis(submission_id):
    """Process code analysis in background thread"""
    db_session = None
    try:
        db_session = SessionLocal()
        submission = db_session.query(CodeSubmission).filter_by(id=submission_id).first()
        if not submission:
            logger.error(f"Submission {submission_id} not found")
            return
        
        logger.info(f"Starting analysis for submission {submission_id}")
        
        # Step 1: Detect programming language
        try:
            language = detect_programming_language(submission.code)
            submission.language = language
            db_session.commit()
        except Exception as e:
            logger.error(f"Error detecting language: {str(e)}", exc_info=True)
            submission.language = "Unknown"
            db_session.commit()
        
        # Step 2: Split code into chunks for analysis
        code_chunks = chunk_code(submission.code)
        logger.info(f"Split code into {len(code_chunks)} chunks for analysis")
        
        # Step 3: Analyze the code
        try:
            chunk_analyses = []
            for chunk in code_chunks:
                analysis = analyze_code_chunk(chunk, submission.language or "Unknown")
                chunk_analyses.append(analysis)
                combined_analysis = combine_chunk_analyses(chunk_analyses)
            submission.line_analysis = combined_analysis
            db_session.commit()
            logger.info(f"Completed analysis for submission {submission_id}")
        except Exception as e:
            error_msg = f"Error during code analysis: {str(e)}"
            logger.error(error_msg, exc_info=True)
            submission.line_analysis = error_msg
            db_session.commit()
        
        # Step 4: Restructure/improve the code
        try:
            restructured_chunks = []
            for chunk in code_chunks:
                restructured = restructure_code_chunk(chunk, submission.language or "Unknown")
                restructured_chunks.append(restructured)
            
            combined_restructured = combine_restructured_code(restructured_chunks, submission.language or "Unknown")
            submission.restructured_code = combined_restructured
            db_session.commit()
            logger.info(f"Completed code restructuring for submission {submission_id}")
        except Exception as e:
            error_msg = f"Error during code restructuring: {str(e)}"
            logger.error(error_msg, exc_info=True)
            submission.restructured_code = error_msg
            db_session.commit()
        
        # Step 5: Grade the code
        try:
            grade_result = grade_code_with_chunking(submission.code, submission.language or "Unknown")
            
            # Add a motivational quote to the grade
            motivational_quote = random.choice(PROGRAMMING_QUOTES)
            formatted_grade = f"{grade_result}\n\n💡 {motivational_quote}"
            submission.grade = formatted_grade
            db_session.commit()
            logger.info(f"Completed grading for submission {submission_id}")
        except Exception as e:
            error_msg = f"Error during code grading: {str(e)}"
            logger.error(error_msg, exc_info=True)
            submission.grade = error_msg
            db_session.commit()
        
        logger.info(f"Completed all processing for submission {submission_id}")
        
    except Exception as e:
        logger.error(f"Unhandled error during code analysis for submission {submission_id}: {str(e)}", exc_info=True)
    finally:
        if db_session:
            db_session.close()

# Web Routes
@app.route('/')
def home():
    """Display the home/landing page"""
    return render_template('index.html')

@app.route('/health')
def health_check():
    """API endpoint to check if the application is healthy"""
    if check_database_health():
        return jsonify({"status": "ok", "database": "healthy"})
    else:
        return jsonify({"status": "error", "database": "unhealthy"}), 500

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handle user login"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        db_session = None
        try:
            db_session = SessionLocal()
            user = db_session.query(User).filter_by(username=username).first()
            
            if user and check_password_hash(user.password, password):
                session['user_id'] = user.id
                session.permanent = True  # Make session persistent
                flash('Login successful!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid username or password', 'danger')
                return redirect(url_for('login'))
        except Exception as e:
            logger.error(f"Login error: {str(e)}", exc_info=True)
            flash('An error occurred during login. Please try again.', 'danger')
            return redirect(url_for('login'))
        finally:
            if db_session:
                db_session.close()
    
    # Display login form for GET requests
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Handle new user registration"""
    if is_logged_in():
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        # Validate input
        if not username or not password:
            flash('Username and password are required', 'danger')
            return redirect(url_for('register'))
            
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return redirect(url_for('register'))
        
        db_session = None
        try:
            db_session = SessionLocal()
            
            # Check if username already exists
            existing_user = db_session.query(User).filter_by(username=username).first()
            if existing_user:
                flash('Username already exists.', 'danger')
                return redirect(url_for('register'))
            
            # Create new user account
            hashed_password = generate_password_hash(password)
            new_user = User(username=username, password=hashed_password)
            db_session.add(new_user)
            db_session.commit()
            
            flash('Registration successful! You can now log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            if db_session:
                db_session.rollback()
            logger.error(f"Registration error: {str(e)}", exc_info=True)
            flash('An error occurred during registration. Please try again.', 'danger')
            return redirect(url_for('register'))
        finally:
            if db_session:
                db_session.close()
    
    # Display registration form for GET requests
    return render_template('register.html')

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    """Handle password reset requests"""
    if request.method == 'POST':
        username = request.form.get('username')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        security_token = request.form.get('security_token')
        session_token = session.get('reset_token')
        
        # Validate security token
        if not security_token or not session_token or not secrets.compare_digest(security_token, session_token):
            flash('Invalid security token. Please try again.', 'error')
            return redirect(url_for('reset_password'))
        
        # Validate passwords
        if new_password != confirm_password:
            flash('Passwords do not match', 'error')
            return redirect(url_for('reset_password'))
        
        db_session = None
        try:
            db_session = SessionLocal()
            user = db_session.query(User).filter_by(username=username).first()
            
            if not user:
                # For security, don't reveal if username exists or not
                flash('If the username exists, the password has been reset.', 'info')
                session.pop('reset_token', None)
                return redirect(url_for('login'))
            
            # Update password
            user.password = generate_password_hash(new_password)
            db_session.commit()
            
            session.pop('reset_token', None)
            flash('Password reset successful! You can now log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            if db_session:
                db_session.rollback()
            logger.error(f"Password reset error: {str(e)}", exc_info=True)
            flash('An error occurred during password reset. Please try again.', 'error')
            return redirect(url_for('reset_password'))
        finally:
            if db_session:
                db_session.close()
    
    # Generate a secure token for password reset form
    reset_token = secrets.token_hex(32)
    session['reset_token'] = reset_token
    session['reset_token_expiry'] = (datetime.now() + timedelta(minutes=15)).timestamp()
    
    return render_template('reset_password.html', reset_token=reset_token)

@app.route('/dashboard')
@login_required
def dashboard():
    """Display user dashboard with recent submissions"""
    user_id = session.get('user_id')
    
    db_session = None
    try:
        db_session = SessionLocal()
        
        try:
            # Get recent submissions for this user
            past_submissions = db_session.query(CodeSubmission).filter_by(user_id=user_id).order_by(CodeSubmission.timestamp.desc()).limit(5).all()
            return render_template('dashboard.html', past_submissions=past_submissions)
        except Exception as schema_error:
            logger.error(f"Schema error: {schema_error}")
            # If there's a database schema error, fix it
            CodeSubmission.__table__.drop(engine, checkfirst=True)
            Base.metadata.create_all(engine)
            flash('Database schema has been updated. Please submit code to see your submissions.', 'info')
            return render_template('dashboard.html', past_submissions=[])
    except Exception as e:
        logger.error(f"Dashboard error: {str(e)}", exc_info=True)
        flash('An error occurred while loading your dashboard. Please try again.', 'error')
        return redirect(url_for('home'))
    finally:
        if db_session:
            db_session.close()

@app.route('/terms')
def terms():
    """Display terms of service page"""
    return render_template('terms.html')

@app.route('/privacy')
def privacy():
    """Display privacy policy page"""
    return render_template('privacy.html')

@app.route('/submit_code', methods=['POST'])
@login_required
def submit_code():
    """Handle code submission for analysis"""
    code = request.form.get('code')
    if not code:
        flash('Code cannot be empty!', 'danger')
        return redirect(url_for('dashboard'))

    user_id = session.get('user_id')
    db_session = None
    try:
        db_session = SessionLocal()
        
        # Detect programming language
        language = detect_programming_language(code)
        
        # Create submission record with initial status
        submission = CodeSubmission(
            code=code, 
            user_id=user_id, 
            language=language,
            line_analysis="Analysis in progress...",
            restructured_code="Restructuring in progress...",
            grade="Grading in progress..."
        )
        db_session.add(submission)
        db_session.commit()
        
        # Start background processing
        thread = threading.Thread(target=process_code_analysis, args=(submission.id,))
        thread.daemon = True
        thread.start()
        
        flash('Code submitted successfully! Analysis in progress...', 'success')
        return redirect(url_for('view_analysis', submission_id=submission.id))
    except Exception as e:
        if db_session:
            db_session.rollback()
        logger.error(f"Code submission error: {str(e)}", exc_info=True)
        flash(f'Failed to submit code. Error: {e}', 'danger')
        return redirect(url_for('dashboard'))
    finally:
        if db_session:
            db_session.close()

@app.route('/submission_history')
@login_required
def submission_history():
    """Display all submission history for current user"""
    user_id = session.get('user_id')
    if not user_id:
        flash('You must be logged in to view submission history.', 'error')
        return redirect(url_for('login'))
    
    db_session = None
    try:
        db_session = SessionLocal()
        
        # Check if user exists
        user = db_session.query(User).filter_by(id=user_id).first()
        if not user:
            flash('User not found. Please login again.', 'error')
            return redirect(url_for('login'))
        
        # Get all submissions for this user
        try:
            submissions = db_session.query(CodeSubmission).filter_by(user_id=user_id).order_by(CodeSubmission.timestamp.desc()).all()
            return render_template('submission_history.html', submissions=submissions)
        except Exception as schema_error:
            logger.error(f"Schema error in history: {schema_error}")
            flash('There was an issue retrieving your submission history. We\'ve fixed the database schema. Please try again.', 'warning')
            # Fix database schema if needed
            CodeSubmission.__table__.drop(engine, checkfirst=True) 
            Base.metadata.create_all(engine)
            return redirect(url_for('dashboard'))
    except Exception as e:
        logger.error(f"Submission history error: {str(e)}", exc_info=True)
        flash('An error occurred while loading your submission history. Please try again.', 'error')
        return redirect(url_for('dashboard'))
    finally:
        if db_session:
            db_session.close()
@app.route('/analysis/<int:submission_id>')
@login_required
def view_analysis(submission_id):
    user_id = session.get('user_id')
    db_session = None
    try:
        db_session = SessionLocal()
        submission = db_session.query(CodeSubmission).filter_by(id=submission_id, user_id=user_id).first()
        if not submission:
            flash('Submission not found or unauthorized.', 'error')
            return redirect(url_for('dashboard'))
        
        return render_template('analysis.html', submission=submission)
    except Exception as e:
        logger.error(f"View analysis error: {str(e)}", exc_info=True)
        flash('An error occurred while loading the analysis. Please try again.', 'error')
        return redirect(url_for('dashboard'))
    finally:
        if db_session:
            db_session.close()

@app.route('/grade/<int:submission_id>')
@login_required
def view_grade(submission_id):
    user_id = session.get('user_id')
    db_session = None
    try:
        db_session = SessionLocal()
        submission = db_session.query(CodeSubmission).filter_by(id=submission_id, user_id=user_id).first()
        if not submission:
            flash('Submission not found or unauthorized.', 'error')
            return redirect(url_for('dashboard'))

        return render_template('grade.html', submission=submission)
    except Exception as e:
        logger.error(f"View grade error: {str(e)}", exc_info=True)
        flash('An error occurred while loading the grade. Please try again.', 'error')
        return redirect(url_for('dashboard'))
    finally:
        if db_session:
            db_session.close()

@app.route('/improved_code/<int:submission_id>')
@login_required
def view_improved_code(submission_id):
    user_id = session.get('user_id')
    db_session = None
    try:
        db_session = SessionLocal()
        submission = db_session.query(CodeSubmission).filter_by(id=submission_id, user_id=user_id).first()
        if not submission:
            flash('Submission not found or unauthorized.', 'error')
            return redirect(url_for('dashboard'))

        return render_template('improved_code.html', submission=submission)
    except Exception as e:
        logger.error(f"View improved code error: {str(e)}", exc_info=True)
        flash('An error occurred while loading the improved code. Please try again.', 'error')
        return redirect(url_for('dashboard'))
    finally:
        if db_session:
            db_session.close()

@app.route('/refresh_analysis/<int:submission_id>')
@login_required
def refresh_analysis(submission_id):
    """Re-run the analysis on a previously submitted code."""
    user_id = session.get('user_id')
    db_session = None
    try:
        db_session = SessionLocal()
        submission = db_session.query(CodeSubmission).filter_by(id=submission_id, user_id=user_id).first()
        if not submission:
            flash('Submission not found or unauthorized.', 'error')
            return redirect(url_for('dashboard'))

        # Reset analysis fields
        submission.line_analysis = "Analysis in progress..."
        submission.restructured_code = "Restructuring in progress..."
        submission.grade = "Grading in progress..."
        db_session.commit()

        # Start new analysis in a background thread
        thread = threading.Thread(target=process_code_analysis, args=(submission.id,))
        thread.daemon = True
        thread.start()

        flash('Re-analysis started successfully!', 'success')
        return redirect(url_for('view_analysis', submission_id=submission.id))
    except Exception as e:
        logger.error(f"Refresh analysis error: {str(e)}", exc_info=True)
        flash('An error occurred while refreshing the analysis. Please try again.', 'error')
        return redirect(url_for('dashboard'))
    finally:
        if db_session:
            db_session.close()

# Logout Route
@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

# Advanced error handling - add custom error handlers
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def server_error(e):
    logger.error(f"500 error: {str(e)}")
    return render_template('500.html'), 500

# Clean up old or stuck submissions
@app.route('/admin/clean_stuck_submissions', methods=['POST'])
@login_required
def clean_stuck_submissions():
    user_id = session.get('user_id')
    db_session = None
    try:
        db_session = SessionLocal()
        # Check if user is an admin (you'd need to add an admin column to User model)
        user = db_session.query(User).filter_by(id=user_id).first()
        
        # For simplicity, just fix any stuck submissions for the current user
        # In a real app, you'd check if user.is_admin == True
        submissions = db_session.query(CodeSubmission).filter_by(user_id=user_id).all()
        fixed_count = 0
        
        for submission in submissions:
            if "in progress" in submission.line_analysis.lower() or "in progress" in submission.grade.lower():
                # Submission appears stuck
                submission.line_analysis = "Analysis was incomplete - please refresh analysis."
                submission.restructured_code = "Restructuring was incomplete - please refresh analysis."
                submission.grade = "Grading was incomplete - please refresh analysis."
                fixed_count += 1
        
        if fixed_count > 0:
            db_session.commit()
            flash(f'Fixed {fixed_count} stuck submissions. You can now refresh their analysis.', 'success')
        else:
            flash('No stuck submissions found.', 'info')
        
        return redirect(url_for('submission_history'))
    except Exception as e:
        if db_session:
            db_session.rollback()
        logger.error(f"Clean stuck submissions error: {str(e)}", exc_info=True)
        flash('An error occurred while cleaning submissions. Please try again.', 'error')
        return redirect(url_for('dashboard'))
    finally:
        if db_session:
            db_session.close()

# Migration helper for database structure updates
@app.route('/migrate_database', methods=['GET'])
def migrate_database():
    # This should normally be protected by authentication and authorization
    # For demonstration purposes only
    try:
        # Recreate tables safely
        Base.metadata.create_all(engine)
        return jsonify({"status": "success", "message": "Database migrations completed successfully"})
    except Exception as e:
        logger.error(f"Database migration error: {str(e)}", exc_info=True)
        return jsonify({"status": "error", "message": f"Migration failed: {str(e)}"}), 500

# Run Flask App
if __name__ == '__main__':
    # Make sure the database is created before starting
    try:
        Base.metadata.create_all(engine)
        logger.info("Database tables created successfully")
    except Exception as e:
        logger.error(f"Error creating database tables: {str(e)}", exc_info=True)
    
    app.run(debug=True)