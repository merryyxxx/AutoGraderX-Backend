# AutoGraderX

AutoGraderX is an AI-powered code analysis and grading application that helps users improve their programming skills through automated feedback, code restructuring, and quality assessment.

## Features

- **AI-Powered Code Analysis**: Get detailed explanations of what your code does and how it works
- **Code Restructuring**: Receive suggestions on how to improve your code's readability, maintainability, and efficiency
- **Automated Grading**: Get a letter grade (A-F) with concise feedback on your code quality
- **Multi-Language Support**: Automatic detection of Python, JavaScript, Java, and C++
- **User Authentication**: Secure login and registration system with password reset functionality
- **Submission History**: Track your progress over time by viewing past submissions
- **Real-time Analysis Status**: Monitor the progress of your code analysis with status updates

## Technology Stack

- **Backend**: Flask (Python web framework)
- **Database**: SQLAlchemy ORM with SQLite (configurable for other databases)
- **AI Integration**: Google's Gemini 1.5 Pro API for code analysis
- **Authentication**: Werkzeug security for password hashing
- **Frontend**: HTML/CSS/JavaScript (templates not included in this repository)

## Installation

### Prerequisites

- Python 3.8 or higher
- pip (Python package manager)
- Google Gemini API key

### Setup

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/autograderx.git
   cd autograderx
   ```

2. Create a virtual environment:
   ```
   python -m venv venv
   source venv/bin/activate  # On Windows, use: venv\Scripts\activate
   ```

3. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

4. Create a `.env` file in the root directory with the following content:
   ```
   FLASK_APP=app.py
   FLASK_ENV=development
   SECRET_KEY=your_secure_secret_key
   DATABASE_URL=sqlite:///codeapp.db
   GEMINI_API_KEY=your_gemini_api_key
   ```

   Replace `your_secure_secret_key` with a randomly generated key and `your_gemini_api_key` with your actual Google Gemini API key.

5. Create the database:
   ```
   python -c "from app import Base, engine; Base.metadata.create_all(engine)"
   ```

## Usage

1. Start the Flask development server:
   ```
   flask run
   ```

2. Access the application in your web browser at `http://127.0.0.1:5000/`

3. Register a new account or log in with existing credentials

4. Submit code for analysis from the dashboard

5. View detailed analysis results, improved code suggestions, and overall grade

## Application Structure

- **User Authentication**: Registration, login, and password reset functionality
- **Dashboard**: Central hub for submitting code and viewing recent submissions
- **Code Analysis**: Detailed breakdown of what your code does
- **Code Improvement**: AI-generated suggestions for code optimization
- **Grading**: Letter grade assessment with concise feedback
- **Submission History**: Access to all previous submissions and analyses

## Environment Variables

- `SECRET_KEY`: Secret key for securing session data
- `DATABASE_URL`: Database connection string (defaults to SQLite if not specified)
- `GEMINI_API_KEY`: API key for Google's Gemini AI service
- `FLASK_APP`: Points to the main application file
- `FLASK_ENV`: Set to `development` for development features or `production` for deployment

## API Endpoints

### Public Endpoints

- `/` - Home/landing page
- `/login` - User login
- `/register` - New user registration
- `/reset_password` - Password reset functionality
- `/health` - API health check
- `/terms` - Terms of service
- `/privacy` - Privacy policy

### Protected Endpoints (Require Login)

- `/dashboard` - User dashboard with recent submissions
- `/submit_code` - Submit code for analysis
- `/submission_history` - View all previous submissions
- `/analysis/<submission_id>` - View detailed code analysis
- `/grade/<submission_id>` - View code grade and feedback
- `/improved_code/<submission_id>` - View restructured code suggestions
- `/refresh_analysis/<submission_id>` - Re-run analysis on existing submission
- `/check_analysis_status/<submission_id>` - Check status of ongoing analysis

## Maintenance

- `/admin/clean_stuck_submissions` - Admin endpoint to fix stuck submissions
- `/migrate_database` - Update database structure (for development)

## Development

### Debugging

Run the application in debug mode:
```
python app.py
```

### Database Management

The application uses SQLAlchemy ORM with models for:
- `User`: Stores user credentials
- `CodeSubmission`: Stores code submissions and analysis results

### Code Analysis Process

1. Code is submitted via the `/submit_code` endpoint
2. Language detection identifies the programming language
3. Code is split into chunks if necessary for better analysis
4. A background thread processes the analysis in three steps:
   - Line-by-line analysis of what the code does
   - Restructuring/improvement suggestions
   - Overall quality grading
5. Results are stored in the database and displayed to the user

## License

[Insert your chosen license here]

## Contributing

[Insert contribution guidelines here]

## Acknowledgements

- Google Gemini API for AI code analysis
- Flask and SQLAlchemy for the web framework and ORM
- Programming motivational quotes included from various sources
