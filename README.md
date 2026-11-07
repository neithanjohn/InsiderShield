# InsiderShield – Insider Threat Detection System

InsiderShield is a web-based insider threat detection prototype that uses **User Behaviour Analytics (UBA)** and machine learning to identify potentially suspicious employee activities in a simulated corporate environment.

The project was developed as a mini project for the Bachelor of Technology in Computer Science and Engineering programme at Viswajyothi College of Engineering and Technology.

## Overview

Traditional security tools mainly focus on threats originating outside an organization. InsiderShield focuses on activities performed by users who already have authorized access to organizational resources.

The system records employee activities, analyses behavioural patterns, assigns risk levels, and notifies the security administrator when suspicious behaviour is detected.

## Key Features

### Employee Portal
- Role-based employee login.
- Simulated corporate workspace for accessing and downloading files.
- Automatic logging of employee activities.
- Records relevant behavioural information such as login time, session duration, file access, downloads, and weekend activity.

### Security Administrator Dashboard
- Restricted administrator login.
- Centralized view of employee activity and risk information.
- Displays anomaly and risk assessment results.
- Alert review, acknowledgement, and dismissal.
- Historical activity monitoring and report generation.

### Machine Learning-Based Detection
- Uses the **Isolation Forest** unsupervised machine learning algorithm to identify unusual behaviour.
- Applies feature extraction and standardization to employee activity data.
- Considers behavioural indicators such as:
  - Unusual or off-hours login activity.
  - High file-access or download frequency.
  - Access to sensitive files.
  - Weekend activity and session patterns.
- Combines machine-learning results with rule-based risk-scoring logic.
- Categorizes alerts into Low, Medium, and High risk levels.

## System Architecture

InsiderShield follows a three-layer web application architecture:

1. **Presentation layer:** HTML, CSS, and JavaScript interfaces for employees and security administrators.
2. **Application layer:** Python Flask backend for authentication, session handling, activity logging, and application logic.
3. **Data and analytics layer:** SQLite database managed through SQLAlchemy, together with the Scikit-learn Isolation Forest model.

### Activity Flow

1. An employee logs in and interacts with the simulated workspace.
2. The application records the employee's activities.
3. Activity records are stored in the SQLite database.
4. The behaviour analysis module extracts features and evaluates activity using Isolation Forest and rule-based scoring.
5. The system stores the analysis results and generates alerts when risk thresholds are met.
6. The security administrator reviews the alerts, risk information, and reports through the dashboard.

## Technology Stack

| Component | Technology |
|---|---|
| Frontend | HTML5, CSS3, JavaScript |
| Backend | Python 3, Flask |
| Database | SQLite |
| ORM | Flask-SQLAlchemy / SQLAlchemy |
| Machine Learning | Scikit-learn |
| Anomaly Detection | Isolation Forest |
| Data Processing | NumPy, Pandas |

## Getting Started

The exact commands may depend on how the project folders are arranged in your local repository. The project contains separate employee and administrator applications, each initialized through its Flask `app.py`.

### Prerequisites

- Python 3
- pip (Python package installer)
- A modern web browser such as Google Chrome or Microsoft Edge
- Git (optional, for cloning the repository)

### 1. Clone the repository

```bash
git clone <YOUR_GITHUB_REPOSITORY_URL>
cd <YOUR_REPOSITORY_FOLDER>
```

### 2. Create and activate a virtual environment

**Windows (Command Prompt):**

```cmd
python -m venv venv
venv\Scripts\activate
```

**Windows (PowerShell):**

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

**Linux / macOS:**

```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install dependencies

If the repository contains a `requirements.txt` file, install the listed dependencies:

```bash
pip install -r requirements.txt
```

If it does not contain one, the main packages identified in the project report are:

```bash
pip install Flask Flask-SQLAlchemy scikit-learn numpy pandas
```

Install any additional packages imported by the application if prompted.

### 4. Run the applications

The project has two Flask applications:

- **Employee Portal:** Run the `app.py` belonging to the employee application.
- **Administrator Dashboard:** Run the `app.py` belonging to the administrator application.

Open a terminal in the directory containing the relevant `app.py` and execute:

```bash
python app.py
```

Run the two applications in separate terminals if they are intended to operate simultaneously. Open the local URL printed by Flask in your browser.

> **Note:** The repository's actual folder names, port numbers, and local URLs should be followed. They are not specified here because they depend on the checked-in application configuration.

## Database Initialization and Demo Data

As described in the project report, application initialization connects to the SQLite database through SQLAlchemy. If the database has no existing records, the database seeding process can create an administrator profile, employee profiles, baseline activity records, and simulated anomalous activity.

The demo data is intended to demonstrate the behaviour-analysis and alert-generation workflow. It should not be treated as real organizational activity.

## Project Scope and Limitations

- The current implementation operates in a **simulated organizational environment**.
- Monitoring is limited to actions performed within the application.
- It does not install native endpoint agents or perform keylogging or screen recording.
- It is a detection and alerting prototype; it does not automatically block accounts, revoke permissions, or terminate network connections.
- The system is not presented as a production-ready enterprise security platform.

## Future Enhancements

Possible extensions identified for the project include:

- Integration with real organizational systems and activity sources.
- Evaluation of additional machine learning and deep learning models.
- Inclusion of network traffic and device-usage behavioural features.
- Integration with cloud platforms and Security Information and Event Management (SIEM) tools.
- Improvements to scalability and reduction of false-positive alerts.

## Project Team

| Name | Register Number |
|---|---|
| Neithan Benoy John | VJC23CS148 |
| Anoop Job Augustin | VJC23CS038 |
| Nevin Davis Joshy | VJC23CS149 |

**Project Guide:** Mrs. Kala O S  
**Department:** Computer Science and Engineering  
**Institution:** Viswajyothi College of Engineering and Technology, Vazhakulam  
**Academic Year:** 2025–2026

## Disclaimer

InsiderShield is an academic mini-project prototype developed for educational and demonstration purposes. Its alerts indicate potentially anomalous activity and should be reviewed by an authorized security administrator. An anomaly does not, by itself, prove malicious intent.

## License

No license has been specified for this repository. Unless a license is added, the project should be treated as having all rights reserved by its contributors.
