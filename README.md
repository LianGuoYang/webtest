# **CloudsineAI: WebTest Take-Home Assignment**

*"Clean code always looks like it was written by someone who cares."*  
— **Robert C. Martin**, *Author of Clean Code*

Welcome to the CloudsineAI take-home assignment! This project will help us evaluate your coding skills, problem-solving abilities, and design process. Let's get started!

---

## **Objective**
The goal of this assignment is to create a functional web application with GenAI hosted on **AWS EC2**. The application will integrate with the VirusTotal API to securely upload and scan files for malware or viruses.  Integrate with a free GenAI app such as Gemini API to explain the results to a lay end user.  

---

## **Features**
1. **File Upload and Scanning**: Build a web interface that allows users to upload files and scan them using the [VirusTotal API](https://docs.virustotal.com/reference/overview).
2. **Result Display**: Present the scan results dynamically and clearly on the webpage.
3. **GenAI Integration**: Integrate with a LLM to explain the results to a lay end user
4. **Customizable Design**: Add enhancements or optimizations to showcase your skills.

---

## **Assignment Steps**

### **Step 1: Set Up the Web Server on EC2**
1. Launch an **AWS EC2 instance** to host your web application:
   - Choose an appropriate instance type (e.g., t2.micro under the free tier) and configure the security group for web traffic (HTTP/HTTPS).  
   - Install and configure your preferred web server software, such as **Apache**, **NGINX**, or any other of your choice.
2. Ensure the instance is properly configured and accessible for hosting the web application.

---

### **Step 2: Develop the Web Application**
1. **Core Functionality**:
   - Implement a **file upload** feature with basic validation (e.g., file size/type).
   - Integrate with the VirusTotal API to scan the uploaded files.
   - Dynamically display the scan results on the webpage.
2. **Preferred Programming Languages**:
   - While **Golang** or **Python** are preferred, you may use any language or framework you are comfortable with.
3. **Security Considerations**:
   - Handle file uploads securely to prevent malicious file execution.
   - Sanitize API requests and responses.

---

### **Step 3: Test with Sample Files**
1. Use the provided sample files in this repository to test your application.
2. Verify that the scan results are displayed correctly after processing by the VirusTotal API.

---

## **Example Workflow**
1. A user uploads a file through the web interface.
2. The file is sent to the VirusTotal API for scanning.  
3. The API processes the file and returns the results.  
4. The scan results are displayed on the webpage in a user-friendly format.
5. Include a button where the GenAI can elaborate on the scan results to a lay end user.

---

## **Bonus Section: Optional Enhancements**
Go the extra mile by implementing one or both of the following:

### **1. Dockerization**
- Create separate **Dockerfiles** for development and production environments.
- Use **Docker Compose** to manage multi-container setups (e.g., integrating a PostgreSQL database).
- Optimize image sizes and configurations for faster deployments.

### **2. CI/CD Pipeline**
- Automate testing and deployments using a CI/CD pipeline (e.g., GitHub Actions or AWS CodePipeline).
- Include integration tests to ensure file uploads and VirusTotal API calls function correctly.
- Securely manage environment variables and secrets using tools like AWS Secrets Manager.

---

## **Evaluation Criteria**
You are free to use AI code assistants such as Cursor and Claude Code.  However, you are expected to be able to understand and explain most of the code.  

Your submission will be assessed on:
1. **Functionality**: Does the application meet the core requirements?  
2. **Code Quality**: Is the code modular, maintainable, and well-documented?  
3. **Problem-Solving**: How effectively did you address challenges and errors?  
4. **Creativity**: Did you add enhancements or optimizations to improve the application?  
5. **Presentation**: Is the solution polished and user-friendly?  

---

## **Resources**
- [AWS EC2 Getting Started Guide](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/get-set-up-for-amazon-ec2.html)  
- [VirusTotal API Documentation](https://docs.virustotal.com/reference/overview)  
- [PostgreSQL Quick Start Guide](https://www.postgresql.org/docs/current/tutorial.html)  
- [Gemini API Docs] https://ai.google.dev/gemini-api/docs
---

## **Submission Requirements**
1. **Documentation**:
   - Provide a detailed README explaining your setup process, challenges, and solutions.  
2. **Source Code**:
   - Share your codebase with clear instructions for running the application.  
3. **Deployment**:
   - Host your application on AWS EC2 and provide access for review.  
4. **Discussion**:
   - Be prepared to discuss your design choices, challenges faced, and any enhancements implemented.

---

## **Getting Started**
1. Clone this repository and review the provided sample files.  
2. Set up your AWS EC2 instance and deploy the web application.  
3. Test the file upload and VirusTotal integration locally before deploying it to AWS.

---

We look forward to seeing your innovative solutions and thoughtful designs!  
**CloudsineAI Team**  

---

---

# VirusTotal + Gemini AI File Scanner

## Overview
This project is a cloud-native web application built with Golang that scans uploaded files using the VirusTotal API and generates structured, human-readable security explanations using Google Gemini AI.

The application is containerized with Docker, deployed on AWS EC2, and integrated with a CI/CD pipeline via GitHub Actions. It is designed with security, scalability, and maintainability in mind.



---

## Features
* **Secure File Upload**: Supports files up to 650MB with strict server-side validation.
* **Large File Handling**: Automatically switches between `/files` (≤32MB) and `/files/upload_url` (>32MB) endpoints.
* **Efficient Scanning**: Performs SHA256 hash lookup before upload to avoid redundant submissions.
* **AI Interpretation**: Generates structured, user-friendly explanations via Gemini.
* **Modern UI**: Dynamic rendering with detection breakdown and scan history sidebar.
* **Cloud-Ready Deployment**: Dockerized application with AWS Secrets Manager integration.
* **Resilient Design**: Graceful handling of API rate limits (HTTP 429) and upload timeouts.
* **Automated Delivery**: CI/CD pipeline via GitHub Actions with auto-deploy on push to `main`.


---

## Architecture

### Frontend
* HTML5, CSS3, and JavaScript (Vanilla).
* Dynamic result rendering with risk-based color indicators.
* Persistent scan history panel for the session.

### Backend
* **Golang** HTTP server for high-performance concurrency.
* Secure multipart file handling with disk-based streaming for memory safety.
* SHA256 hashing for efficient VirusTotal lookup optimization.
* Integration with VirusTotal and Gemini REST APIs.

### Infrastructure
* **AWS EC2 (Ubuntu)**: Reliable hosting environment.
* **Docker**: Consistent container runtime.
* **Networking**: Elastic IP and Security Groups (Ports 80/22).
* **Security**: IAM Roles for secure access to Secrets Manager.
* **Github Actions**: Continuous Integration & Deployment pipeline.

---

## Project Structure
```text
.
├── .github/
│   └── workflows/
│       ├── ci.yml             # CI/CD pipeline
│       └── deploy.yml         # Deployment workflow
├── main.go                    # Server entry point
├── handler.go                 # Request/Response logic
├── virustotal.go              # VirusTotal API client
├── gemini.go                  # Gemini AI integration
├── utils.go                   # Hashing and validation helpers
├── page.go                    # HTML template rendering
├── Dockerfile                 # Container configuration
├── go.mod                     # Dependency management
└── README.md                  # Project documentation

```

## Request Flow

1. User uploads file via web interface.
2. Server computes SHA256 hash.
3. Server queries VirusTotal for existing analysis.
4. If report not found:
   - <=32MB → Upload via /files
   - >32MB → Obtain /files/upload_url and upload there
5. Server polls /analyses/{id} until completion.
6. Detection statistics extracted.
7. Gemini generates structured explanation.
8. JSON response returned to frontend.

## Live Deployment

The application is publicly accessible at:

[http://18.142.78.188](http://18.142.78.188)
(Note: HTTP only for demonstration purposes. HTTPS is recommended for production.)

---

### Hosting Details

The application is deployed on an AWS EC2 Ubuntu instance

- Docker container runtime
- Elastic IP attached
- Port **80** exposed via Security Group
- Automatic container restart policy enabled
- CI/CD pipeline with auto-deployment on push to `main`

---

## Local Setup Guide

### Prerequisites

Ensure the following are installed:

- **Go 1.25** or later
- **Docker** (optional, for containerized execution)
- **VirusTotal API key**
- **Gemini API key**

---

## Option 1 — Run Locally (Without Docker)

### 1. Clone the Repository

```bash
git clone https://github.com/your-username/your-repository.git
cd your-repository
````

### 2. Create Environment File

Create a file named `.env` in the project root:

```env
VT_API_KEY=your_virustotal_api_key
GEMINI_API_KEY=your_gemini_api_key
```

### 3. Install Dependencies

```bash
go mod tidy
```

### 4. Run the Application

```bash
go run main.go
```

### 5. Access the Server

The server will start at:

```
http://localhost:8080
```

---

## Option 2 — Run Using Docker

### 1. Build Docker Image

```bash
docker build -t virustotal-scanner .
```

### 2. Run the Container

```bash
docker run -p 8080:8080 --env-file .env virustotal-scanner
```

### 3. Access the Server

```
http://localhost:8080
```

## Limitations

- VirusTotal and Gemini free-tier rate limits apply.
- Files larger than 200MB may experience longer analysis times.
- Polling is synchronous and may block the request for several minutes during large scans.
- HTTPS is not enabled in the current deployment (recommended for production use).

## Security Considerations

- API keys are never stored in source code.
- AWS IAM Roles used instead of hardcoded credentials.
- Temporary files are automatically deleted after processing.
- Server-side upload size limits enforced to prevent abuse.
- Errors are sanitized before returning to clients.

## Challenges Faced

- Designed memory-safe large file uploads (≤32MB vs >32MB endpoint switching).
- Implemented asynchronous VirusTotal polling with timeout handling.
- Managed API rate limits (HTTP 429) with graceful error handling.
- Configured secure AWS EC2 deployment with IAM-based secrets management.
- Automated build and deployment using GitHub Actions CI/CD.
- Resolved GitHub large-file push rejections and cleaned commit history.
