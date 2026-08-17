// Jenkinsfile — EvidenceTool CI
//
// Runs the test suite in an isolated, disposable Docker agent — never
// directly on a Jenkins agent that shares a host with a real diagnosed
// service. The test suite itself needs no root/sudo: all TLS fixtures
// are generated under pytest's tmp_path, and SSH transport is fully
// mocked (see tests/test_ssh_transport.py) — nothing here ever touches
// a real /etc/nginx, a real systemd, or a real network socket.
 
pipeline {
    agent any
 
    options {
        timeout(time: 15, unit: 'MINUTES')
        disableConcurrentBuilds()
    }
 
    stages {
        stage('Python CI Suite') {
            agent {
                docker {
                    image 'python:3.12-slim'
                    // Pin the interpreter explicitly. This project has already
                    // been run across 3.10 (VPS, Ubuntu jammy) and 3.12
                    // (development) without incident, but CI should test one
                    // known-good version deterministically rather than whatever
                    // happens to be on the Jenkins host.
                    args '-u root:root'
                }
            }
            stages {
                stage('Install') {
                    steps {
                        sh '''
                            python -m venv /tmp/venv
                            . /tmp/venv/bin/activate
                            pip install --upgrade pip setuptools wheel
                            pip install --no-cache-dir -e ".[dev,test]"
                        '''
                    }
                }
         
                stage('Code Quality (Ruff)') {
                    steps {
                        sh '''
                            . /tmp/venv/bin/activate
                            ruff check src/ tests/
                        '''
                    }
                }

                stage('Type Checking (Mypy)') {
                    steps {
                        sh '''
                            . /tmp/venv/bin/activate
                            mypy src/
                        '''
                    }
                }

                stage('Security (Bandit SAST)') {
                    steps {
                        sh '''
                            . /tmp/venv/bin/activate
                            bandit -r src/ -c pyproject.toml
                        '''
                    }
                }

                stage('Security (pip-audit SCA)') {
                    steps {
                        sh '''
                            . /tmp/venv/bin/activate
                            pip-audit
                        '''
                    }
                }
         
                stage('Test & Coverage (Pytest)') {
                    steps {
                        sh '''
                            . /tmp/venv/bin/activate
                            pytest tests/ -v --junitxml=test-results.xml --cov=evidencetool --cov-report=xml
                        '''
                    }
                }
            }
        }

        stage('E2E Operational Tests') {
            // No docker agent here; runs directly on the Jenkins host machine
            // to execute Docker commands and spin up the systemd container.
            steps {
                sh 'bash tests/e2e/run.sh'
            }
        }
    }
 
    post {
        always {
            junit 'test-results.xml'
        }
        failure {
            echo 'Build failed — main should not be considered green until this is fixed.'
        }
    }
}
