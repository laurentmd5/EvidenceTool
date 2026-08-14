// Jenkinsfile — EvidenceTool CI
//
// Runs the test suite in an isolated, disposable Docker agent — never
// directly on a Jenkins agent that shares a host with a real diagnosed
// service. The test suite itself needs no root/sudo: all TLS fixtures
// are generated under pytest's tmp_path, and SSH transport is fully
// mocked (see tests/test_ssh_transport.py) — nothing here ever touches
// a real /etc/nginx, a real systemd, or a real network socket.
 
pipeline {
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
 
    options {
        timeout(time: 10, unit: 'MINUTES')
        disableConcurrentBuilds()
    }
 
    stages {
        stage('Install') {
            steps {
                sh '''
                    python -m venv /tmp/venv
                    . /tmp/venv/bin/activate
                    pip install --no-cache-dir -e . pytest
                '''
            }
        }
 
        stage('Test') {
            steps {
                sh '''
                    . /tmp/venv/bin/activate
                    pytest tests/ -v --junitxml=test-results.xml
                '''
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
