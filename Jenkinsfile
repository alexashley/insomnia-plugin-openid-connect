pipeline {
    agent { docker { image 'node:14.13' } }
    stages {
        stage('build') {
            steps {
                sh 'npm --version'
            }
        }
    }
}
