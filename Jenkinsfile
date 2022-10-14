
timestamps {
	node(){
        checkout scm
        stage("Preparation"){
            sh '''
                find .
                printenv | sort
            '''
        }
        stage('Security check by Aqua') {
            withCredentials([
                string(credentialsId: 'AQUA_KEY', variable: 'AQUA_KEY'), 
                string(credentialsId: 'AQUA_SECRET', variable: 'AQUA_SECRET')
            ]) {

                sh '''
                    if [ "${gitlabMergeRequestState}" = "opened" ]; then
                        SCM_TRIGGER="PR"
                    else
                        SCM_TRIGGER="PUSH"
                    fi
                    export TRIGGERED_BY=${SCM_TRIGGER}
                    echo ${TRIGGERED_BY}
                    export TRIVY_RUN_AS_PLUGIN=aqua
                    export trivyVersion=0.30.4
                    curl -sLO https://github.com/aquasecurity/trivy/releases/download/v${trivyVersion}/trivy_${trivyVersion}_Linux-64bit.deb
                    curl -sLO https://github.com/aquasecurity/trivy/releases/download/v${trivyVersion}/trivy_${trivyVersion}_checksums.txt
                    grep trivy_${trivyVersion}_Linux-64bit.deb trivy_${trivyVersion}_checksums.txt > trivy_${trivyVersion}_Linux-64bit.checksum
                    sha256sum -c trivy_${trivyVersion}_Linux-64bit.checksum
                    dpkg -i trivy_${trivyVersion}_Linux-64bit.deb
                    trivy plugin update aqua
                    trivy fs --debug --format template --template "@Report-Templates/aqua.tpl" -o report.html --security-checks config,vuln,secret .

                '''
            }
        }
        stage('Build Docker Image') {
            // fake build by downloading an image
            sh '''
                docker pull aquasaemea/mynodejs-app:1.0
            '''
        }
        stage('Manifest Generation') {
            withCredentials([
                // Replace GITLAB_CREDENTIALS_ID with the id of your gitlab credentials
                usernamePassword(credentialsId: 'jenkins2gitlab', usernameVariable: 'GITLAB_USER', passwordVariable: 'GITLAB_TOKEN'), 
                string(credentialsId: 'AQUA_KEY', variable: 'AQUA_KEY'), 
                string(credentialsId: 'AQUA_SECRET', variable: 'AQUA_SECRET')
            ]) {
                // Replace ARTIFACT_PATH with the path to the root folder of your project 
                // or with the name:tag the newly built image
                
                sh '''
                    curl -sLo install.sh download.codesec.aquasec.com/billy/install.sh
                    curl -sLo install.sh.checksum https://github.com/argonsecurity/releases/releases/latest/download/install.sh.checksum
                    if ! cat install.sh.checksum | shasum -a 256 ; then
                        echo "install.sh checksum failed"
                        exit 1
                    fi
                    sh install.sh
                    rm install.sh install.sh.checksum
                    /usr/local/bin/billy generate -v \
                        --aqua-key ${AQUA_KEY} \
                        --aqua-secret ${AQUA_SECRET} \
                        --access-token ${GITLAB_TOKEN} \
                        --artifact-path "aquasaemea/mynodejs-app:1.0"

                        # The docker image name:tag of the newly built image
                        # --artifact-path "my-image-name:my-image-tag" 
                        # OR the path to the root folder of your project. I.e my-repo/my-app 
                        # --artifact-path "ARTIFACT_PATH"
                '''
            }
        }
    }
}
