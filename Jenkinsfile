
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
		// trivy plugin update aqua
                sh '''
                    export TRIVY_RUN_AS_PLUGIN=aqua
                    export trivyVersion=0.32.0
                    curl -sLO https://github.com/aquasecurity/trivy/releases/download/v${trivyVersion}/trivy_${trivyVersion}_Linux-64bit.deb
                    curl -sLO https://github.com/aquasecurity/trivy/releases/download/v${trivyVersion}/trivy_${trivyVersion}_checksums.txt
                    grep trivy_${trivyVersion}_Linux-64bit.deb trivy_${trivyVersion}_checksums.txt > trivy_${trivyVersion}_Linux-64bit.checksum
                    sha256sum -c trivy_${trivyVersion}_Linux-64bit.checksum
                    sudo dpkg -i trivy_${trivyVersion}_Linux-64bit.deb
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
                usernamePassword(credentialsId: 'jenkinsgithub', usernameVariable: 'GITHUB_USER', passwordVariable: 'GITHUB_TOKEN'), 
                string(credentialsId: 'AQUA_KEY', variable: 'AQUA_KEY'), 
                string(credentialsId: 'AQUA_SECRET', variable: 'AQUA_SECRET')
            ]) {
                // Replace ARTIFACT_PATH with the path to the root folder of your project 
                // or with the name:tag the newly built image
                
                sh '''
                    export BILLY_SERVER=https://prod-aqua-billy.codesec.aquasec.com
            	    curl -sLo install.sh download.codesec.aquasec.com/billy/install.sh
            	    curl -sLo install.sh.checksum https://github.com/argonsecurity/releases/releases/latest/download/install.sh.checksum
		    if ! cat install.sh.checksum | sha256sum ; then
			echo "install.sh checksum failed"
			exit 1
		    fi
		    BINDIR="." sh install.sh
		    rm install.sh install.sh.checksum
                    ./billy generate -v \
                        --aqua-key ${AQUA_KEY} \
                        --aqua-secret ${AQUA_SECRET} \
                        --access-token ${GITHUB_TOKEN} \
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
