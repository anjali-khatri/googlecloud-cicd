#!/bin/bash

#This script should only be run ONE TIME.
#It creates binary authorization attestor, associated attestor note, IAM policy assignment for that attestor, the associated keys to the attestor, and a custom binary authorization policy that can be assigned either to a GKE cluster or Kubernetes namespace.
#Author: Anjali Khatri

#List of all variables used in the script

#GCP Project Logistics
LOCATION=us-central1
PROJECT_ID=anjali-cicd
PROJECT_NUMBER=$(gcloud projects describe "${PROJECT_ID}" --format='value(projectNumber)')
CLOUD_BUILD_SA_EMAIL="${PROJECT_NUMBER}@cloudbuild.gserviceaccount.com"
BINAUTHZ_SA_EMAIL="service-${PROJECT_NUMBER}@gcp-sa-binaryauthorization.iam.gserviceaccount.com"

#Container Image stored in Artifact Registry
REPO_NAME=vuln-image-list
IMAGE=vuln-image
TAG=latest
CONTAINER_PATH=$LOCATION-docker.pkg.dev/$PROJECT_ID/$REPO_NAME/$IMAGE:$TAG
DIGEST_CONTAINER_PATH=$LOCATION-docker.pkg.dev/$PROJECT_ID/$REPO_NAME/$IMAGE
DIGEST=$(gcloud container images describe ${CONTAINER_PATH} --format='get(image_summary.digest)')
CONTAINER_IMAGE_DIGEST_PATH=${DIGEST_CONTAINER_PATH}@${DIGEST}

#Binary Authorization Attestor
ATTESTOR_ID=cb-attestor
NOTE_ID=cb-attestor-note

#KMS Key Details
KEY_LOCATION=global
KEYRING=vuln-keys
KEY_NAME=cd-blog-key
KEY_VERSION=1

#GKE Cluster that will be allowed deployed via Binary Authorization
GKE_NS=workingimages

GKE_Test_Cluster_Name=test
GKE_Staging_Cluster_Name=staging
GKE_Prod_Cluster_Name=prod

GKE_BA_Policy_Staging=$LOCATION.$GKE_Staging_Cluster_Name
GKE_BA_Policy_Prod=$LOCATION.$GKE_Prod_Cluster_Name

GKE_Test_Cluster_Config=gke_${PROJECT_ID}_${LOCATION}_${GKE_Test_Cluster_Name}
GKE_Staging_Cluster_Config=gke_${PROJECT_ID}_${LOCATION}_${GKE_Staging_Cluster_Name}
GKE_Prod_Cluster_Config=gke_${PROJECT_ID}_${LOCATION}_${GKE_Prod_Cluster_Name}

#Create GKE Cluster Configurations 
gcloud container clusters get-credentials $GKE_Test_Cluster_Name --region=$LOCATION
gcloud container clusters get-credentials $GKE_Staging_Cluster_Name --region=$LOCATION
gcloud container clusters get-credentials $GKE_Prod_Cluster_Name --region=$LOCATION

#Apply the new binary authorization policy
#gcloud container binauthz policy import scripts/require_binauthz_gkecluster_policy.yaml

curl "https://containeranalysis.googleapis.com/v1/projects/${PROJECT_ID}/notes/?noteId=${NOTE_ID}" \
  --request "POST" \
  --header "Content-Type: application/json" \
  --header "Authorization: Bearer $(gcloud auth print-access-token)" \
  --header "X-Goog-User-Project: ${PROJECT_ID}" \
  --data-binary @- <<EOF
    {
      "name": "projects/${PROJECT_ID}/notes/${NOTE-ID}",
      "attestation": {
        "hint": {
          "human_readable_name": "Attestor Note is Created, Requires an attestor"
        }
      }
    }
EOF

#curl -vvv -H "Authorization: Bearer $(gcloud auth print-access-token)" "https://containeranalysis.googleapis.com/v1/projects/${PROJECT_ID}/notes/${NOTE_ID}"

#Create attestor and attach to the Container Analysis Note created in the step above
gcloud container binauthz attestors create $ATTESTOR_ID \
    --attestation-authority-note=$NOTE_ID \
    --attestation-authority-note-project=${PROJECT_ID}

#Validate the note is registered with attestor
gcloud container binauthz attestors list



#Before you can use this attestor, you must grant Binary Authorization the appropriate permissions to view the Container Analysis Note you created.
#OPTIONAL: If the required permission already exists, you can skip this step.
#Use the following script to create a Container Analysis IAM JSON request:
#Make a curl request to grant the necessary IAM role

curl "https://containeranalysis.googleapis.com/v1/projects/${PROJECT_ID}/notes/${NOTE_ID}:setIamPolicy" \
  --request "POST" \
  --header "Content-Type: application/json" \
  --header "Authorization: Bearer $(gcloud auth print-access-token)" \
  --header "x-goog-user-project: ${PROJECT_ID}" \
  --data-binary @- <<EOF
    {
      'resource': 'projects/${PROJECT_ID}/notes/${NOTE_ID}',
      'policy': {
        'bindings': [
          {
          'role': 'roles/containeranalysis.notes.occurrences.viewer',
          'members': [
            'serviceAccount:${BINAUTHZ_SA_EMAIL}'
            ]
          }
        ]
      }
    }
EOF

#Enable Cloud KMS API
gcloud services enable --project "${PROJECT_ID}" cloudkms.googleapis.com

#Before you can use this attestor, your authority needs to create a cryptographic key pair that can be used to sign container images.
#OPTIONAL: Create a keyring to hold a set of keys, if the key ring already exists, skip this step.
#gcloud kms keyrings create "${KEYRING}" --location="${KEY_LOCATION}"

#Create a new asymmetric signing key pair for the attestor
#OPTIONAL: Crate a key name that will be assigned to the above key ring. If the key already exists, skip this step.
#gcloud kms keys create "${KEY_NAME}" --keyring="${KEYRING}" --location="${KEY_LOCATION}" --purpose asymmetric-signing --default-algorithm="ec-sign-p256-sha256"

#Now, associate the key with your authority through the gcloud binauthz command:


gcloud beta container binauthz attestors public-keys add  \
    --attestor="${ATTESTOR_ID}"  \
    --keyversion-project="${PROJECT_ID}"  \
    --keyversion-location="${KEY_LOCATION}" \
    --keyversion-keyring="${KEYRING}" \
    --keyversion-key="${KEY_NAME}" \
    --keyversion="${KEY_VERSION}"

#Print the list of attestors, you should now see a key registered:

gcloud container binauthz attestors list

#Next, sign the attestor with the specific container image path in artifact registry. This command simply takes in the details of the key you want to use for signing, and the specific container image you want to approve

gcloud beta container binauthz attestations sign-and-create  \
    --artifact-url="${CONTAINER_IMAGE_DIGEST_PATH}" \
    --attestor="${ATTESTOR_ID}" \
    --attestor-project="${PROJECT_ID}" \
    --keyversion-project="${PROJECT_ID}" \
    --keyversion-location="${KEY_LOCATION}" \
    --keyversion-keyring="${KEYRING}" \
    --keyversion-key="${KEY_NAME}" \
    --keyversion="${KEY_VERSION}"

#To ensure everything worked as expected, you can list your attestations and the key that's assigned to that attestor for verification

gcloud container binauthz attestations list \
   --attestor=$ATTESTOR_ID --attestor-project=${PROJECT_ID}

curl "https://binaryauthorization.googleapis.com/v1/projects/${PROJECT_ID}/policy" \
    -X PUT \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $(gcloud auth application-default print-access-token)" \
    -H "x-goog-user-project: ${PROJECT_ID}" \
    --data-binary @- <<EOF 
    {
      "globalPolicyEvaluationMode": "ENABLE",
      "defaultAdmissionRule": {
          "enforcementMode": "ENFORCED_BLOCK_AND_AUDIT_LOG",
          "evaluationMode": "ALWAYS_DENY"
      },
      "clusterAdmissionRules": {
          "${GKE_BA_Policy_Staging}": {
            "enforcementMode": "ENFORCED_BLOCK_AND_AUDIT_LOG",
            "evaluationMode": "REQUIRE_ATTESTATION",
            "requireAttestationsBy": [
                "projects/${PROJECT_ID}/attestors/${ATTESTOR_ID}"
            ]
          },
          "${GKE_BA_Policy_Prod}": {
            "enforcementMode": "ENFORCED_BLOCK_AND_AUDIT_LOG",
            "evaluationMode": "REQUIRE_ATTESTATION",
            "requireAttestationsBy": [
                "projects/${PROJECT_ID}/attestors/${ATTESTOR_ID}"
            ]
          }
      },
      "name": "projects/${PROJECT_ID}/policy"
    }
EOF