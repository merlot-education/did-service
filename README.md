# MERLOT DID Service
The DID service is a microservice in the MERLOT marketplace which handles:
- Provision of a new did:web and a new key pair that can be used for signing and verification.
  - The service manages the did:web along with a generated certificate containing the public key.
- Provision of the DID document for a did:web that the service manages.
  - Currently, the DID document lists one verification method that refers to the generated private key.
- Provision of the certificate associated with a did:web that the service manages.

At the moment, the DID service handles only did:web!

## Development

To start development for the MERLOT marketplace, please refer to [this document](https://github.com/merlot-education/.github/blob/main/Docs/DevEnv.md)
to set up a local WSL development environment of all relevant services.
This is by far the easiest way to get everything up and running locally.

## Structure

```
├── src/main/java/eu/merloteducation/didservice
│   ├── config          # configuration-related components
│   ├── controller      # external REST API controllers
│   ├── models          # internal data models
│   ├── repositories    # DAOs for accessing the stored data
│   ├── service         # internal services for processing data from the controller layer
```

REST API related models such as the DTOs can be found at [models-lib](https://github.com/merlot-education/models-lib/tree/main)
which is shared amongst the microservices.

## Dependencies
- rabbitmq (rabbitmq:3-management)

## Build

To build this microservice you need to provide a GitHub read-only token in order to be able to fetch maven packages from
GitHub. You can create this token at https://github.com/settings/tokens with at least the scope "read:packages".
Then set up your ~/.m2/settings.xml file as follows:

    <settings xmlns="http://maven.apache.org/SETTINGS/1.0.0"
          xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
          xsi:schemaLocation="http://maven.apache.org/SETTINGS/1.0.0
                      http://maven.apache.org/xsd/settings-1.0.0.xsd">

        <servers>
            <server>
                <id>github</id>
                <username>REPLACEME_GITHUB_USER</username>
                <!-- Public token with `read:packages` scope -->
                <password>REPLACEME_GITHUB_TOKEN</password>
            </server>
        </servers>
    </settings>

Afterward you can build the service with

    mvn clean package

## Run

    java -jar target/did-service-X.Y.Z.jar

## Deploy (Docker)

This microservice can be deployed as part of the full MERLOT docker stack at
[localdeployment](https://github.com/merlot-education/localdeployment).

## Deploy (Helm)
### Prerequisites
Before you begin, ensure you have Helm installed and configured to the desired Kubernetes cluster.

### Setting Up Minikube (if needed)
If you don't have a Kubernetes cluster set up, you can use Minikube for local development. Follow these steps to set up Minikube:

1. **Install Minikube:**
   Follow the instructions [here](https://minikube.sigs.k8s.io/docs/start/) to install Minikube on your machine.

2. **Start Minikube:**
   Start Minikube using the following command:
   ```
   minikube start
   ```
3. **Verify Minikube Status:**
   Check the status of Minikube to ensure it's running:   
   ```
   minikube status
   ```

### Usage
1. **Clone the Repository:**
   Clone the repository containing the Helm chart:
   ```
   git clone https://github.com/merlot-education/gitops.git
   ```
   
2. **Navigate to the Helm Chart:**
   Change into the directory of the Helm chart:
   ```
   cd gitops/charts/orchestrator
   ```
   
3. **Customize Values (if needed):**
   If you need to customize any values, modify the values.yaml file in this directory according to your requirements. This file contains configurable parameters such as image repository, tag, service ports, etc. An example containing the values used in Merlot dev environment is available in gitops/environments/dev/didservice-orchestrator.yaml

4. **Install the Chart:**
   Run the following command to install the chart from the local repository:
   ```
   helm install [RELEASE_NAME] .
   ```
   Replace [RELEASE_NAME] with the name you want to give to this deployment. In this case it can be did-service.

5. **Verify Deployment:**
   Check the status of your deployment using the following commands:
   ```
   kubectl get pods
   kubectl get services
   ```
   
### Additional Resources 
- [Helm Documentation](https://helm.sh/docs/)
