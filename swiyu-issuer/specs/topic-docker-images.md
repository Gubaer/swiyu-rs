For the time being, there are two main stakeholders to be supported:
* developer - a person who actively contributes to `swiyu-issuer`, by designing, coding, and testing
* explor - a person who wan't to learn about `swiyu-issuer`, or about the SWIYU ecosystem, by running experiments with `swiyu-issuer`

# role *developer* 
We currently support developers with docker images:
* the developer can and will clone the repo
* the developer can and will install the required tools to develop with rust 
* the developer can and will build the dev docker images
```bash
docker compose build --build
```
* the developer can and will start the dev docker images to run tests against them
```bash
docker compose up -d
```

However, good support for explorers is currently missing. Explorers
* do not or cannot locally install the rust tooling
* do not or cannot clone the `swiyu-issuer` git repo 

Explorers should be able:
1. to download a dedicated docker compose file
2. to download a .env.example file 
3. to read instructions on 
   * how to onboard a sample business entity
   * how to save the DEV_TENANT_* env variables 
2. lauch the runtime environment with the `swiyu-issuer-mgmtapi`, `swiyu-issuer-oidcapi`, database and hashicorp vault 
    * using docker compose
    * docker compose should download prebuild docker images from the github docker image repository
    

