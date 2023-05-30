# 1. Preface

Federation in this context means that multiple ("subscription" or "federated") context brokers can be accessed from federation (main) context broker. This particular feature is implemented in NEC's [Scorpio](https://github.com/ScorpioBroker) NGSI-LD Context Broker. This is a powerful feature, when you have information in several brokers, and you want to get that information with one single query. This federation mechanism does not how ever alone address some of the issues with data sovergnity; for that we need a authorization and authentication layer and that is where [i4Trust](https://i4trust.org/) data space tehcnology comes into play.

Technically the request made to federation context broker will be forwarded to subscription context brokers if they are registered in federation broker with Context Source Registrations (CSourceRegistration). While requesting entities from brokers, Authentication & Authorization components checks the request with iSHARE functions which checks the iSHARE policies from iSHARE Satellite & Authorization Registry.

![federated broker](./pictures/weather.png)

![ODALA](./pictures/odala.png)
![Contrasec](./pictures/contrasec.jpg)
<img src="./pictures/i4trust.png" width=33% height=33%>

## 1.2 Federation and Authentication & Authorization

With federation alone, you can simply connect the brokers and they implicitly trust eachother and will transfer the data when requested; they have no access control. We need a solution for that. During the project execution, we avaluated several options and i4Trust was selected. One of the reasons for selection was a clear roadmap from the then used components (Umbrella and Keyrock) to the i4Trust framework. In addition, the iSHARE tehcnology was proven in industry.

We have implemented i4Trust's authorization and identification scheme on top of the Scorpio federation. This way the data owners have control over who can access what data, and this paves the way towards being Data Spaces and GAIA-X compatible.

![Endpoint Auth Service flow](./pictures/endpoint01.png)

# 2 Broker-Federation demo application

To demonstrate the functionality of the solutions, we have deployed a [demo application](https://i4trust.staging.odala.kiel.de/) which is deployed to Kiel. 


## 2.1 What this application do exactly?

![Application](./pictures/homepage.png)

This application is used to fetch entities and authenticate & authorize user with Keyrock IDM's OAuth2 i4trust functions and iSHARE policies.

The application is simple but secure due to backend/frontend scheme. The backend server handles authentication & authorization functions while frontend is used to login and search entities from Scorpio brokers.

Here is a [demo video](https://youtu.be/KAc9PRu56Ig). It's awesome!


## 3.1. Application functions

### 3.1.1. Registering application into Keyrock IDM

Registering application is made in application's /auth path. When /auth is requested, backend server posts a request into Keyrock IDM with JSON which contains needed information for registering into Keyrock IDM.

```
{
     'response_type':'code',
     'client_id': provider_client_id,
     'redirect_uri': keyrock_redirect_url,
     'scope': 'iSHARE',
     'request': make_jwt()
}
```

![Registered page](./pictures/registered.png)

If registering the application was succesful, Keyrock redirects into application and user is greeted with "Applicaton registered!" message.

### 3.1.2. Login into application

In the index page (/), backend server creates an unique link for Keyrock IDM with different parameters:

```
{
    'response_type': 'code',
    'client_id': provider_client_id, 
    'scope': 'openid ishare',
    'redirect_uri': keyrock_redirect_url, 
    'state': 'F3D3rat3DstAt3', 
    'nonce': gen_random()
}
```

Technically, it is a link to Keyrock IDM with parameters shown above.

User is greeted with Keyrock IDM login screen or if user has a session already, Keyrock IDM handles the request and redirects back into application with a header called code, which is used for obtaining access token.

![Login page](./pictures/login_page.png)

When redirection is done, backend server makes another request into Keyrock IDM with JSON data:

```
{
    'grant_type': 'authorization_code',
    'client_id': provider_client_id,
    'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
    'client_assertion': make_jwt(),
    'redirect_uri': keyrock_redirect_url,
    'scope': 'iSHARE',
    'code': request.args.get('code')
}
```

JSON data above must match with information which was passed to Keyrock IDM earlier in registering application phase. 
Due to expiration of code (30 seconds), it is ideal to let backend server to request an access token from Keyrock IDM.

If login & redirection was succesful, user is now authenticated and logged into application.
Technically, backend server passes the access token into user's browser and application checks if there is an access token. This was made this way due to security reasons.


### 3.1.3. Search entities

![Search entities](./pictures/search.png)

When user is logged into application, user can now search entities with **type**/**attribute**/**identifier** forms. When user submits a form, backend server uses form as a data and requests entities from Scorpio brokers with that data and access token. The access token is hidden in same form so therefore the form contains user's defined input and access token.

Technically, request is sent to API-Umbrella which validates the access token and forwards the request for Scorpio broker. While validating the access token, API-Umbrella checks user's policies from iSHARE Satellite.

If access token and policy is valid, the application returns a list of JSON data into user's browser.

```
[
  {
    "id": "ngsi-ld:DELIVERYORDER:CTS001-fed-broker",
    "type": "DELIVERYORDER",
    "value": "CTS007-fed-broker"
  }
]
```


### 3.1.4. JWT token creation

**make_jwt()** function creates a JWT token for Keyrock IDM. The JWT token contains iSHARE related information that Keyrock IDM uses for iSHARE functions and validates application. 

```
{
        "jti": str(uuid.uuid4()),
        "iss": provider_client_id,
        "sub": provider_client_id,
        "aud": consumer_client_id,
        "email": email,
        "iat": datetime.now(),
        "nbf": datetime.now(),
        "exp": datetime.now() + timedelta(seconds=30),
        "response_type": "code",
        "redirect_uri": keyrock_redirect_url,
        "callback_url": keyrock_redirect_url,
        "client_id": provider_client_id,
        "scope": "openid iSHARE",
        "state": "F3D3rat3DstAt3",
        "nonce": gen_random(),
        "acr_values": "urn:http://eidas.europa.eu/LoA/NotNotified/high",
        "language": "en"
}, private_key, algorithm='RS256', headers={'x5c': authorize_x5c})
```

"redirect_uri" key must match the Federation application's url because Keyrock IDM uses it to redirect back into application.

"exp" key must be maximum of + 30 seconds 

---
# 4. Configuring Federation

Since Federation is now containerized, it is easier to configure it for production.

## 4.1 Environment Variables

|Environment variable|Default value|Explanation|
|---|---|---|
|PROVIDER_CLIENT_ID|EU.EORI.PROVIDER|Provider's EU.EORI number|
|CONSUMER_CLIENT_ID|EU.EORI.CONSUMER|Consumer's EU.EORI number|
|CONSUMER_EMAIL|johndoe@example.com  | Consumer's email address|
|KEYROCK_URL|http://127.0.0.1:3000|Provider's Keyrock instance URL|
|APP_URL|http://127.0.0.1:5000|Federation's instance URL|
|SCORPIO_URL|http://127.0.0.1:9090|Scorpio Context Broker URL <br> (Must be behind API-Management)|
|PRIVATE_KEY_FILE|private_key|Private key's file name|
|X5C_VALUE_FILE|x5c|X5C Value's file name|


---

These environment variables must be modified:

```
      - env:
        - name: PROVIDER_CLIENT_ID
          value: "EU.EORI.FICTSODALAPROVIDER"
        - name: CONSUMER_CLIENT_ID
          value: "EU.EORI.FICTSODALACONSUMER"
        - name: CONSUMER_EMAIL
          value: "johndoe@example.fi"
        - name: KEYROCK_URL
          value: "https://accounts.DOMAIN.fi"
        - name: APP_URL
          value: "https://federation.DOMAIN.fi"
        - name: SCORPIO_URL
          value: "https://scorpio.DOMAIN.fi"
        - name: PRIVATE_KEY_FILE
          value: "private_key"
        - name: X5C_VALUE_FILE
          value: "x5c"  
```

Make sure that secrets made in 3.1.3. correspond with variables **PRIVATE_KEY_FILE** & **X5C_VALUE_FILE** values:

--from-file=**private_key** --from-file=**x5c**:

* PRIVATE_KEY_FILE value: **private_key**
* X5C_VALUE_FILE value: **x5c**



## 4.2 Obtaining certificates from iSHARE

Two sets of iSHARE certificates are needed if federated setup with two Scorpio brokers is used.

.pkcs12 file contains 3 certificates with private key. 

https://dev.ishare.eu/_downloads/54a7b056df8dcc44f1049a82824d56f8/181113iSHARE_Certificate_cheat_sheet_v1.pdf

Extract key & certificates from pkcs12
>openssl pkcs12 -info -in filename.p12 -nodes -nocerts

>openssl pkcs12 -in filename.p12 -out certificates.pem -nokeys

### 4.2.1 Private key

The extracted private key file should be fine for Federation.

Private key file must contain PEM contents with actual private key.

This private key is used to create a JWT token.

### 4.2.2 X5C value

X5C value file is made from certificates.pem file. X5C value contains iSHARE related information.

X5C value file should contain 3 lines where certificates are put without BEGIN CERTIFICATE & END CERTIFICATE phrases: 

* 1. first line is first certificate from certificates.pem file without BEGIN and END lines: **MIIA**
* 2. second line is second certificate from certificates.pem file without BEGIN and END lines: **MIIB**
* 2. third line is third certificate from certificates.pem file without BEGIN and END lines: **MIIC**

If X5C value file has empty lines, make sure to delete them.

### 4.2.3 Secrets

Create secrets from private key and x5c value files.

>kubectl -n odala create secret generic ishare-keys --from-file=private_key --from-file=x5c

## 4.3 Building Docker image

Federation image is built with Dockerfile.
Federation image can be built with command:
>docker build -t federation:latest .

## 4.4 .yaml file contents

The deployment .yaml is used to start the Federation in Kubernetes. .yaml file contains deployment, service and ingress rule.

>kubectl -n odala apply -f deployment.yaml

### 4.4.2 Mounting secrets

```
    spec:
      volumes:
      - name: ishare-keys
        secret:
          secretName: ishare-keys
```

```
        volumeMounts:
        - name: ishare-keys
          mountPath: "/keys/secrets/"
```

### 4.4.3 Ingress

```
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-production
    kubernetes.io/ingress.class: nginx
  name: federation-app
  namespace: odala
spec:
  rules:
  - host: federation.DOMAIN.fi
    http:
      paths:
      - backend:
          service:
            name: federation-app
            port:
              number: 5000
        path: /
        pathType: Prefix
  tls:
  - hosts:
    - federation.DOMAIN.fi
    secretName: federation-cert
status:
  loadBalancer:
    ingress:
    - ip: 10.128.30.124
```

---

# 5 Endpoint-Auth-Service

Endpoint-Auth-Service component intercepts subscription broker requests from federation broker and triggers a Machine to Machine flow (M2M) in subscription broker side and obtains the access token for entities from subscription broker.

This way federation broker is able to request entities from subscription broker and pass entities for user.

Endpoint-Auth-Service contains Envoy Proxy, Endpoint-Config-Service and iSHARE-Auth-Provider (for storing iSHARE certificates)

![Endpoint Auth Service flow](./pictures/endpoint01.png)

## 5.1 Configuring Endpoint-Auth-Service

Proxy into K8S cluster with command:
```
kubectl proxy -port 8082
```
While proxying into K8S cluster, it is now possible to send HTTP POST requests directly with Postman or cURL.

### 5.1.1 Endpoint configuration

1. Change `NAMESPACE` for corresponding namespace
2. Change `"domain"` value to Sub broker's URI
3. Change `"iShareClientId"` value to Main broker's iSHARE ID
4. Change `"iShareIdpId"` value to sub broker's iSHARE ID
5. Change `"ishareIdpAddress"` value to sub broker's keyrock token URI

```
curl --location --request POST 'http://localhost:8082/api/v1/namespaces/NAMESPACE/services/NAMESPACE-cs-endpoint-auth-service:8080/proxy/endpoint' \
--header 'Content-Type: application/json' \
--data-raw '{
          "domain": "scorpio.DOMAIN.FI",
          "path": "/ngsi-ld/v1",
          "authType": "iShare",
          "useHttps": true,
          "authCredentials": {
            "iShareClientId": "EU.EORI.PROVIDER",
            "iShareIdpId": "EU.EORI.CONSUMER",
            "iShareIdpAddress": "https://KEYROCK/oauth2/token",
            "requestGrantType": "urn:ietf:params:oauth:grant-type:jwt-bearer"
          }
        }'
```

### 5.1.2 Credentials configuration

1. Change `NAMESPACE` for corresponding namespace and `EU.EORI.CONSUMER` to Sub broker's iSHARE ID

2. Main broker's iSHARE certificate must be one line, containing new line symbol for every line `\n`. example:

```
-----BEGIN CERTIFICATE-----
example
ishare
certificate
-----END CERTIFICATE-----
```
into: `example\nishare\ncertificate`

replace `xxx` with one line certificate. Repeat this with other certificates for `yyy` and `zzz`. Repeat this with main broker's iSHARE private key and add it into `vvv`. 

```
curl --location --request POST 'http://localhost:8082/api/v1/namespaces/NAMESPACE/services/NAMESPACE-ishare-endpoint-auth-service:8080/proxy/credentials/EU.EORI.CONSUMER' \
--header 'Content-Type: application/json' \
--data-raw '{
          "certificateChain": "-----BEGIN CERTIFICATE-----\nxxx\n-----END CERTIFICATE\n----------BEGIN CERTIFICATE----\n-yyy\n-----END CERTIFICATE----------\nBEGIN CERTIFICATE-----\nzzz\n-----END CERTIFICATE-----\n",
          "signingKey": "-----BEGIN PRIVATE KEY-----\nvvv\n-----END PRIVATE KEY-----\n"
        }’
```

## 5.2 Configuring Main broker's Scorpio Context Broker

Scorpio must have an extra annotation to get Endpoint-Auth-Service working with Scorpio:

```
template:
    metadata:
      labels:
        sidecar-injection: enabled
        app: scorpio
      annotations:
        sidecar.k8s.fiware.org/request: "envoy-sidecar"
```

Restart Scorpio with `kubectl -n NAMESPACE rollout restart deployment scorpio` to get additional containers for Scorpio.

## 5.3 Adding Context Source Registration into Scorpio

CSourceRegistrations are needed for requesting entities from subscription brokers with federation broker.

```
kubectl –n NAMESPACE exec –it scorpio-pod -- bash


curl --location --request POST 'http://localhost:9090/ngsi-ld/v1/csourceRegistrations/' \
--header 'Content-Type: application/json' \
--data-raw '{
    "id": "urn:ngsi-ld:DELIVERYORDER:CTS1",
    "type": "ContextSourceRegistration",
    "information": [
        {
            "entities": [
                {
                    "type": "DELIVERYORDER"
                }
                ]
        }
    ],
    "endpoint": "http://scorpio.DOMAIN"
}
‘
```

*Note:* "endpoint" must be HTTP

---

# 6 iSHARE Authorization Registry & Satellite

iSHARE Satellite contains registered participants whom can create policies in Authorization Registry.
These policies are checked when user is requesting entities from context brokers – if user is found to have right policy for particular entity (by matching specific attribute, type or ID), context broker will respond with entities.

With this deployment, Satellite is iSHARE test satellite, and so is the Authorization registry.

It is possible to host these components seprately. More on this on [iSHARE satellite](https://ishare.eu/ishare-satellite-explained/) documentation and [iSHARE Authorization Registry](https://ishare.eu/about-ishare/authorization-registry/)

## 6.1 iSHARE Authorization Registry policies

Sub broker must create an organization level policy for main broker, as shown in picture below, Access Subject: `EU.EORI.FICTSODALAPROVIDER`. 

![Policies in AR](./pictures/ishare-ar.png)

Policy:

![Policy contents](./pictures/ar-policy.png)
---

# 6 Known issues

Sometimes fetching the federated data returns empty array.

# 7 Contact 

We are here to help you! If you need any help, or just want to have a chat, please contact ilari.mikkonen@contrasec.fi

---

Components- Broker-Federation

for the ODALA project.

© 2023 Contrasec Oy

License EUPL 1.2

![](https://ec.europa.eu/inea/sites/default/files/ceflogos/en_horizontal_cef_logo_2.png)

The contents of this publication are the sole responsibility of the authors and do not necessarily reflect the opinion of the European Union.
This project has received funding from the European Union’s “The Connecting Europe Facility (CEF) in Telecom” programme under Grant Agreement number: INEA/CEF/ICT/A2019/2063604
