# Another LDAP
Another LDAP is a form-based authentication for Active Directory / LDAP server.

Another LDAP provides Authentication and Authorization for your applications running on Kubernetes.

**Another LDAP** works perfect with **NGINX ingress controller** via ([External OAUTH Authentication](https://kubernetes.github.io/ingress-nginx/examples/auth/oauth-external-auth/)), **HAProxy** ([haproxy-auth-request](https://github.com/TimWolla/haproxy-auth-request)) or any webserver/reverse proxy with authorization based on the result of a subrequest.

[![Docker image](https://img.shields.io/badge/Docker-image-blue.svg)](https://github.com/dignajar/another-ldap/pkgs/container/another-ldap)
[![Kubernetes YAML manifests](https://img.shields.io/badge/Kubernetes-manifests-blue.svg)](https://github.com/dignajar/another-ldap/tree/master/kubernetes)
[![codebeat badge](https://codebeat.co/badges/f57de995-ca62-49e5-b309-82ed60570324)](https://codebeat.co/projects/github-com-dignajar-another-ldap-master)
[![release](https://img.shields.io/github/v/release/dignajar/another-ldap.svg)](https://github.com/dignajar/another-ldap/releases)
[![license](https://img.shields.io/badge/license-MIT-green)](https://github.com/dignajar/another-ldap/blob/master/LICENSE)

![Alt text](another-ldap.png?raw=true "Another LDAP")

## Features
- Authentication and Authorization for applications.
- Authorization via LDAP groups, supports regex in groups list.
- Supports protocols `ldap://` and `ldaps://`.
- Enabled by design TLS via self-signed certificate.
- Supports configuration via headers or via environment variables.
- HTTP response headers with username and matched groups for the backend.
- Brute force protection.
- Log format in Plain-Text or JSON.

## Installation
- Clone this repository or download the manifests from the directory `kubernetes`.
- Edit the ingress, config-map and secrets with your configuration.
- ALDAP is installed in the namespace `another`.

```
git clone https://github.com/dignajar/another-ldap.git
cd another-ldap/kubernetes
kubectl apply -f .
```

## Configuration

### Example 1: Authentication
The following example provides authentication for the application `my-app`.
- The authentication validates username and password.

```
---
kind: Ingress
apiVersion: networking.k8s.io/v1
metadata:
  name: my-app
  annotations:
    kubernetes.io/ingress.class: "nginx"
    nginx.ingress.kubernetes.io/auth-url: https://another-ldap.another.svc.cluster.local/auth
    nginx.ingress.kubernetes.io/server-snippet: |
      error_page 401 = @login;
      location @login {
        return 302 https://another-ldap.testmyldap.com/?protocol=$pass_access_scheme&callback=$host;
      }
spec:
  rules:
  - host: my-app.testmyldap.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: my-app
            port:
              number: 80
```

### Example 2: Authentication and Authorization
The following example provides authentication and authorization for the application `my-app`.
- The authentication validates username and password.
- The authorization validates if the user has the LDAP group `DevOps production environment`.

```
---
kind: Ingress
apiVersion: networking.k8s.io/v1
metadata:
  name: my-app
  annotations:
    kubernetes.io/ingress.class: "nginx"
    nginx.ingress.kubernetes.io/auth-url: https://another-ldap.another.svc.cluster.local/auth
    nginx.ingress.kubernetes.io/auth-snippet: |
      proxy_set_header Ldap-Allowed-Groups "DevOps production environment";
    nginx.ingress.kubernetes.io/server-snippet: |
      error_page 401 = @login;
      location @login {
        return 302 https://another-ldap.testmyldap.com/?protocol=$pass_access_scheme&callback=$host;
      }
spec:
  rules:
  - host: my-app.testmyldap.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: my-app
            port:
              number: 80
```

### Example 3: Authentication, Authorization and response headers
The following example provides authentication and authorization for the application `my-app` and calls the application with the headers `x-username` and `x-groups`.
- The authentication validates username and password.
- The authorization validates if the user has one of the following LDAP groups `DevOps production environment` or `DevOps QA environment`.
- Nginx will return the header `x-username` to the application that contains the username authenticated.
- Nginx will return the header `x-groups` to the application that contains the matched groups for the username authenticated.

With the headers you can do increase the authorization in the application or display the user logged.

```
---
kind: Ingress
apiVersion: networking.k8s.io/v1
metadata:
  name: my-app
  annotations:
    kubernetes.io/ingress.class: "nginx"
    nginx.ingress.kubernetes.io/auth-url: https://another-ldap.another.svc.cluster.local/auth
    nginx.ingress.kubernetes.io/auth-response-headers: "x-username, x-groups"
    nginx.ingress.kubernetes.io/auth-snippet: |
      proxy_set_header Ldap-Allowed-Groups "DevOps production environment, DevOps QA environment";
    nginx.ingress.kubernetes.io/server-snippet: |
      error_page 401 = @login;
      location @login {
        return 302 https://another-ldap.testmyldap.com/?protocol=$pass_access_scheme&callback=$host;
      }
spec:
  rules:
  - host: my-app.testmyldap.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: my-app
            port:
              number: 80
```

## Available parameters
All parameters are defined in the config-map and secret manifests.

All values type are `string`.

The parameter `LDAP_SEARCH_FILTER` supports variable expansion with the username, you can do something like this `(sAMAccountName={username})` and `{username}` is going to be replaced by the username typed in the login form.

The parameter `LDAP_BIND_DN` supports variable expansion with the username, you can do something like this `{username}@TESTMYLDAP.com` or `UID={username},OU=PEOPLE,DC=TESTMYLDAP,DC=COM` and `{username}` is going to be replaced by the username typed in the login form.

The parameter `COOKIE_DOMAIN` define the scope of the cookie, for example if you need to authentication/authorizate the domain `testmyldap.com` you should set the wildcard `.testmyldap.com` (notice the dot at the beginning).

## Supported HTTP request headers
The variables send via HTTP headers take precedence over environment variables.
- `Ldap-Allowed-Users`
- `Ldap-Allowed-Groups`
- `Ldap-Conditional-Groups`: Default=`"or"`
- `Ldap-Conditional-Users-Groups`: Default=`"or"`

## HTTP response headers
- `x-username` Contains the authenticated username
- `x-groups` Contains the user's matches groups
