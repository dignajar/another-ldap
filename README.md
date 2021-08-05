# Another LDAP
Another LDAP is a form-based authentication for Active Directory / LDAP server.

Another LDAP provides Authentication and Authorization for your backend applications running on Kubernetes.

[![Docker image](https://img.shields.io/badge/Docker-image-blue.svg)](https://github.com/dignajar/another-ldap/pkgs/container/another-ldap)
[![Kubernetes YAML manifests](https://img.shields.io/badge/Kubernetes-manifests-blue.svg)](https://github.com/dignajar/another-ldap/tree/master/kubernetes)
[![codebeat badge](https://codebeat.co/badges/f57de995-ca62-49e5-b309-82ed60570324)](https://codebeat.co/projects/github-com-dignajar-another-ldap-master)
[![release](https://img.shields.io/github/v/release/dignajar/another-ldap.svg)](https://github.com/dignajar/another-ldap/releases)
[![license](https://img.shields.io/badge/license-MIT-green)](https://github.com/dignajar/another-ldap/blob/master/LICENSE)

## Install
```
git clone https://github.com/dignajar/another-ldap.git

cd another-ldap/kubernetes

# Change the ingress, config-map and secrets for your configuration.

kubectl apply -f .
```
