FROM quay.io/keycloak/keycloak:25.0.5

#COPY target/keycloak-whereq.jar /opt/keycloak/providers/

CMD ["start-dev", "--hostname-strict=false"]

# Build
# Naming Convention: [host]/repo:tag
# docker build -t whereq.local/keycloak/whereq:v0.1 .
# docker run --name kw 45cfb375d675
# docker run --name kw whereq.local/keycloak/whereq:v0.1