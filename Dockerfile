FROM python:3.9.10-alpine3.14

ENV PYTHONUNBUFFERED=1
ENV CRYPTOGRAPHY_DONT_BUILD_RUST=1

RUN apk --no-cache add build-base libffi-dev openssl-dev openldap-dev
COPY ./files/requirements.txt /tmp/requirements.txt
RUN pip install -r /tmp/requirements.txt --no-cache-dir

# Run as non-root
ENV USER aldap
ENV UID 10001
ENV GROUP aldap
ENV GID 10001
ENV HOME /home/$USER
RUN addgroup -g $GID -S $GROUP && adduser -u $UID -S $USER -G $GROUP

# Copy app
COPY --chown=$UID:$GID ./files/ $HOME/

EXPOSE 9000
USER $UID:$GID
WORKDIR $HOME
CMD ["python3", "-u", "main.py"]