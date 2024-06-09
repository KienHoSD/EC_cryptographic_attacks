FROM python:3.11

RUN apt-get update && apt-get install socat -y
RUN pip install pycryptodome
RUN pip install ecdsa

WORKDIR /app
COPY chall.py .
COPY secret.py .

RUN useradd -ms /bin/bash ctf
USER ctf
EXPOSE 6060
ENTRYPOINT ["socat", "TCP-LISTEN:6060,fork,reuseaddr", "EXEC:'python chall.py',stderr"]
