FROM python:3.10
FROM sagemath/sagemath:latest



RUN sudo apt-get update && sudo apt-get install socat -y && sudo apt-get install python3-pip -y
RUN sage --pip install pycryptodome

COPY chall.py .
COPY 3-540-48910-X_14.pdf .

VOLUME ["/frey_ruck"]
WORKDIR /frey_ruck


EXPOSE 8006
CMD ["socat", "TCP-LISTEN:8006,fork,reuseaddr", "EXEC:'python3 chall.py',stderr"]
