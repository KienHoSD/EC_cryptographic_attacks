FROM python:3.10
FROM sagemath/sagemath:latest



RUN sudo apt-get update && sudo apt-get install socat -y && sudo apt-get install python3-pip -y
RUN sage --pip install pycryptodome


COPY chall.py .
COPY 2017-554.pdf .
VOLUME ["/invalid"]
WORKDIR /invalid


EXPOSE 8007
CMD ["socat", "TCP-LISTEN:8007,fork,reuseaddr", "EXEC:'python3 chall.py',stderr"]