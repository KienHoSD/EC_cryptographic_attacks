FROM python:3.10
FROM sagemath/sagemath:latest



RUN sudo apt-get update && sudo apt-get install socat -y && sudo apt-get install python3-pip -y
RUN sage --pip install pycryptodome

COPY chall.py .
COPY secret.py . 
COPY 2015-605.pdf .

VOLUME ["/bsgs"]
WORKDIR /bsgs


EXPOSE 8001
CMD ["socat", "TCP-LISTEN:8001,fork,reuseaddr", "EXEC:'python3 chall.py',stderr"]
