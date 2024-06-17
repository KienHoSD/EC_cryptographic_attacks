FROM python:3.10
FROM sagemath/sagemath:latest



RUN sudo apt-get update && sudo apt-get install socat -y && sudo apt-get install python3-pip -y
RUN sage --pip install pycryptodome ecdsa


COPY chall.py .
COPY 2019-023.pdf .
VOLUME ["/biased"]
WORKDIR /biased


EXPOSE 8777
CMD ["socat", "TCP-LISTEN:8777,fork,reuseaddr", "EXEC:'python3 source.py',stderr"]