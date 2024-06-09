FROM python:3.10
FROM sagemath/sagemath:latest



RUN sudo apt-get update && sudo apt-get install socat -y && sudo apt-get install python3-pip -y
RUN sage --pip install pycryptodome


COPY chall.py .
COPY s001459900052.pdf .
COPY smarts_attack_curves.json .
VOLUME ["/smart"]
WORKDIR /smart


EXPOSE 8007
CMD ["socat", "TCP-LISTEN:8007,fork,reuseaddr", "EXEC:'python3 chall.py',stderr"]