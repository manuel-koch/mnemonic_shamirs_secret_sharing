FROM python:3.8-slim

WORKDIR /opt/secret_sharing

COPY requirements.txt ./
RUN pip install -r requirements.txt

COPY mnemonic_shamirs_secret_sharing.py \
     sss.py \
     wordlist.py \
     wordlist.txt \
     ./
RUN chmod +x mnemonic_shamirs_secret_sharing.py

ENTRYPOINT ["./mnemonic_shamirs_secret_sharing.py"]