FROM python:3.12-slim
RUN pip install --no-cache-dir "psycopg[binary]==3.2.3" faker==33.1.0 argon2-cffi==23.1.0 pyotp==2.9.0
COPY seed.py /seed.py
USER 1000:1000
CMD ["python", "/seed.py"]
