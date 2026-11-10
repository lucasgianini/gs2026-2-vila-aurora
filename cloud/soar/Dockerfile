FROM python:3.12-slim
RUN pip install --no-cache-dir "psycopg[binary]==3.2.3" httpx==0.28.1
COPY soar.py /srv/soar.py
USER 1000:1000
CMD ["python", "-u", "/srv/soar.py"]
