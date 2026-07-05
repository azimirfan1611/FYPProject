FROM python:3.11-slim
WORKDIR /app

# Install dependencies first (better layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy only necessary app files
COPY app.py database.py ./
COPY templates/ templates/
COPY static/ static/

ENV FLASK_APP=app.py
EXPOSE 5001
CMD ["python", "app.py"]
