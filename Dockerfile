FROM python:3.8-alpine3.14
RUN apk --no-cache add curl
COPY . ./app
WORKDIR /app
ENV PYTHONPATH "$PYTHONPATH:/app"
RUN pip install --no-cache -r requirements.txt
CMD ["python", "-u", "mirroroperator/operator.py"]
