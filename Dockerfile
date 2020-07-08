FROM python:3.8-alpine3.12
RUN apk --no-cache add curl
COPY . ./app
WORKDIR /app
ENV PYTHONPATH "$PYTHONPATH:/app"
RUN pip install --no-cache -r requirements.txt
ENTRYPOINT ["python", "mirroroperator/operator.py"]
