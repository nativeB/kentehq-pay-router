FROM python:3.12-alpine
WORKDIR /app
COPY router.py .
EXPOSE 8080
HEALTHCHECK CMD wget -qO- http://127.0.0.1:8080/health || exit 1
CMD ["python", "-u", "router.py"]
