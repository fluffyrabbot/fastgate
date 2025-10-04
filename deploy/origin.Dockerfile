FROM python:3.11-alpine
WORKDIR /app
COPY deploy/origin /app
EXPOSE 8081
CMD ["python","-m","http.server","8081"]
