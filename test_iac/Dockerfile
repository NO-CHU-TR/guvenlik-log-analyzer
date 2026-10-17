FROM python:3.11
RUN useradd -m appuser
WORKDIR /app
COPY . /app
USER appuser
HEALTHCHECK CMD python -c "print('ok')" || exit 1
CMD ["python", "app.py"]