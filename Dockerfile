FROM python:3.9-slim
WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir -r requirements.txt
EXPOSE 2222
EXPOSE 8501
CMD ["sh", "-c", "python server.py & streamlit run dashboard.py --server.port 8501 --server.address 0.0.0.0"]
