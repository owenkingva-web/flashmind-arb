# FlashMind DeFi Arbitrage Bot - Railway Deployment
# Gradio dashboard with v15g PPO model (pure NumPy inference)

FROM python:3.11-slim

WORKDIR /app

# Install dependencies first (layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Expose Gradio default port
EXPOSE 7860

# Railway Procfile will handle the start command
# But also provide a default CMD for standalone use
CMD ["python", "app.py"]
