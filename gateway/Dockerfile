FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
ARG ENABLE_FRENCH_NLP=false
RUN pip install --no-cache-dir -r requirements.txt \
    && python -m spacy download en_core_web_lg \
    && if [ "$ENABLE_FRENCH_NLP" = "true" ]; then python -m spacy download fr_core_news_lg; fi

COPY . .

RUN chmod +x entrypoint.sh

EXPOSE 8080

ENTRYPOINT ["./entrypoint.sh"]
