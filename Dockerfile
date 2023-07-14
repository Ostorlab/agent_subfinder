FROM python:3.10-alpine as base
FROM base as builder
RUN apk add build-base
RUN mkdir /install
WORKDIR /install
COPY requirement.txt /requirement.txt
RUN pip install --prefix=/install -r /requirement.txt

FROM golang:1.19-alpine AS go-build-env
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

FROM base
RUN apk -U upgrade --no-cache && apk add --no-cache bind-tools ca-certificates
COPY --from=builder /install /usr/local
COPY --from=go-build-env /go/bin/subfinder /usr/local/bin/subfinder
RUN mkdir -p /app/agent
ENV PYTHONPATH=/app
COPY agent /app/agent
COPY ostorlab.yaml /app/agent/ostorlab.

WORKDIR /root
RUN mkdir -p .config/subfinder/
WORKDIR /root/.config/subfinder/
RUN touch provider-config.yaml

WORKDIR /app
CMD ["python3", "/app/agent/subfinder_agent.py"]
