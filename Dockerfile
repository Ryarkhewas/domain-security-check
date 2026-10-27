# domain-security-check in a container.
#
#   docker run --rm -v "$PWD/reports:/reports" ghcr.io/ryarkhewas/domain-security-check example.com --pdf
#
# Two images are built from this file:
# - "standard" (default): the tool with PDF output;
# - "browser": the same, plus Playwright and Chromium for --browser (much larger).
#   docker build --target browser -t domain-security-check:browser .

FROM python:3.12-slim AS standard
LABEL org.opencontainers.image.title="domain-security-check" \
      org.opencontainers.image.description="Passive security audit of a domain name, with HTML and PDF reports" \
      org.opencontainers.image.source="https://github.com/Ryarkhewas/domain-security-check" \
      org.opencontainers.image.licenses="MIT"
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY domaincheck ./domaincheck
RUN pip install ".[pdf]" && rm -rf /src \
    && useradd --create-home --uid 1000 audit && mkdir /reports && chown audit /reports
USER audit
WORKDIR /reports
# Reports are written to /reports: mount a folder there to keep them (and the history of each domain)
ENTRYPOINT ["domain-security-check", "--output-dir", "/reports"]
CMD ["--help"]

FROM standard AS browser
USER root
RUN pip install "playwright>=1.40" \
    && PLAYWRIGHT_BROWSERS_PATH=/opt/playwright python -m playwright install --with-deps chromium \
    && chmod -R a+rX /opt/playwright
ENV PLAYWRIGHT_BROWSERS_PATH=/opt/playwright
USER audit

# The default image is the standard one
FROM standard
