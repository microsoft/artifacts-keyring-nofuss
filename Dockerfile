FROM python:3.12-slim@sha256:090ba77e2958f6af52a5341f788b50b032dd4ca28377d2893dcf1ecbdfdfe203
RUN pip install uv keyring artifacts-keyring-nofuss \
  --index-url "https://pkgs.dev.azure.com/pypi-lockdown/pypi-lockdown/_packaging/public@Local/pypi/simple/"
COPY pyproject.toml uv.lock ./
RUN --mount=type=secret,id=ACCESS_TOKEN,env=ARTIFACTS_KEYRING_NOFUSS_TOKEN \
    ARTIFACTS_KEYRING_NOFUSS_DEBUG=1 \
    UV_KEYRING_PROVIDER=subprocess \
    uv sync --locked --no-install-project
