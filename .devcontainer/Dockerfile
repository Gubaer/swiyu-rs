FROM node:25-bookworm


# libreoffice: to convert word documents to PDF
# curl: downloads
# python and python3-pip: Claude's main work horse
# direnv: to load environment variables from .env files
RUN apt-get update && apt-get install -y --no-install-recommends \
    libreoffice \
    curl \
    python3 \
    python3-pip \
    direnv \
    sudo \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

# uv is a Python package manager that is faster and more efficient than pip. 
# We use it to install the Python dependencies for Claude.
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /usr/local/bin/

# We install a bunch of Python libraries that are commonly used by Claude
# for document processing and data manipulation. Claude's work is smoother 
# and faster with these libraries installed.
RUN UV_SYSTEM_PYTHON=1 uv pip install --break-system-packages \
    pymupdf \
    pdfplumber \
    pypdf \
    python-docx \
    python-pptx \
    pandas \
    openpyxl \
    markitdown \
    unstructured \
    pytesseract \
    qrbill \
    cairosvg \
    fonttools \
    lato \
    poppler-utils \
    pyzbar \
    pillow \
    weasyprint

RUN mkdir -p /tmp/user/1000 && chmod -R 1777 /tmp/user
RUN useradd -m -s /bin/bash claude
RUN echo "claude ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

USER claude
WORKDIR /home/claude

# Install the binary for claude and set up the environment for the claude user
RUN mkdir -p /home/claude/.runtime && chown claude:claude /home/claude/.runtime
RUN curl -fsSL https://claude.ai/install.sh | bash
RUN echo 'export PATH="/home/claude/.local/bin:$PATH"' >> /home/claude/.bashrc
RUN echo "alias claude-dangerous='claude --dangerously-skip-permissions'" >> /home/claude/.bashrc
RUN echo "alias gemini-dangerous='NO_BROWSER=true gemini --approval-mode=yolo'" >> /home/claude/.bashrc
RUN echo 'eval "$(direnv hook bash)"' >> /home/claude/.bashrc
